package e2e_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

// TestEventRetentionPolicy: events get their class when inserted (also the
// ones triggers write), GET/PUT …/event-retention validate against the
// deployment ceilings, only owners write, and a change is an event.
func TestEventRetentionPolicy(t *testing.T) {
	e := newEnv(t)
	url := e.Base + "/event-retention"

	got := e.Must("GET", url, e.Owner, nil, 200).JSON
	ceilings := got["ceilings"].(map[string]any)
	effective := got["effective"].(map[string]any)
	if got["security_retention_seconds"] != nil || got["default_retention_seconds"] != nil ||
		effective["security"] != float64(365*86400) || effective["default"] != float64(90*86400) ||
		ceilings["security"] != float64(365*86400) || ceilings["default"] != float64(90*86400) {
		t.Fatalf("defaults = %v", got)
	}

	// Classes are set at insert, from the catalog, including trigger writes.
	e.Login(e.AliceEmail)
	for typ, want := range map[string]string{"session.created": "security", "user.created": "default", "login.failed": "security"} {
		e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password!"), 401)
		if n := e.count(`SELECT count(*) FROM events WHERE environment_id=$1 AND type=$2 AND retention_class<>$3`, e.EnvID, typ, want); n != 0 {
			t.Fatalf("%s has another class than %s", typ, want)
		}
		if n := e.count(`SELECT count(*) FROM events WHERE environment_id=$1 AND type=$2`, e.EnvID, typ); n == 0 {
			t.Fatalf("no %s event", typ)
		}
	}
	items := e.Must("GET", e.Base+"/events?type=session.created&limit=1", e.Owner, nil, 200).JSON["items"].([]any)
	if items[0].(map[string]any)["retention_class"] != "security" {
		t.Fatalf("event = %v", items[0])
	}

	// Validation: at least a day, at most the ceiling; null = the ceiling.
	for _, body := range []fiber.Map{
		{"security_retention_seconds": 3600},
		{"default_retention_seconds": 91 * 86400},
		{"security_retention_seconds": 366 * 86400},
		{"default_retention_seconds": 0},
	} {
		if r := e.Do("PUT", url, e.Owner, body); r.Status != 422 || r.JSON["error"].(map[string]any)["code"] != "RETENTION_OUT_OF_RANGE" {
			t.Fatalf("%v = %d %s", body, r.Status, r.Body)
		}
	}
	e.Must("PUT", url, e.Owner, fiber.Map{"default_retention_seconds": "x"}, 400)
	admin := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "admin@example.com", "role": "admin"}, 201).JSON["secret"].(string)
	e.Must("PUT", url, admin, fiber.Map{"default_retention_seconds": 86400}, 403)
	e.Must("GET", url, admin, nil, 200)

	set := e.Must("PUT", url, e.Owner, fiber.Map{"security_retention_seconds": 30 * 86400, "default_retention_seconds": nil}, 200).JSON
	if set["security_retention_seconds"] != float64(30*86400) || set["default_retention_seconds"] != nil || set["effective"].(map[string]any)["default"] != float64(90*86400) {
		t.Fatalf("set = %v", set)
	}
	if again := e.Must("GET", url, e.Owner, nil, 200).JSON; again["effective"].(map[string]any)["security"] != float64(30*86400) {
		t.Fatalf("get after set = %v", again)
	}
	if n := len(eventTypes(e.Must("GET", e.Base+"/events?type=event_retention.updated", e.Owner, nil, 200))); n != 1 {
		t.Fatalf("event_retention.updated events = %d", n)
	}
	// Clearing returns to the ceiling.
	cleared := e.Must("PUT", url, e.Owner, fiber.Map{}, 200).JSON
	if cleared["security_retention_seconds"] != nil || cleared["effective"].(map[string]any)["security"] != float64(365*86400) {
		t.Fatalf("cleared = %v", cleared)
	}

	// /api/v1 reads with iam:events:read.
	api := "/api/v1/environments/" + e.EnvID + "/event-retention"
	e.Must("GET", api, e.scopedToken("iam:users:read"), nil, 403)
	e.Must("GET", api, e.scopedToken("iam:events:read"), nil, 200)
}

// TestEventPruneVolume (D39): a million old events of both classes in two
// environments are pruned in batches while inserts go on; each class is cut
// at its own effective retention (the environment's override included), and
// no insert waits on the prune.
func TestEventPruneVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("volume test")
	}
	e := newEnv(t)
	a := e.EnvID
	project := e.ID("POST", "/management/v1/projects", fiber.Map{"name": "Second"})
	b := e.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "staging"})
	// B keeps security events 30 days and other events 7.
	e.Must("PUT", "/management/v1/environments/"+b+"/event-retention", e.Owner,
		fiber.Map{"security_retention_seconds": 30 * 86400, "default_retention_seconds": 7 * 86400}, 200)

	const security, other = "session.created", "user.updated"
	load := func(env, typ string, days, rows int) {
		t.Helper()
		e.DB.MustExec(`INSERT INTO events(environment_id, type, actor_kind, created_at)
			SELECT $1, $2, 'system', now() - make_interval(days => $3) - make_interval(secs => g) FROM generate_series(1, $4) g`, env, typ, days, rows)
	}
	type bucket struct {
		env, typ string
		days     int
		rows     int
		kept     bool
	}
	const small = 10000
	buckets := []bucket{
		// Past every ceiling: gone.
		{a, security, 400, 230000, false}, {a, other, 400, 230000, false},
		{b, security, 400, 230000, false}, {b, other, 400, 230000, false},
		// Security outlives the default ceiling; the default does not.
		{a, security, 200, small, true}, {a, other, 100, small, false},
		{a, other, 60, small, true}, {a, security, 20, small, true},
		// Environment B's overrides cut earlier.
		{b, security, 200, small, false}, {b, other, 60, small, false},
		{b, security, 10, small, true}, {b, other, 3, small, true},
	}
	total := 0
	for _, x := range buckets {
		load(x.env, x.typ, x.days, x.rows)
		total += x.rows
	}
	e.DB.MustExec(`ANALYZE events`)
	if n := e.count(`SELECT count(*) FROM events WHERE type IN ($1,$2)`, security, other); n != total {
		t.Fatalf("loaded %d of %d", n, total)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type=$1 AND retention_class<>'security'`, security); n != 0 {
		t.Fatalf("%d bulk rows not in the security class", n)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type=$1 AND retention_class<>'default'`, other); n != 0 {
		t.Fatalf("%d bulk rows not in the default class", n)
	}

	envA, err := identity.ParseEnvironmentID(a)
	if err != nil {
		t.Fatal(err)
	}

	// Writers keep emitting while the prune runs.
	var (
		mu      sync.Mutex
		maxWait time.Duration
		inserts int
		failure error
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			err := eventpg.Tx(context.Background(), e.DB, func(tx *sqlx.Tx) error {
				return eventpg.Emit(context.Background(), tx, envA, "", "session.created", event.Subject{Kind: "session", ID: "volume"}, nil)
			})
			took := time.Since(start)
			mu.Lock()
			if err != nil && failure == nil {
				failure = err
			}
			maxWait = max(maxWait, took)
			inserts++
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	expired := `SELECT count(*) FROM events WHERE type IN ($1,$2) AND (
		(environment_id=$3 AND type=$1 AND created_at < now() - interval '365 days') OR
		(environment_id=$3 AND type=$2 AND created_at < now() - interval '90 days') OR
		(environment_id=$4 AND type=$1 AND created_at < now() - interval '30 days') OR
		(environment_id=$4 AND type=$2 AND created_at < now() - interval '7 days'))`
	rounds := 0
	for e.count(expired, security, other, a, b) > 0 {
		if rounds++; rounds > 200 {
			t.Fatal("the prune did not drain in 200 rounds")
		}
		if found, err := e.Server.Workers.RunOnce(context.Background(), "event_prune"); !found || err != nil {
			t.Fatalf("event_prune: %v %v", found, err)
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("pruned the expired part of %d events in %d rounds; %d concurrent inserts, slowest %v", total, rounds, inserts, maxWait)

	if failure != nil {
		t.Fatalf("an insert failed during the prune: %v", failure)
	}
	if inserts < 10 {
		t.Fatalf("only %d inserts ran during the prune", inserts)
	}
	if maxWait >= time.Second {
		t.Fatalf("an insert waited %v for the prune", maxWait)
	}
	// Exactly the rows within their cutoff remain, per bucket.
	for _, x := range buckets {
		days := x.days
		got := e.count(`SELECT count(*) FROM events WHERE environment_id=$1 AND type=$2 AND created_at BETWEEN now() - make_interval(days => $3) - interval '1 day' AND now() - make_interval(days => $3) + interval '1 day'`, x.env, x.typ, days)
		want := 0
		if x.kept {
			want = x.rows
		}
		if got != want {
			t.Errorf("env %s %s %dd: %d rows left, want %d", x.env[:8], x.typ, x.days, got, want)
		}
	}
	// Rows younger than the cutoff of their class were never touched: the
	// writers' events and the policy event are all still there.
	if n := e.count(`SELECT count(*) FROM events WHERE environment_id=$1 AND type='session.created' AND subject_id='volume'`, a); n != inserts {
		t.Fatalf("%d of %d concurrent events remain", n, inserts)
	}
	if n := len(eventTypes(e.Must("GET", "/management/v1/environments/"+b+"/events?type=event_retention.updated", e.Owner, nil, 200))); n != 1 {
		t.Fatalf("event_retention.updated in B = %d", n)
	}
}
