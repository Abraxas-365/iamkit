package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventhook"
	"github.com/gofiber/fiber/v2"
)

// hookReceiver is a loopback webhook endpoint that verifies Standard
// Webhooks signatures with the secrets it is told and records events.
type hookReceiver struct {
	mu      sync.Mutex
	secrets []string
	status  int
	events  []map[string]any
	ids     []string
	bad     int
}

func (r *hookReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status >= 300 {
		w.WriteHeader(r.status)
		return
	}
	verified := false
	for _, secret := range r.secrets {
		want, _ := eventhook.Sign([]string{secret}, req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"), body)
		for _, sig := range strings.Split(req.Header.Get("webhook-signature"), " ") {
			verified = verified || sig == want
		}
	}
	if !verified {
		r.bad++
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var e map[string]any
	json.Unmarshal(body, &e)
	r.events = append(r.events, e)
	r.ids = append(r.ids, req.Header.Get("webhook-id"))
	w.WriteHeader(http.StatusNoContent)
}

func (r *hookReceiver) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for _, e := range r.events {
		out = append(out, e["type"].(string))
	}
	return out
}

func (r *hookReceiver) set(status int, secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	if secrets != nil {
		r.secrets = secrets
	}
}

// drain runs delivery rounds until nothing is due.
func (e *Env) drain() {
	e.t.Helper()
	for i := 0; i < 50; i++ {
		more, err := e.Server.WebhookDispatcher.DispatchRound(context.Background())
		if err != nil {
			e.t.Fatal(err)
		}
		var due int
		if err := e.DB.Get(&due, `SELECT count(*) FROM (SELECT DISTINCT ON (d.subscription_id) d.next_attempt_at FROM event_deliveries d
			JOIN event_subscriptions s ON s.id=d.subscription_id AND s.active WHERE d.status='pending' ORDER BY d.subscription_id, d.id) h
			WHERE h.next_attempt_at <= now()`); err != nil {
			e.t.Fatal(err)
		}
		if !more && due == 0 {
			return
		}
	}
	e.t.Fatal("webhook deliveries never drained")
}

// TestEventWebhooks: a subscription receives the matching events in order,
// signed per Standard Webhooks; failures retry with backoff, then fail and
// can be retried or replayed; rotation signs with both secrets; failing
// subscriptions are disabled; the routes are on /api/v1 with
// iam:webhooks:*.
func TestEventWebhooks(t *testing.T) {
	receiver := &hookReceiver{}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithWebhookTransport(http.DefaultTransport))

	e.Must("POST", e.Base+"/webhooks", e.Owner, fiber.Map{"name": "CRM", "url": "ftp://x"}, 400)
	e.Must("POST", e.Base+"/webhooks", e.Owner, fiber.Map{"name": "CRM", "url": srv.URL, "types": []string{"Nope"}}, 400)
	created := e.Must("POST", e.Base+"/webhooks", e.Owner, fiber.Map{"name": "CRM", "url": srv.URL, "types": []string{"user.*", "organization.created"}}, 201).JSON
	sub, secret := created["id"].(string), created["secret"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret = %q", secret)
	}
	receiver.set(0, secret)
	got := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200)
	if strings.Contains(got.Body, "whsec_") || got.JSON["active"] != true {
		t.Fatalf("subscription = %s", got.Body)
	}

	// Events after the subscription are queued in their transaction and
	// delivered in order; others are not.
	bob := e.User("Bob", "bob@example.com")
	e.Must("PATCH", e.Base+"/users/"+bob, e.Owner, fiber.Map{"name": "Robert"}, 204)
	e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.ID("POST", e.Base+"/applications", fiber.Map{"name": "ignored"})
	e.drain()
	if got := receiver.types(); fmt.Sprint(got) != "[user.created user.updated organization.created]" {
		t.Fatalf("delivered = %v", got)
	}
	if receiver.events[0]["subject"].(map[string]any)["id"] != bob || receiver.bad != 0 {
		t.Fatalf("event = %v bad = %d", receiver.events[0], receiver.bad)
	}
	deliveries := e.Must("GET", e.Base+"/webhooks/"+sub+"/deliveries?status=delivered", e.Owner, nil, 200)
	if deliveries.JSON["page"].(map[string]any)["total"].(float64) != 3 {
		t.Fatalf("deliveries = %s", deliveries.Body)
	}

	// Test event: sent now, never queued.
	test := e.Must("POST", e.Base+"/webhooks/"+sub+"/test", e.Owner, nil, 200)
	if test.JSON["delivered"] != true || receiver.types()[3] != "webhook.test" {
		t.Fatalf("test = %s", test.Body)
	}

	// A failing endpoint: the delivery is retried later, in order, then
	// given up past the window and retried by an operator.
	receiver.set(http.StatusServiceUnavailable)
	e.Must("PATCH", e.Base+"/users/"+bob, e.Owner, fiber.Map{"name": "Bobby"}, 204)
	e.Must("PATCH", e.Base+"/users/"+bob, e.Owner, fiber.Map{"name": "Bob"}, 204)
	e.drain()
	pending := e.Must("GET", e.Base+"/webhooks/"+sub+"/deliveries?status=pending", e.Owner, nil, 200).JSON["items"].([]any)
	if len(pending) != 2 {
		t.Fatalf("pending = %v", pending)
	}
	head := pending[1].(map[string]any)
	if head["attempts"].(float64) != 1 || head["response_status"].(float64) != 503 || pending[0].(map[string]any)["attempts"].(float64) != 0 {
		t.Fatalf("head = %v, next = %v", head, pending[0])
	}
	if s := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200).JSON; s["failing_since"] == nil || s["pending"].(float64) != 2 {
		t.Fatalf("failing subscription = %v", s)
	}
	// Past the retry window the head is given up and the next one tried.
	e.DB.MustExec(`UPDATE event_deliveries SET first_attempt_at = now() - interval '25 hours', next_attempt_at = now() WHERE id=$1`, int64(head["id"].(float64)))
	e.drain()
	failed := e.Must("GET", e.Base+"/webhooks/"+sub+"/deliveries?status=failed", e.Owner, nil, 200).JSON["items"].([]any)
	if len(failed) != 1 {
		t.Fatalf("failed = %v", failed)
	}
	receiver.set(0)
	e.DB.MustExec(`UPDATE event_deliveries SET next_attempt_at = now() WHERE subscription_id=$1 AND status='pending'`, sub)
	e.drain()
	failedID := int64(failed[0].(map[string]any)["id"].(float64))
	e.Must("POST", fmt.Sprintf("%s/webhooks/%s/deliveries/%d/retry", e.Base, sub, failedID), e.Owner, nil, 202)
	e.Must("POST", fmt.Sprintf("%s/webhooks/%s/deliveries/%d/retry", e.Base, sub, failedID), e.Owner, nil, 404)
	e.drain()
	types := receiver.types()
	if fmt.Sprint(types[4:]) != "[user.updated user.updated]" {
		t.Fatalf("after retry = %v", types)
	}
	if s := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200).JSON; s["failing_since"] != nil {
		t.Fatalf("recovered subscription = %v", s)
	}

	// Rotation: both secrets sign during the overlap.
	rotated := e.Must("POST", e.Base+"/webhooks/"+sub+"/rotate-secret", e.Owner, nil, 200).JSON["secret"].(string)
	receiver.set(0, secret)
	e.User("Carol", "carol@example.com")
	e.drain()
	receiver.set(0, rotated)
	e.User("Dave", "dave@example.com")
	e.drain()
	if n := len(receiver.types()); n != 8 || receiver.bad != 0 {
		t.Fatalf("after rotation = %v bad = %d", receiver.types(), receiver.bad)
	}

	// Replay from an event id queues the matching events again.
	first := int64(receiver.events[0]["id"].(float64))
	replay := e.Must("POST", e.Base+"/webhooks/"+sub+"/replay", e.Owner, fiber.Map{"from": first}, 202)
	if replay.JSON["queued"].(float64) < 6 {
		t.Fatalf("replay = %s", replay.Body)
	}
	e.drain()
	if n := len(receiver.types()); n < 14 {
		t.Fatalf("after replay = %v", receiver.types())
	}
	if receiver.ids[0] == receiver.ids[len(receiver.ids)-1] {
		t.Fatal("a replay is a new message")
	}

	// A subscription failing for three days is disabled; re-enabling resumes.
	receiver.set(http.StatusInternalServerError)
	e.User("Erin", "erin@example.com")
	e.drain()
	e.DB.MustExec(`UPDATE event_subscriptions SET failing_since = now() - interval '4 days' WHERE id=$1`, sub)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "event_webhook_maintenance"); !found || err != nil {
		t.Fatalf("maintenance: %v %v", found, err)
	}
	s := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200).JSON
	if s["active"] != false || s["disabled_reason"] != "failing" {
		t.Fatalf("disabled = %v", s)
	}
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=webhook.*", e.Owner, nil, 200)); !contains(got, "webhook.disabled") || !contains(got, "webhook.created") || !contains(got, "webhook.secret_rotated") {
		t.Fatalf("webhook events = %v", got)
	}
	// Events keep queuing while it is disabled for failing ...
	frank := e.User("Frank", "frank@example.com")
	if s := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200).JSON; s["pending"] != float64(2) {
		t.Fatalf("pending while disabled = %v", s["pending"])
	}
	receiver.set(0)
	e.Must("PATCH", e.Base+"/webhooks/"+sub, e.Owner, fiber.Map{"active": true}, 200)
	e.DB.MustExec(`UPDATE event_deliveries SET next_attempt_at = now() WHERE subscription_id=$1 AND status='pending'`, sub)
	e.drain()
	last := func() map[string]any {
		receiver.mu.Lock()
		defer receiver.mu.Unlock()
		return receiver.events[len(receiver.events)-1]
	}
	if got := last(); got["type"] != "user.created" || got["subject"].(map[string]any)["id"] != frank {
		t.Fatalf("resumed = %v, want frank's user.created", got)
	}
	// ... but not after an operator turned it off.
	e.Must("PATCH", e.Base+"/webhooks/"+sub, e.Owner, fiber.Map{"active": false}, 200)
	e.User("Gina", "gina@example.com")
	if s := e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 200).JSON; s["pending"] != float64(0) {
		t.Fatalf("pending after an operator disable = %v", s["pending"])
	}

	// /api/v1: iam:webhooks:read lists, iam:webhooks:write changes.
	api := "/api/v1/environments/" + e.EnvID + "/webhooks"
	e.Must("GET", api, e.scopedToken("iam:events:read"), nil, 403)
	reader := e.scopedToken("iam:webhooks:read")
	if items := e.Must("GET", api, reader, nil, 200).JSON["items"].([]any); len(items) != 1 {
		t.Fatalf("api list = %v", items)
	}
	e.Must("DELETE", api+"/"+sub, reader, nil, 403)
	e.Must("DELETE", api+"/"+sub, e.scopedToken("iam:webhooks:write"), nil, 204)
	e.Must("GET", e.Base+"/webhooks/"+sub, e.Owner, nil, 404)
}

// TestEventWebhooksGuarded: without a test transport loopback endpoints
// are refused at delivery time, and secrets need an encryption key.
func TestEventWebhooksGuarded(t *testing.T) {
	receiver := &hookReceiver{}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t)
	sub := e.Must("POST", e.Base+"/webhooks", e.Owner, fiber.Map{"name": "local", "url": srv.URL}, 201).JSON["id"].(string)
	test := e.Must("POST", e.Base+"/webhooks/"+sub+"/test", e.Owner, nil, 200).JSON
	if test["delivered"] != false || test["error"] != "the URL does not resolve to a public address" {
		t.Fatalf("test = %v", test)
	}
	if len(receiver.types()) != 0 {
		t.Fatal("guarded transport reached loopback")
	}
}
