package e2e_test

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// The races of the external-client work, made deterministic (W4-7, W4-8):
// a rowGate holds the row the racers contend for, every racer is started
// and seen waiting on a lock (pg_stat_activity) before the gate opens, so
// each test exercises the overlap it names on any machine. One lock order
// (protected resource, then client rows, then tickets, token rows and
// sessions) means no 40P01: every request ends in a success or a clean
// refusal, never a 500.

// raceEnv is an MCP server with Claude Code approved, alice signed in to it
// once (so she may finish sign-ins), and a high rate limit.
type raceEnv struct {
	*Env
	protected, base, row string
}

func newRaceEnv(t *testing.T) raceEnv {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 1000000
	// Each browser signs in from its own address: the hosted sign-in
	// limiter (per address) must not answer before Complete runs.
	e.Server.TrustedProxies = []string{"0.0.0.0/8"}
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	e.metadataHost().Put(claudeCodeID, claudeDoc(loopback))
	r := raceEnv{Env: e, protected: protected, base: e.Base + "/protected-resources/" + protected}
	if p := e.loginAndAsk(claudeCodeID); p.Status != 403 {
		t.Fatalf("first ask: %d", p.Status)
	}
	e.DB.Get(&r.row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	e.approveClient(r.base, r.row)
	return r
}

func (r raceEnv) live() int {
	return r.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, r.row)
}

func (r raceEnv) liveTokens() int {
	return r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1 AND active AND kind IN ('access','refresh') AND expires_at>now()`, r.row)
}

// codes signs alice in n times through the client and returns the codes.
func (r raceEnv) codes(n int) []string {
	r.t.Helper()
	out := make([]string, n)
	for i := range out {
		b := r.browser()
		b.ip = "203.0.113." + itoa(1+i%250)
		out[i] = b.signInTo(b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {loopback}})), loopback)
	}
	return out
}

func exchangeForm(code string) url.Values {
	form := codeForm(claudeCodeID, code)
	form.Set("redirect_uri", loopback)
	return form
}

// operator runs an operator call from a goroutine; the status is checked
// after the race.
type operatorCall struct {
	method, path string
	body         any
	want         int
	got          Response
}

func (r raceEnv) call(c *operatorCall) { c.got = r.Do(c.method, c.path, r.Owner, c.body) }

func (c *operatorCall) check(t *testing.T) {
	t.Helper()
	if c.got.Status != c.want {
		t.Fatalf("%s %s: %d %s", c.method, c.path, c.got.Status, c.got.Body)
	}
}

// refused is a token answer that is a clean refusal of the grant.
func refused(status int, out map[string]any) bool {
	return status == 400 && (out["error"] == "invalid_grant" || out["error"] == "invalid_request")
}

// TestTokenRequestsRaceBlocks is W4-1: code exchanges and refreshes of an
// external client run while IT blocks, forgets or demotes it. The token
// transactions hold their token rows; the operator holds the client row and
// revokes those token rows. Each request either finishes before the change
// (its tokens are then revoked by it) or is refused after it; nothing is
// left live, no request and no operator call fails with a deadlock.
func TestTokenRequestsRaceBlocks(t *testing.T) {
	r := newRaceEnv(t)
	const n = 6

	// Each case: the requests (token forms) and the change.
	type round struct {
		name        string
		forms       func() []url.Values
		change      *operatorCall
		after       func()
		changeFirst bool
	}
	exchanges := func() []url.Values {
		var forms []url.Values
		for _, code := range r.codes(n) {
			forms = append(forms, exchangeForm(code))
		}
		return forms
	}
	refreshes := func() []url.Values {
		var forms []url.Values
		for _, code := range r.codes(n) {
			status, out := r.tokenTry(exchangeForm(code))
			if status != 200 {
				t.Fatalf("exchange: %d %v", status, out)
			}
			forms = append(forms, refreshForm(claudeCodeID, out["refresh_token"].(string)))
		}
		return forms
	}
	readmit := func() {
		r.Must("POST", r.base+"/clients/"+r.row+"/unblock", r.Owner, nil, 200)
		r.approveClient(r.base, r.row)
	}
	rounds := []round{
		{"block during code exchange", exchanges, &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}, readmit, false},
		{"block during refresh", refreshes, &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}, readmit, false},
		{"documents off during refresh", refreshes, &operatorCall{method: "PATCH", path: r.base, body: fiber.Map{"allow_client_metadata": false}, want: 200}, func() {
			r.Must("PATCH", r.base, r.Owner, fiber.Map{"allow_client_metadata": true}, 200)
			r.approveClient(r.base, r.row)
		}, false},
		{"code exchange after a block", exchanges, &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}, readmit, true},
		{"refresh after a block", refreshes, &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}, readmit, true},
	}
	// race queues the token requests on the client row (a gate holds it as
	// a change of admission does), then the change behind them, and opens
	// the gate: the token transactions (which take the client row first,
	// FOR SHARE) and the change run against each other in either order.
	// With changeFirst the change queues first (W5-3): it commits before
	// any token transaction locks the client, so every request is refused
	// (the code was read before the block; its transaction finds the client
	// not admitted).
	race := func(forms []url.Values, change *operatorCall, changeFirst bool) ([]int, []map[string]any) {
		t.Helper()
		gate := r.holdRows(`SELECT 1 FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`, r.row)
		var wg sync.WaitGroup
		statuses := make([]int, len(forms))
		answers := make([]map[string]any, len(forms))
		queued := 0
		if changeFirst {
			wg.Add(1)
			go func() { defer wg.Done(); r.call(change) }()
			queued++
			r.waitFor("the change queued on the client", func() bool { return r.locked("oauth_clients") >= queued })
		}
		for i, form := range forms {
			wg.Add(1)
			go func() { defer wg.Done(); statuses[i], answers[i] = r.tokenTry(form) }()
		}
		queued += len(forms)
		r.waitFor("token requests queued on the client", func() bool { return r.locked("oauth_clients") >= queued })
		if !changeFirst {
			wg.Add(1)
			go func() { defer wg.Done(); r.call(change) }()
			queued++
			r.waitFor("the change queued on the client", func() bool { return r.locked("oauth_clients") >= queued })
		}
		gate.open()
		wg.Wait()
		change.check(t)
		return statuses, answers
	}
	for _, rd := range rounds {
		statuses, answers := race(rd.forms(), rd.change, rd.changeFirst)
		for i := range statuses {
			if statuses[i] != 200 && !refused(statuses[i], answers[i]) {
				t.Fatalf("%s: request %d: %d %v", rd.name, i, statuses[i], answers[i])
			}
			if rd.changeFirst && statuses[i] == 200 {
				t.Fatalf("%s: request %d got tokens after the change committed", rd.name, i)
			}
		}
		if n := r.live(); n != 0 {
			t.Fatalf("%s: %d sessions outlived the change", rd.name, n)
		}
		if n := r.liveTokens(); n != 0 {
			t.Fatalf("%s: %d tokens outlived the change", rd.name, n)
		}
		rd.after()
	}

	// Forget: the row goes with its token rows; a request queued behind it
	// finds no client, one ahead of it issues tokens the forget deletes.
	statuses, answers := race(refreshes(), &operatorCall{method: "DELETE", path: r.base + "/clients/" + r.row, want: 204}, false)
	for i := range statuses {
		if statuses[i] >= 500 {
			t.Fatalf("forget: request %d: %d %v", i, statuses[i], answers[i])
		}
	}
	if n := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1`, r.row); n != 0 {
		t.Fatalf("forget left %d token rows", n)
	}
}

// TestTokenTransactionRechecksAdmission isolates the token transaction's
// own admission check (W4-1): a refresh passes the at-use check, queues on
// the client row (BeginTX, FOR SHARE), and while it waits the client stops
// being admitted without its tokens being revoked (an approval past its
// expiry that the job has not reached). The transaction reads the row it
// locked and refuses: invalid_grant, no new tokens.
func TestTokenTransactionRechecksAdmission(t *testing.T) {
	r := newRaceEnv(t)
	status, out := r.tokenTry(exchangeForm(r.codes(1)[0]))
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, out)
	}
	code := r.codes(1)[0]
	expire := func(gate *rowGate) {
		if _, err := gate.tx.Exec(`UPDATE oauth_clients SET admission_expires_at=now()-interval '1 second' WHERE id=$1`, r.row); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name string
		form url.Values
	}{
		{"refresh", refreshForm(claudeCodeID, out["refresh_token"].(string))},
		// W5-3: the code exchange refuses before it spends the code.
		{"code exchange", exchangeForm(code)},
	} {
		r.DB.MustExec(`UPDATE oauth_clients SET admission_expires_at=NULL WHERE id=$1`, r.row)
		before := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1`, r.row)
		gate := r.holdRows(`SELECT 1 FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`, r.row)
		done := make(chan struct{})
		var got int
		var answer map[string]any
		go func() {
			defer close(done)
			got, answer = r.tokenTry(c.form)
		}()
		r.waitFor("the token request queued on the client", func() bool { return r.locked("oauth_clients") >= 1 })
		expire(gate)
		gate.open()
		<-done
		if !refused(got, answer) || answer["error"] != "invalid_grant" {
			t.Fatalf("%s of a client no longer admitted: %d %v", c.name, got, answer["error"])
		}
		if n := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1`, r.row); n != before {
			t.Fatalf("the refused %s stored %d token rows", c.name, n-before)
		}
	}
	if n := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1 AND kind='code' AND active`, r.row); n != 1 {
		t.Fatalf("the refused exchange spent its code (%d active codes)", n)
	}

	// W5-1: a sign-in queued on the client while it stops being admitted
	// gets the refusal page and stores no code. (It queues on Complete's
	// share lock, the first it takes; the code's own transaction rechecks
	// the same way, see TestSignInsRaceOperatorChanges for its race.)
	r.DB.MustExec(`UPDATE oauth_clients SET admission_expires_at=NULL WHERE id=$1`, r.row)
	b := r.browser()
	start := b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {loopback}}))
	ticket := b.get(start.Location).field("ticket")
	before := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1`, r.row)
	gate := r.holdRows(`SELECT 1 FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`, r.row)
	done := make(chan page)
	go func() {
		done <- b.post("/hosted/login/password", url.Values{"ticket": {ticket}, "email": {r.AliceEmail}, "password": {r.Pass}})
	}()
	r.waitFor("the sign-in queued on the client", func() bool { return r.locked("oauth_clients") >= 1 })
	expire(gate)
	gate.open()
	p := <-done
	if p.Status != 403 || !strings.Contains(p.Body, "Waiting for approval") {
		t.Fatalf("sign-in of a client no longer admitted: %d %q", p.Status, p.Location)
	}
	if n := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1`, r.row); n != before {
		t.Fatalf("the refused sign-in stored %d rows", n-before)
	}
}

// TestTokenRequestHoldingItsRowRacesABlock is the cycle of W4-1 itself: a
// refresh that already holds its token row (a test transaction stands in
// for it) and a block of its client. Before the fix the refresh's insert
// waited for the block's client lock while the block waited for the token
// row: 40P01. Now the block passes the client row, waits for the token row,
// and the refresh is refused or revoked.
func TestTokenRequestHoldingItsRowRacesABlock(t *testing.T) {
	r := newRaceEnv(t)
	code := r.codes(1)[0]
	status, out := r.tokenTry(exchangeForm(code))
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, out)
	}
	// The block must not need a full lock of the client row: it waits for
	// the token rows only, behind the gate on them.
	gate := r.holdRows(`SELECT 1 FROM oauth_requests WHERE client_id=$1 FOR UPDATE`, r.row)
	// While the token rows are held, a key-share lock of the client (what
	// a token insert's foreign key takes) still passes the block's lock.
	block := &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}
	done := make(chan struct{})
	go func() { defer close(done); r.call(block) }()
	r.waitLocked(1)
	var one int
	if err := r.DB.Get(&one, `SELECT 1 FROM oauth_clients WHERE id=$1 FOR KEY SHARE NOWAIT`, r.row); err != nil {
		t.Fatalf("a token insert's key-share lock of the client waits for the block: %v", err)
	}
	gate.open()
	<-done
	block.check(t)
	if status, out := r.tokenTry(refreshForm(claudeCodeID, out["refresh_token"].(string))); !refused(status, out) {
		t.Fatalf("refresh after the block: %d %v", status, out)
	}
	if n := r.liveTokens(); n != 0 {
		t.Fatalf("%d tokens outlived the block", n)
	}
}

// TestSignInsRaceOperatorChanges is N-1/N-2 with W4-8: users finishing
// their sign-in (Complete: the client, then the ticket) while IT blocks
// the client, turns document clients off or deletes the server (each: the
// server or the client first, then tickets and sessions). Every sign-in is
// a redirect or a refusal page, every operator call succeeds, and once the
// change commits no session of the client is left.
func TestSignInsRaceOperatorChanges(t *testing.T) {
	r := newRaceEnv(t)
	const n = 6
	addr := 0
	// started returns browsers at the password step of fresh authorizations.
	started := func() ([]*browser, []string) {
		var bs []*browser
		var tks []string
		for range n {
			b := r.browser()
			addr++
			b.ip = "198.51." + itoa(addr/250) + "." + itoa(1+addr%250)
			start := b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {loopback}}))
			if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
				t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
			}
			bs = append(bs, b)
			tks = append(tks, b.get(start.Location).field("ticket"))
		}
		return bs, tks
	}
	race := func(name string, change *operatorCall) {
		t.Helper()
		bs, tks := started()
		// The gate holds the client row for a change of its admission: the
		// sign-ins reach Complete (after the password hash) and queue on
		// the client; the operator's change queues behind them.
		gate := r.holdRows(`SELECT 1 FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`, r.row)
		var wg sync.WaitGroup
		pages := make([]page, n)
		for i := range bs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pages[i] = bs[i].post("/hosted/login/password", url.Values{"ticket": {tks[i]}, "email": {r.AliceEmail}, "password": {r.Pass}})
			}()
		}
		// W5-1: count only the statements waiting on the client row (the
		// sign-ins also serialize on alice's user row before Complete).
		r.waitFor("sign-ins queued on the client", func() bool { return r.locked("oauth_clients") >= n })
		wg.Add(1)
		go func() { defer wg.Done(); r.call(change) }()
		r.waitFor("the change queued on the client", func() bool { return r.locked("oauth_clients") >= n+1 })
		gate.open()
		wg.Wait()
		change.check(t)
		refusals := map[string]bool{"Waiting for approval": true, "Application blocked": true, "Application not available": true}
		codes := 0
		for i, p := range pages {
			title := ""
			if m := regexp.MustCompile(`<title>([^<·]*)`).FindStringSubmatch(p.Body); m != nil {
				title = strings.TrimSpace(m[1])
			}
			switch {
			case p.Status == 303 && strings.HasPrefix(p.Location, loopback+"?code="):
				codes++
			case p.Status >= 400 && p.Status < 500 && refusals[title]:
			default:
				t.Fatalf("%s: sign-in %d: %d %q %q, want a code or a refusal page", name, i, p.Status, p.Location, title)
			}
		}
		t.Logf("%s: %d codes, %d refusals", name, codes, n-codes)
		if live := r.count(`SELECT count(*) FROM oauth_requests WHERE client_id=$1 AND active AND expires_at>now()`, r.row); live != 0 {
			t.Fatalf("%s: %d live codes or tokens outlived the change", name, live)
		}
		if n := r.live(); n != 0 {
			t.Fatalf("%s: %d sessions outlived the change", name, n)
		}
	}
	race("block", &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200})
	r.Must("POST", r.base+"/clients/"+r.row+"/unblock", r.Owner, nil, 200)
	r.approveClient(r.base, r.row)

	race("documents off", &operatorCall{method: "PATCH", path: r.base, body: fiber.Map{"allow_client_metadata": false}, want: 200})
	var admission string
	r.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, r.row)
	if admission != "pending" {
		t.Fatalf("admission %q after allow_client_metadata off (N-2)", admission)
	}
	r.Must("PATCH", r.base, r.Owner, fiber.Map{"allow_client_metadata": true}, 200)
	r.approveClient(r.base, r.row)

	race("delete", &operatorCall{method: "DELETE", path: r.base, want: 204})
	if n := r.count(`SELECT count(*) FROM oauth_clients WHERE id=$1`, r.row); n != 0 {
		t.Fatal("the client outlived its server")
	}
}

// TestProtectedResourceUpdateRacesDelete is W4-2 and W4-3: a PATCH that
// reconciles the server's clients (and ends its grants) and a DELETE of the
// same server, and a PATCH that ends the grants racing a block. All take
// the server, then the clients, then the sessions.
func TestProtectedResourceUpdateRacesDelete(t *testing.T) {
	r := newRaceEnv(t)
	r.codes(1)
	// PATCH (documents off + inactive) against a block of the client (W4-3).
	// The gate holds the client row; the block queues on it first, then the
	// PATCH. In the old order the PATCH ended the server's sessions before
	// queuing on the client, so once the gate opened the block (holding the
	// client) waited for those sessions and the PATCH for the client: 40P01.
	// Now the PATCH takes the client before the sessions.
	gate := r.holdRows(`SELECT 1 FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`, r.row)
	patch := &operatorCall{method: "PATCH", path: r.base, body: fiber.Map{"allow_client_metadata": false, "active": false}, want: 200}
	block := &operatorCall{method: "POST", path: r.base + "/clients/" + r.row + "/block", want: 200}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.call(block) }()
	r.waitLocked(1)
	go func() { defer wg.Done(); r.call(patch) }()
	r.waitLocked(2)
	gate.open()
	wg.Wait()
	block.check(t)
	patch.check(t)

	// PATCH against DELETE: the gate holds the server row; both queue on
	// it, in either order.
	r.Must("PATCH", r.base, r.Owner, fiber.Map{"allow_client_metadata": true, "active": true}, 200)
	r.Must("POST", r.base+"/clients/"+r.row+"/unblock", r.Owner, nil, 200)
	r.approveClient(r.base, r.row)
	r.codes(1)
	gate = r.holdRows(`SELECT 1 FROM protected_resources WHERE id=$1 FOR NO KEY UPDATE`, r.protected)
	patch = &operatorCall{method: "PATCH", path: r.base, body: fiber.Map{"allow_client_metadata": false}}
	del := &operatorCall{method: "DELETE", path: r.base, want: 204}
	wg.Add(2)
	go func() { defer wg.Done(); r.call(patch) }()
	r.waitLocked(1)
	go func() { defer wg.Done(); r.call(del) }()
	r.waitLocked(2)
	gate.open()
	wg.Wait()
	del.check(t)
	// The PATCH ran first (200) or found the server gone (404).
	if patch.got.Status != 200 && patch.got.Status != 404 {
		t.Fatalf("patch: %d %s", patch.got.Status, patch.got.Body)
	}
	if n := r.count(`SELECT count(*) FROM oauth_clients WHERE id=$1`, r.row); n != 0 {
		t.Fatal("the client outlived its server")
	}
}

// TestProtectedResourceConcurrentUpdates is N-9 with W4-7: two operators
// change different settings of a server at once (both queued on the
// server row before either runs); neither change is reverted by the other.
// Two changes of the TTL bounds that are each valid but not together end in
// a 409 for the second, and default_scopes [] clears the defaults.
func TestProtectedResourceConcurrentUpdates(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 1000000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	base := e.Base + "/protected-resources/" + protected
	// both sends a and b while the server row is held and opens the gate
	// once both wait for it.
	both := func(a, b fiber.Map) (int, int) {
		t.Helper()
		gate := e.holdRows(`SELECT 1 FROM protected_resources WHERE id=$1 FOR NO KEY UPDATE`, protected)
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		for i, body := range []fiber.Map{a, b} {
			wg.Add(1)
			go func() { defer wg.Done(); statuses[i] = e.Do("PATCH", base, e.Owner, body).Status }()
		}
		e.waitLocked(2)
		gate.open()
		wg.Wait()
		return statuses[0], statuses[1]
	}
	for round := range 4 {
		name := "Server " + itoa(round)
		admission := []string{"open", "allowlist"}[round%2]
		if a, b := both(fiber.Map{"name": name}, fiber.Map{"client_admission": admission}); a != 200 || b != 200 {
			t.Fatalf("round %d: %d %d", round, a, b)
		}
		var got struct {
			Name      string `db:"name"`
			Admission string `db:"client_admission"`
		}
		e.DB.Get(&got, `SELECT name,client_admission FROM protected_resources WHERE id=$1`, protected)
		if got.Name != name || got.Admission != admission {
			t.Fatalf("round %d: %+v, want %q %q (one PATCH reverted the other)", round, got, name, admission)
		}
	}

	// idle 1h ≤ max 2h; one lowers max to 1h30 (valid with idle 1h), the
	// other raises idle to 1h45 (valid with max 2h). Together: idle > max.
	e.Must("PATCH", base, e.Owner, fiber.Map{"idle_ttl_seconds": 3600, "max_ttl_seconds": 7200}, 200)
	a, b := both(fiber.Map{"max_ttl_seconds": 5400}, fiber.Map{"idle_ttl_seconds": 6300})
	if !((a == 200 && b == 409) || (a == 409 && b == 200)) {
		t.Fatalf("ttl race: %d %d, want one 200 and one 409", a, b)
	}
	var ttl struct {
		Idle int `db:"idle_ttl_seconds"`
		Max  int `db:"max_ttl_seconds"`
	}
	e.DB.Get(&ttl, `SELECT idle_ttl_seconds,max_ttl_seconds FROM protected_resources WHERE id=$1`, protected)
	if ttl.Idle > ttl.Max {
		t.Fatalf("ttl %+v", ttl)
	}

	e.Must("PATCH", base, e.Owner, fiber.Map{"default_scopes": []string{}}, 200)
	var scopes string
	e.DB.Get(&scopes, `SELECT default_scopes::text FROM protected_resources WHERE id=$1`, protected)
	if scopes != "{}" {
		t.Fatalf("default_scopes [] left %s", scopes)
	}
}

// TestProtectedResourceLockLetsAuthorizationsThrough is W4-4: a PATCH holds
// its server row FOR NO KEY UPDATE, which the foreign keys of a new ticket
// (an authorize request) do not wait for. A plain FOR UPDATE held every
// sign-in to the server until the PATCH (and its demotions) committed.
func TestProtectedResourceLockLetsAuthorizationsThrough(t *testing.T) {
	r := newRaceEnv(t)
	r.codes(1)
	// The real PATCH (deactivate) locks the server, then waits for the
	// client's sessions (ending the grants) behind the gate, holding the
	// server lock meanwhile. Authorize touches neither the sessions nor
	// (in this PATCH) the client row.
	gate := r.holdRows(`SELECT 1 FROM sessions WHERE oauth_client_id=$1 FOR UPDATE`, r.row)
	patch := &operatorCall{method: "PATCH", path: r.base, body: fiber.Map{"active": false}, want: 200}
	done := make(chan struct{})
	go func() { defer close(done); r.call(patch) }()
	r.waitLocked(1)
	// A client the server has not seen: its ticket names the server
	// (protected_resource_id), whose foreign key takes a key-share lock.
	other := "https://tools.example/oauth/client.json"
	doc := claudeDoc(loopback)
	doc["client_id"] = other
	host := r.metadataHost()
	host.Put(claudeCodeID, claudeDoc(loopback))
	host.Put(other, doc)
	start := r.browser().get(resourceAuthorize(other, url.Values{"redirect_uri": {loopback}}))
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		t.Fatalf("authorize while the server is being updated: %d %q", start.Status, start.Location)
	}
	gate.open()
	<-done
	patch.check(t)
}

// TestCombinedPatchAdmitsByPolicy is W4-5: one PATCH turns document clients
// back on and leaves open mode for the allowlist. The waiting clients the
// allowlist covers are admitted (the demotion of open-mode approvals runs
// first, then the admission by the new policy).
func TestCombinedPatchAdmitsByPolicy(t *testing.T) {
	r := newRaceEnv(t)
	r.Must("PATCH", r.base, r.Owner, fiber.Map{"client_admission": "open"}, 200)
	r.Must("PATCH", r.base, r.Owner, fiber.Map{"allow_client_metadata": false}, 200)
	var admission string
	r.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, r.row)
	if admission != "pending" {
		t.Fatalf("admission %q after documents off", admission)
	}
	u, _ := url.Parse(claudeCodeID)
	r.Must("POST", r.Base+"/oauth-client-allowlist", r.Owner, fiber.Map{"origin": u.Scheme + "://" + u.Host, "path_prefix": u.Path, "protected_resource_id": r.protected}, 201)
	r.Must("PATCH", r.base, r.Owner, fiber.Map{"allow_client_metadata": true, "client_admission": "allowlist"}, 200)
	var got struct {
		Admission string `db:"admission"`
		Source    string `db:"admission_source"`
	}
	r.DB.Get(&got, `SELECT admission,COALESCE(admission_source,'') AS admission_source FROM oauth_clients WHERE id=$1`, r.row)
	if got.Admission != "approved" || got.Source != "allowlist" {
		t.Fatalf("after documents on + allowlist: %+v, want approved by the allowlist", got)
	}
}
