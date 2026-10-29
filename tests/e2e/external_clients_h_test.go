package e2e_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/gofiber/fiber/v2"
)

// flushable is a metadata cache a test can empty, so a changed document is
// read again.
type flushable struct {
	mu sync.Mutex
	*cachememory.Store
}

func newFlushable() *flushable { return &flushable{Store: cachememory.New()} }

func (f *flushable) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Store = cachememory.New()
}

func (f *flushable) Get(ctx context.Context, k string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Store.Get(ctx, k)
}

func (f *flushable) Set(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Store.Set(ctx, k, v, ttl)
}

func (f *flushable) SetNX(ctx context.Context, k string, v []byte, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Store.SetNX(ctx, k, v, ttl)
}

func (f *flushable) Delete(ctx context.Context, k ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Store.Delete(ctx, k...)
}

func claudeDoc(redirects ...string) map[string]any {
	return map[string]any{"client_id": claudeCodeID, "client_name": "Claude Code", "redirect_uris": redirects, "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"}
}

func (e *Env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.DB.Get(&n, query, args...); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// loginAndAsk authorizes url_ anonymously, signs alice in and returns the
// final page of the sign-in.
func (e *Env) loginAndAsk(clientID string) page {
	return e.loginAsAndAsk(e.AliceEmail, clientID)
}

// loginAsAndAsk is loginAndAsk for the user with email (shared password).
func (e *Env) loginAsAndAsk(email, clientID string) page {
	e.t.Helper()
	b := e.browser()
	start := b.get(resourceAuthorize(clientID, url.Values{"redirect_uri": {"http://localhost:53682/callback"}}))
	if start.Status != 303 {
		e.t.Fatalf("authorize %s: %d %s", clientID, start.Status, start.Body)
	}
	tk := b.get(start.Location).field("ticket")
	return b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {email}, "password": {e.Pass}})
}

// TestExternalClientFlood is H1: anonymous authorize requests for any
// number of distinct URLs persist nothing and write no event; signed-in
// users create pending rows only up to the environment's cap.
func TestExternalClientFlood(t *testing.T) {
	e := newEnv(t, bootstrap.WithClientMetadataMaxPending(3))
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	e.mcpServer(fiber.Map{})
	host := e.metadataHost()

	urls := make([]string, 500)
	for i := range urls {
		urls[i] = "https://flood.example/clients/" + strings.Repeat("a", 1) + url.PathEscape(string(rune('a'+i%26))) + "/" + itoa(i)
		host.Put(urls[i], map[string]any{"client_id": urls[i], "client_name": "Flood", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	}
	rowsBefore := e.count(`SELECT count(*) FROM oauth_clients`)
	eventsBefore := e.count(`SELECT count(*) FROM events`)
	var served, limited int
	for _, id := range urls {
		switch p := e.browser().get(resourceAuthorize(id, url.Values{"redirect_uri": {"http://localhost:53682/callback"}})); p.Status {
		case 303:
			served++
		case 429:
			limited++
		default:
			t.Fatalf("flood %s: %d %s", id, p.Status, p.Body)
		}
	}
	if got := e.count(`SELECT count(*) FROM oauth_clients`); got != rowsBefore {
		t.Fatalf("anonymous flood persisted %d rows", got-rowsBefore)
	}
	if got := e.count(`SELECT count(*) FROM events`); got != eventsBefore {
		t.Fatalf("anonymous flood wrote %d events", got-eventsBefore)
	}
	// The environment reads at most 60 distinct documents a minute; the
	// rest of the flood is refused before any fetch.
	reads := 0
	for _, id := range urls {
		reads += host.Reads(id)
	}
	if served == 0 || limited == 0 || reads > 60 {
		t.Fatalf("served %d, limited %d, document reads %d", served, limited, reads)
	}
	if served != reads {
		t.Fatalf("served %d != reads %d", served, reads)
	}
}

func TestExternalClientPendingCap(t *testing.T) {
	e := newEnv(t, bootstrap.WithClientMetadataMaxPending(3))
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	var ids []string
	for i := range 5 {
		id := "https://apps.example/client/" + itoa(i)
		ids = append(ids, id)
		host.Put(id, map[string]any{"client_id": id, "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	}
	for i, id := range ids {
		done := e.loginAndAsk(id)
		want := 403
		if i >= 3 {
			want = 429
		}
		if done.Status != want || done.Location != "" {
			t.Fatalf("client %d: %d %q %s", i, done.Status, done.Location, done.Body)
		}
	}
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE source='cimd' AND admission='pending'`); n != 3 {
		t.Fatalf("pending rows = %d, want the cap 3", n)
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.access_requested'`); n != 3 {
		t.Fatalf("access_requested events = %d", n)
	}
	// A known pending client keeps taking requests from new users at the cap.
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE external_id=$1`, ids[4]); n != 0 {
		t.Fatalf("refused client was persisted")
	}
}

// TestExternalClientApprovalBoundToMetadata is H2: a manual approval holds
// for the document IT saw; if its redirect URIs change the client waits for
// IT again, while an allowlisted client stays approved and the change is
// only on record.
func TestExternalClientApprovalBoundToMetadata(t *testing.T) {
	cache := newFlushable()
	e := newEnv(t, bootstrap.WithClientMetadataCache(cache))
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	redirect := "http://localhost:53682/callback"

	// Pending, then approved by hand.
	if done := e.loginAndAsk(claudeCodeID); done.Status != 403 {
		t.Fatalf("pending: %d", done.Status)
	}
	var rowID string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	e.DB.MustExec(`UPDATE oauth_clients SET admission='approved', admission_source='manual' WHERE id=$1`, rowID)
	b := e.browser()
	code := b.signInTo(b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})), redirect)
	form := codeForm(claudeCodeID, code)
	form.Set("redirect_uri", redirect)
	if status, _, _ := e.tokenCall(form, ""); status != 200 {
		t.Fatalf("approved exchange: %d", status)
	}
	// The same document again changes nothing.
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})); p.Status != 303 {
		t.Fatalf("refetch: %d", p.Status)
	}
	if got := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.updated' AND subject_id=$1`, rowID); got != 0 {
		var data string
		e.DB.Get(&data, `SELECT data::text FROM events WHERE type='oauth_client.updated' AND subject_id=$1`, rowID)
		t.Fatalf("unchanged document wrote %d updates: %s", got, data)
	}

	// The host adds a redirect: back to pending, on record, asked anew.
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback", "https://evil.example/cb"))
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})); p.Status != 303 {
		t.Fatalf("changed authorize: %d %s", p.Status, p.Body)
	}
	var admission string
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, rowID)
	if admission != "pending" {
		t.Fatalf("admission after change = %q", admission)
	}
	var data string
	e.DB.Get(&data, `SELECT data::text FROM events WHERE type='oauth_client.updated' AND subject_id=$1`, rowID)
	if !strings.Contains(data, "redirect_uris") || !strings.Contains(data, "evil.example") || !strings.Contains(data, `"approval_metadata_changed": true`) {
		t.Fatalf("updated event = %s", data)
	}
	// L-4: the grant given for the approved document ended with the approval.
	if !strings.Contains(data, `"revoked_sessions": 1`) {
		t.Fatalf("demotion did not record the revoked session: %s", data)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, rowID); n != 0 {
		t.Fatalf("%d sessions of the demoted client stay live", n)
	}
	before := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.access_requested' AND subject_id=$1`, rowID)
	if done := e.loginAndAsk(claudeCodeID); done.Status != 403 {
		t.Fatalf("pending after change: %d %s", done.Status, done.Body)
	}
	if got := e.count(`SELECT count(*) FROM events WHERE type='oauth_client.access_requested' AND subject_id=$1`, rowID); got != before+1 {
		t.Fatalf("access_requested after change: %d, was %d)", got, before)
	}

	// Allowlisted: stays approved, the change is recorded.
	listed := "https://listed.example/oauth/client.json"
	doc := func(redirects ...string) map[string]any {
		return map[string]any{"client_id": listed, "client_name": "Listed", "redirect_uris": redirects, "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"}
	}
	e.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://listed.example','/oauth/client.json')`, e.EnvID)
	host.Put(listed, doc("http://localhost/callback"))
	b = e.browser()
	code = b.signInTo(b.get(resourceAuthorize(listed, url.Values{"redirect_uri": {redirect}})), redirect)
	form = codeForm(listed, code)
	form.Set("redirect_uri", redirect)
	if status, _, _ := e.tokenCall(form, ""); status != 200 {
		t.Fatalf("allowlisted exchange: %d", status)
	}
	var source string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, listed)
	e.DB.Get(&source, `SELECT admission_source FROM oauth_clients WHERE id=$1`, rowID)
	if source != "allowlist" {
		t.Fatalf("admission_source = %q", source)
	}
	host.Put(listed, doc("http://localhost/callback", "https://other.example/cb"))
	cache.Flush()
	if p := e.browser().get(resourceAuthorize(listed, url.Values{"redirect_uri": {redirect}})); p.Status != 303 {
		t.Fatalf("allowlisted changed authorize: %d", p.Status)
	}
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, rowID)
	e.DB.Get(&data, `SELECT data::text FROM events WHERE type='oauth_client.updated' AND subject_id=$1`, rowID)
	if admission != "approved" || !strings.Contains(data, "other.example") || !strings.Contains(data, `"approval_metadata_changed": true`) {
		t.Fatalf("allowlisted: admission %q, event %s", admission, data)
	}
	_ = protected
}

// TestExternalClientLastUsedAndReuse covers L4 (last_used_at, written at
// most once an interval) and M4 (an unknown grant is invalid_grant; reusing
// a rotated refresh token still revokes the family).
func TestExternalClientLastUsedAndReuse(t *testing.T) {
	e := newEnv(t)
	e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	e.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://claude.ai','/oauth/claude-code-client-metadata')`, e.EnvID)
	redirect := "http://localhost:53682/callback"
	b := e.browser()
	code := b.signInTo(b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {redirect}})), redirect)
	var rowID string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	if e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1 AND last_used_at IS NULL`, rowID) != 1 {
		t.Fatal("last_used_at set before any token")
	}
	form := codeForm(claudeCodeID, code)
	form.Set("redirect_uri", redirect)
	status, first, _ := e.tokenCall(form, "")
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, first)
	}
	used := func() time.Time {
		var at *time.Time
		e.DB.Get(&at, `SELECT last_used_at FROM oauth_clients WHERE id=$1`, rowID)
		if at == nil {
			t.Fatal("last_used_at not set")
		}
		return *at
	}
	firstUse := used()
	// Within the interval a refresh does not write it again.
	status, second, _ := e.tokenCall(refreshForm(claudeCodeID, first["refresh_token"].(string)), "")
	if status != 200 || !used().Equal(firstUse) {
		t.Fatalf("refresh: %d, last_used_at moved within the interval", status)
	}
	// Past it, it moves.
	e.DB.MustExec(`UPDATE oauth_clients SET last_used_at = now() - interval '2 hours' WHERE id=$1`, rowID)
	old := used()
	status, third, _ := e.tokenCall(refreshForm(claudeCodeID, second["refresh_token"].(string)), "")
	if status != 200 || !used().After(old.Add(time.Hour)) {
		t.Fatalf("refresh after the interval: %d", status)
	}
	// Bookkeeping is not change history.
	if n := e.count(`SELECT count(*) FROM events WHERE data::text LIKE '%last_used_at%'`); n != 0 {
		t.Fatalf("last_used_at leaked into %d events", n)
	}

	// D10: the first refresh token was rotated; presenting it again is
	// reuse, and the family dies — the newest token with it.
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, first["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reused refresh token: %d %v", status, out)
	}
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, third["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("family survived reuse: %d %v", status, out)
	}
	// A token nobody issued: invalid_grant at the token endpoint, 200 at revoke.
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, "not-a-token.signature"), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("unknown refresh token: %d %v", status, out)
	}
	if got := httpForm(t, e, "/oauth/revoke", url.Values{"client_id": {claudeCodeID}, "token": {"not-a-token.signature"}}); got != 200 {
		t.Fatalf("revoke unknown token: %d", got)
	}
}

// TestClientPendingPrune: the job deletes pending clients nobody used for
// the retention (counted from the latest request for them), keeps recent,
// used and approved ones.
func TestClientPendingPrune(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})
	row := func(name, admission, age string, used bool) string {
		id := ""
		last := "NULL"
		if used {
			last = "now()"
		}
		e.DB.Get(&id, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,hosted_login,token_endpoint_auth_method,grant_types,source,external_id,protected_resource_id,admission,discovered_at,last_used_at)
			VALUES(gen_random_uuid(),$1,$2,$3,'{http://localhost/callback}',true,true,'none','{authorization_code,refresh_token}','cimd',$4,$5,$6,now()-$7::interval,`+last+`) RETURNING id`,
			e.EnvID, e.Client, resource, "https://"+name+".example/c", protected, admission, age)
		return id
	}
	old := row("old", "pending", "31 days", false)
	recent := row("recent", "pending", "2 days", false)
	used := row("used", "pending", "40 days", true)
	approved := row("approved", "approved", "40 days", false)
	// L-1: old rows users still ask for are kept; an old request does not.
	asked := row("asked", "pending", "60 days", false)
	askedLong := row("askedlong", "pending", "60 days", false)
	e.DB.MustExec(`INSERT INTO oauth_client_access_requests(client_id,environment_id,user_id,requested_at) VALUES($1,$3,$4,now()-interval '2 days'),($2,$3,$4,now()-interval '45 days')`, asked, askedLong, e.EnvID, e.Alice)
	// W5-5: a client with token rows (used, its last_used_at write lost,
	// then demoted) stays, and does not fail the batch.
	tokened := row("tokened", "pending", "40 days", false)
	e.DB.MustExec(`INSERT INTO oauth_requests(environment_id,kind,signature_hash,client_id,request_id,data,expires_at,active) VALUES($1,'refresh','sig-w5-5',$2,'req','{}',now()-interval '1 day',false)`, e.EnvID, tokened)
	deviced := row("deviced", "pending", "40 days", false)
	e.DB.MustExec(`INSERT INTO oauth_device_codes(device_hash,user_hash,environment_id,client_id,scope,interval_seconds,expires_at) VALUES('\x01','\x02',$1,$2,'',5,now()-interval '1 day')`, e.EnvID, deviced)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_pending_prune"); !found || err != nil {
		t.Fatalf("run: %v %v", found, err)
	}
	for id, want := range map[string]int{old: 0, recent: 1, used: 1, approved: 1, asked: 1, askedLong: 0, tokened: 1, deviced: 1} {
		if got := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1`, id); got != want {
			t.Errorf("row %s present = %d, want %d", id, got, want)
		}
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var out []byte
	for ; i > 0; i /= 10 {
		out = append([]byte{digits[i%10]}, out...)
	}
	return string(out)
}
