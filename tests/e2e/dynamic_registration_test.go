package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/gofiber/fiber/v2"
)

// registerClient posts body to /oauth/register (raw JSON) from a fresh
// address (the per-address limit is tested on its own) and decodes the
// answer.
func (e *Env) registerClient(body string) Response {
	e.t.Helper()
	registrations++
	return e.registerFrom(fmt.Sprintf("10.9.%d.%d", registrations/250, registrations%250+1), body)
}

var registrations int

func (e *Env) registerFrom(ip, body string) Response {
	e.t.Helper()
	r := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", ip)
	res, err := e.App.Test(r, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: string(raw)}
	if res.StatusCode != 429 && res.Header.Get("Cache-Control") != "no-store" {
		e.t.Fatalf("register Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

// newDCREnv trusts the harness as a proxy, so each registration may come
// from its own address (X-Forwarded-For).
func newDCREnv(t *testing.T, opts ...bootstrap.Option) *Env {
	e := newEnv(t, opts...)
	e.Server.TrustedProxies = []string{"0.0.0.0/8"}
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	return e
}

// TestDynamicClientRegistration: RFC 7591 end to end. Registration is
// offered only while some environment takes such clients; a registration
// writes nothing an operator sees until a signed-in user asks for a server
// that takes it; then it is admitted like any external client, and every
// refusal is a page.
func TestDynamicClientRegistration(t *testing.T) {
	cache := newFlushable()
	e := newDCREnv(t, bootstrap.WithClientMetadataCache(cache))
	offered := func() bool {
		t.Helper()
		cache.Flush()
		d := e.Must("GET", "/.well-known/oauth-authorization-server", "", nil, 200).JSON
		o := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).JSON
		if d["registration_endpoint"] != o["registration_endpoint"] {
			t.Fatalf("documents disagree: %v %v", d["registration_endpoint"], o["registration_endpoint"])
		}
		if v, ok := d["registration_endpoint"]; ok {
			if v != testIssuer+"/oauth/register" {
				t.Fatalf("registration_endpoint = %v", v)
			}
			return true
		}
		return false
	}
	body := `{"client_name":"Tool","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}`

	// D28: nothing takes registered clients yet: not advertised, 404.
	_, protected, _ := e.mcpServer(fiber.Map{})
	if offered() {
		t.Fatal("offered with the feature off and no server allowing it")
	}
	if r := e.registerClient(body); r.Status != 404 {
		t.Fatalf("register while not offered: %d %s", r.Status, r.Body)
	}
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"allow_dynamic_registration": true}, 200)
	if offered() {
		t.Fatal("offered with the feature off")
	}
	e.Must("PUT", e.Base+"/features/dynamic_client_registration", e.Owner, fiber.Map{"enabled": true}, 200)
	if !offered() {
		t.Fatal("not offered with the feature on and a server allowing it")
	}
	if got := e.Must("GET", e.Base+"/protected-resources/"+protected, e.Owner, nil, 200).JSON["allow_dynamic_registration"]; got != true {
		t.Fatalf("allow_dynamic_registration = %v", got)
	}

	// Invalid requests are RFC 7591 errors.
	for _, bad := range []struct{ body, code string }{
		{`{"redirect_uris":[]}`, "invalid_redirect_uri"},
		{`{"redirect_uris":["http://evil.example/cb"]}`, "invalid_redirect_uri"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, "invalid_client_metadata"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"jwks_uri":"https://a.example/jwks"}`, "invalid_client_metadata"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"grant_types":["client_credentials"]}`, "invalid_client_metadata"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"client_name":"` + strings.Repeat("n", 101) + `"}`, "invalid_client_metadata"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"software_statement":"x.y.z"}`, "invalid_client_metadata"},
		{`[1]`, "invalid_client_metadata"},
		{`{"redirect_uris":["http://127.0.0.1/cb"],"client_uri":"` + strings.Repeat("a", 6000) + `"}`, "invalid_client_metadata"},
	} {
		if r := e.registerClient(bad.body); r.Status != 400 || r.JSON["error"] != bad.code {
			t.Errorf("%.60s: %d %s", bad.body, r.Status, r.Body)
		}
	}

	// A registration: public, no secret, inert (no client row, no event).
	var events int
	e.DB.Get(&events, `SELECT count(*) FROM events`)
	reg := e.registerClient(body)
	if reg.Status != 201 || reg.JSON["client_secret"] != nil || reg.JSON["token_endpoint_auth_method"] != "none" || reg.JSON["client_name"] != "Tool" {
		t.Fatalf("register: %d %s", reg.Status, reg.Body)
	}
	clientID, _ := reg.JSON["client_id"].(string)
	if !strings.HasPrefix(clientID, "dcr_") || len(clientID) != 36 {
		t.Fatalf("client_id = %q", clientID)
	}
	var rows, after int
	e.DB.Get(&rows, `SELECT count(*) FROM oauth_clients WHERE external_id=$1`, clientID)
	e.DB.Get(&after, `SELECT count(*) FROM events`)
	if rows != 0 || after != events {
		t.Fatalf("registration wrote %d rows, %d events", rows, after-events)
	}

	redirect := "http://127.0.0.1:41234/callback"
	authorize := func(client string, extra url.Values) string {
		q := url.Values{"redirect_uri": {redirect}}
		for k, v := range extra {
			q[k] = v
		}
		return resourceAuthorize(client, q)
	}

	// The allowlist never names a registration, even with an entry that
	// matches everything: the client waits, and its page shows no host and
	// the name as unverified.
	e.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://claude.ai','/')`, e.EnvID)
	b := e.browser()
	start := b.get(authorize(clientID, nil))
	if start.Status != 303 {
		t.Fatalf("authorize: %d %s", start.Status, start.Body)
	}
	e.DB.Get(&rows, `SELECT count(*) FROM oauth_clients WHERE external_id=$1`, clientID)
	var used *string
	e.DB.Get(&used, `SELECT last_used_at::text FROM oauth_registrations WHERE client_id=$1`, clientID)
	if rows != 0 || used != nil {
		t.Fatalf("anonymous authorize wrote rows=%d used=%v", rows, used)
	}
	tk := b.get(start.Location).field("ticket")
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if done.Status != 403 || done.Location != "" || !strings.Contains(done.Body, "Tool") {
		t.Fatalf("pending: %d %q %s", done.Status, done.Location, done.Body)
	}
	var rowID, admission, source string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, clientID)
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, rowID)
	e.DB.Get(&source, `SELECT source FROM oauth_clients WHERE id=$1`, rowID)
	e.DB.Get(&used, `SELECT last_used_at::text FROM oauth_registrations WHERE client_id=$1`, clientID)
	if admission != "pending" || source != "dcr" || used == nil {
		t.Fatalf("row admission=%q source=%q used=%v", admission, source, used)
	}
	base := e.Base + "/protected-resources/" + protected
	view := e.Must("GET", base+"/clients/"+rowID, e.Owner, nil, 200).JSON
	if view["source"] != "dcr" || view["client_id"] != clientID || view["host"] != "" {
		t.Fatalf("view: %v", view)
	}

	// IT approves it: the full flow with client_id = dcr_… throughout.
	e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"metadata_hash": view["metadata_hash"]}, 200)
	b = e.browser()
	code := b.signInTo(b.get(authorize(clientID, nil)), redirect)
	form := codeForm(clientID, code)
	form.Set("redirect_uri", redirect)
	status, tokens, _ := e.tokenCall(form, "")
	if status != 200 || tokens["refresh_token"] == nil {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}
	if c := claims(t, tokens["access_token"].(string)); !equal(strs(c["aud"]), []string{mcpURI}) || c["oauth_client_id"] != rowID {
		t.Fatalf("claims: %v", c)
	}
	status, refreshed, _ := e.tokenCall(refreshForm(clientID, tokens["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	for _, grant := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:device_code"} {
		if status, out, _ := e.tokenCall(url.Values{"grant_type": {grant}, "client_id": {clientID}}, ""); status != 400 || out["error"] != "unauthorized_client" {
			t.Errorf("%s: %d %v", grant, status, out)
		}
	}
	// The row uuid is not a client_id (H-1).
	if status, _, _ := e.tokenCall(refreshForm(rowID, refreshed["refresh_token"].(string)), ""); status == 200 {
		t.Fatal("refreshed with the row uuid")
	}
	// Only the registered redirect URIs (any loopback port).
	if p := e.browser().get(authorize(clientID, url.Values{"redirect_uri": {"http://127.0.0.1:41234/other"}})); p.Status != 400 || p.Location != "" {
		t.Fatalf("unregistered redirect: %d %q", p.Status, p.Location)
	}

	// The server stops taking registrations: a page at authorize, the
	// grant fails at refresh.
	e.Must("PATCH", base, e.Owner, fiber.Map{"allow_dynamic_registration": false}, 200)
	if p := e.browser().get(authorize(clientID, nil)); p.Status != 403 || p.Location != "" || !strings.Contains(p.Body, "--client-id") {
		t.Fatalf("server off: %d %q %s", p.Status, p.Location, p.Body)
	}
	if status, out, _ := e.tokenCall(refreshForm(clientID, refreshed["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after the server stopped: %d %v", status, out)
	}
	var demoted string
	e.DB.Get(&demoted, `SELECT data->>'reason' FROM events WHERE type='oauth_client.demoted' AND subject_id=$1`, rowID)
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, rowID)
	if demoted != "dynamic_registration_disabled" || admission != "pending" {
		t.Fatalf("server off: reason=%q admission=%q", demoted, admission)
	}
	if offered() {
		t.Fatal("still offered with no server allowing it")
	}
	if r := e.registerClient(body); r.Status != 404 {
		t.Fatalf("register after: %d", r.Status)
	}

	// An open server admits a registration by policy at authorize; the
	// feature off takes the approval back (client_documents_reconcile) and
	// refuses with the same page.
	e.Must("PATCH", base, e.Owner, fiber.Map{"allow_dynamic_registration": true, "client_admission": "open"}, 200)
	cache.Flush()
	second := e.registerClient(body).JSON["client_id"].(string)
	b = e.browser()
	b.signInTo(b.get(authorize(second, nil)), redirect)
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE external_id=$1`, second)
	if admission != "approved" {
		t.Fatalf("open server: %q", admission)
	}
	e.Must("PUT", e.Base+"/features/dynamic_client_registration", e.Owner, fiber.Map{"enabled": false}, 200)
	if p := e.browser().get(authorize(second, nil)); p.Status != 403 || !strings.Contains(p.Body, "--client-id") {
		t.Fatalf("feature off: %d %s", p.Status, p.Body)
	}
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_documents_reconcile"); !found || err != nil {
		t.Fatal(found, err)
	}
	var reason string
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE external_id=$1`, second)
	e.DB.Get(&reason, `SELECT e.data->>'reason' FROM events e JOIN oauth_clients c ON c.id::text=e.subject_id WHERE e.type='oauth_client.demoted' AND c.external_id=$1`, second)
	if admission != "pending" || reason != "feature_disabled" {
		t.Fatalf("after reconcile: admission=%q reason=%q", admission, reason)
	}
	// One address registers a few clients a minute; the refusal is RFC
	// 7591 (asked while not offered, so nothing is stored).
	var limited Response
	for i := 0; i < 12; i++ {
		limited = e.registerFrom("10.200.0.1", body)
	}
	if limited.Status != 429 || limited.JSON["error"] != "temporarily_unavailable" {
		t.Fatalf("per-address limit: %d %s", limited.Status, limited.Body)
	}
	// Documents keep their own flag.
	if !strings.Contains(e.Must("GET", "/.well-known/oauth-authorization-server", "", nil, 200).Body, "client_id_metadata_document_supported\":true") {
		t.Fatal("documents affected by the registration flag")
	}
}

// TestDynamicRegistrationPrune: registrations nobody used go after a day;
// used ones stay while a client row holds them.
func TestDynamicRegistrationPrune(t *testing.T) {
	e := newDCREnv(t)
	_, protected, _ := e.mcpServer(fiber.Map{})
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"allow_dynamic_registration": true, "client_admission": "open"}, 200)
	e.Must("PUT", e.Base+"/features/dynamic_client_registration", e.Owner, fiber.Map{"enabled": true}, 200)
	body := `{"redirect_uris":["http://127.0.0.1/callback"]}`
	unused := e.registerClient(body).JSON["client_id"].(string)
	fresh := e.registerClient(body).JSON["client_id"].(string)
	held := e.registerClient(body).JSON["client_id"].(string)
	b := e.browser()
	b.signInTo(b.get(resourceAuthorize(held, url.Values{"redirect_uri": {"http://127.0.0.1:5000/callback"}})), "http://127.0.0.1:5000/callback")
	e.DB.MustExec(`UPDATE oauth_registrations SET created_at=now()-interval '2 days', last_used_at=CASE WHEN last_used_at IS NULL THEN NULL ELSE now()-interval '60 days' END WHERE client_id IN ($1,$2)`, unused, held)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_registration_prune"); !found || err != nil {
		t.Fatal(found, err)
	}
	var left []string
	e.DB.Select(&left, `SELECT client_id FROM oauth_registrations ORDER BY client_id`)
	if len(left) != 2 || !contains(left, fresh) || !contains(left, held) {
		t.Fatalf("left = %v", left)
	}
	// Once no row holds it, an idle registration goes too.
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, held)
	e.Must("DELETE", e.Base+"/protected-resources/"+protected+"/clients/"+row, e.Owner, nil, 204)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_registration_prune"); !found || err != nil {
		t.Fatal(found, err)
	}
	left = nil
	e.DB.Select(&left, `SELECT client_id FROM oauth_registrations`)
	if len(left) != 1 || left[0] != fresh {
		t.Fatalf("left = %v", left)
	}
}
