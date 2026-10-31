package e2e_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// consentFlow is one authorization of an MCP client at mcpURI, signed in as
// alice, stopped at the consent page (or past it when nothing is asked).
type consentFlow struct {
	b *browser
	// Done is the sign-in's answer: a redirect to the consent page or to
	// the client.
	Done page
}

// startConsent authorizes client (loopback redirect for external clients,
// the registered callback otherwise) with extra and signs alice in.
func (e *Env) startConsent(client, redirect string, extra url.Values) consentFlow {
	e.t.Helper()
	b := e.browser()
	q := url.Values{"redirect_uri": {redirect}}
	for k, v := range extra {
		q[k] = v
	}
	start := b.get(resourceAuthorize(client, q))
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		e.t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	tk := b.get(start.Location).field("ticket")
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	return consentFlow{b: b, Done: done}
}

// Asks reports whether the sign-in ended at the consent page.
func (f consentFlow) Asks() bool {
	return f.Done.Status == 303 && strings.Contains(f.Done.Location, "/hosted/consent?ticket=")
}

// Page opens the consent page.
func (f consentFlow) Page() page {
	f.b.t.Helper()
	if !f.Asks() {
		f.b.t.Fatalf("no consent page: %d %q %s", f.Done.Status, f.Done.Location, f.Done.Body)
	}
	return f.b.get(f.Done.Location[strings.Index(f.Done.Location, "/hosted/consent"):])
}

// Decide answers the consent page.
func (f consentFlow) Decide(allow bool) page {
	f.b.t.Helper()
	p := f.Page()
	decision := "deny"
	if allow {
		decision = "allow"
	}
	return f.b.post("/hosted/consent", url.Values{"ticket": {p.field("ticket")}, "decision": {decision}})
}

// code reads the authorization code of a redirect to the client.
func codeOf(t *testing.T, done page, redirect string) string {
	t.Helper()
	loc, err := url.Parse(done.Location)
	if done.Status != 303 || err != nil || !strings.HasPrefix(done.Location, redirect+"?") || loc.Query().Get("code") == "" || loc.Query().Get("iss") != testIssuer {
		t.Fatalf("redirect to the client: %d %q %s", done.Status, done.Location, done.Body)
	}
	return loc.Query().Get("code")
}

// redeem exchanges an external client's code (loopback redirect).
func (e *Env) redeem(client, code string) map[string]any {
	e.t.Helper()
	form := codeForm(client, code)
	form.Set("redirect_uri", loopback)
	status, out, _ := e.tokenCall(form, "")
	if status != 200 {
		e.t.Fatalf("code exchange: %d %v", status, out)
	}
	return out
}

// eventData returns the data of the newest event of type typ.
func (e *Env) eventData(typ string) map[string]any {
	e.t.Helper()
	var raw string
	if err := e.DB.Get(&raw, `SELECT data::text FROM events WHERE type=$1 AND environment_id=$2 ORDER BY id DESC LIMIT 1`, typ, e.EnvID); err != nil {
		e.t.Fatalf("no %s event: %v", typ, err)
	}
	out := map[string]any{}
	json.Unmarshal([]byte(raw), &out)
	return out
}

// approvedClaudeCode serves Claude Code's document and approves it at the
// server (open admission), returning its row id after a first sign-in.
func (e *Env) openServer(protected string) *metadataHost {
	e.t.Helper()
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	return host
}

// TestConsent is D29-D34 at work for an external client: the first
// authorization asks, the second does not, a step-up asks only for what is
// new (permissions the user does not hold apart), prompt=consent asks
// again, a denial is access_denied and ends the hosted session, revoking
// the consent cuts refresh and introspection, and every decision is an
// event without tokens.
func TestConsent(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})
	// A third permission alice does not hold.
	e.Must("PUT", e.Base+"/resources/"+resource, e.Owner, fiber.Map{"name": "MCP", "audience": mcpURI, "permissions": []string{"mcp:tools:read", "mcp:tools:write", "mcp:admin"}}, 204)
	e.openServer(protected)

	// First authorization: signed in, the consent page asks for the
	// default scopes, names the client by its host and the verified preset.
	first := e.startConsent(claudeCodeID, loopback, nil)
	if !first.Asks() {
		t.Fatalf("first authorization did not ask: %d %q", first.Done.Status, first.Done.Location)
	}
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	if n := e.count(`SELECT count(*) FROM oauth_consents WHERE client_id=$1`, row); n != 0 {
		t.Fatalf("%d consents before the decision", n)
	}
	p := first.Page()
	if p.Status != 200 || !strings.Contains(p.Body, "claude.ai") || !strings.Contains(p.Body, "Claude Code") || !strings.Contains(p.Body, "mcp:tools:read") || strings.Contains(p.Body, "mcp:tools:write") {
		t.Fatalf("consent page: %d %s", p.Status, p.Body)
	}
	// Another browser (no binding cookie) cannot decide.
	if other := e.browser().post("/hosted/consent", url.Values{"ticket": {p.field("ticket")}, "decision": {"allow"}}); other.Status == 303 {
		t.Fatalf("decided without the binding: %d %q", other.Status, other.Location)
	}
	tokens := e.redeem(claudeCodeID, codeOf(t, first.Decide(true), loopback))
	access := claims(t, tokens["access_token"].(string))
	if !jsonEqual(access["permissions"], []any{"mcp:tools:read"}) || access["resource"] != mcpURI {
		t.Fatalf("claims = %v", access)
	}
	granted := e.eventData("oauth_consent.granted")
	if granted["consent_ui"] != "hosted" || !jsonEqual(granted["granted_scopes"], []any{"mcp:tools:read"}) || granted["user_id"] != e.Alice || granted["resource"] != mcpURI {
		t.Fatalf("granted event = %v", granted)
	}
	if client := granted["client"].(map[string]any); client["client_id"] != claudeCodeID || client["host"] != "claude.ai" || client["id"] != row {
		t.Fatalf("granted event client = %v", client)
	}

	// Second authorization of the same scopes: no page.
	again := e.startConsent(claudeCodeID, loopback, nil)
	if again.Asks() {
		t.Fatal("asked again for what was agreed")
	}
	codeOf(t, again.Done, loopback)

	// Step-up: write is new, admin is not held: the page asks for both,
	// admin apart; agreeing adds them to the consent (union).
	step := e.startConsent(claudeCodeID, loopback, url.Values{"scope": {"mcp:tools:read mcp:tools:write mcp:admin"}})
	sp := step.Page()
	held, unheld := sp.Body, ""
	if i := strings.Index(sp.Body, `class="unheld"`); i >= 0 {
		held, unheld = sp.Body[:i], sp.Body[i:]
	}
	if !strings.Contains(held, "mcp:tools:write") || strings.Contains(held, "mcp:admin") || !strings.Contains(unheld, "mcp:admin") || !strings.Contains(sp.Body, `class="agreed"`) {
		t.Fatalf("step-up page: %s", sp.Body)
	}
	stepped := e.redeem(claudeCodeID, codeOf(t, step.Decide(true), loopback))
	if got := claims(t, stepped["access_token"].(string)); !jsonEqual(got["permissions"], []any{"mcp:tools:read", "mcp:tools:write"}) {
		t.Fatalf("step-up claims = %v", got["permissions"])
	}
	var scopes string
	e.DB.Get(&scopes, `SELECT array_to_string(scopes, ' ') FROM oauth_consents WHERE client_id=$1 AND revoked_at IS NULL`, row)
	if scopes != "mcp:admin mcp:tools:read mcp:tools:write" {
		t.Fatalf("consent scopes = %q", scopes)
	}
	// Once alice holds admin (changing her grants ends her sessions), the
	// next authorization grants it with no new page: it was agreed.
	e.Grant(e.Org, e.Alice, resource, "mcp:tools:read", "mcp:tools:write", "mcp:admin")
	held2 := e.startConsent(claudeCodeID, loopback, url.Values{"scope": {"mcp:tools:read mcp:tools:write mcp:admin"}})
	if held2.Asks() {
		t.Fatal("asked again for an agreed scope the user now holds")
	}
	refreshed := e.redeem(claudeCodeID, codeOf(t, held2.Done, loopback))
	if got := strs(claims(t, refreshed["access_token"].(string))["permissions"]); !slices.Contains(got, "mcp:admin") {
		t.Fatalf("permissions once held = %v", got)
	}

	// prompt=consent asks again for everything.
	forced := e.startConsent(claudeCodeID, loopback, url.Values{"prompt": {"consent"}})
	if !forced.Asks() {
		t.Fatal("prompt=consent did not ask")
	}
	// Denied: access_denied at the client, the ticket spent, the session
	// the hosted pages signed in ended, no consent change.
	fp := forced.Page()
	denied := forced.b.post("/hosted/consent", url.Values{"ticket": {fp.field("ticket")}, "decision": {"deny"}})
	loc, _ := url.Parse(denied.Location)
	if denied.Status != 303 || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" || loc.Query().Get("iss") != testIssuer {
		t.Fatalf("deny: %d %q", denied.Status, denied.Location)
	}
	if replay := forced.b.post("/hosted/consent", url.Values{"ticket": {fp.field("ticket")}, "decision": {"allow"}}); replay.Status == 303 {
		t.Fatalf("spent ticket decided again: %q", replay.Location)
	}
	if d := e.eventData("oauth_consent.denied"); d["consent_ui"] != "hosted" || d["client"].(map[string]any)["host"] != "claude.ai" {
		t.Fatalf("denied event = %v", d)
	}
	if d := e.eventData("session.revoked"); d["reason"] != "consent_denied" {
		t.Fatalf("denied session reason = %v", d)
	}
	e.DB.Get(&scopes, `SELECT array_to_string(scopes, ' ') FROM oauth_consents WHERE client_id=$1 AND revoked_at IS NULL`, row)
	if scopes != "mcp:admin mcp:tools:read mcp:tools:write" {
		t.Fatalf("consent after the denial = %q", scopes)
	}

	// Narrowing: a consent row cut to read (as a future partial revoke
	// would) narrows the next refresh, never widens it.
	e.DB.MustExec(`UPDATE oauth_consents SET scopes='{mcp:tools:read}' WHERE client_id=$1 AND revoked_at IS NULL`, row)
	status, narrowed, _ := e.tokenCall(refreshForm(claudeCodeID, refreshed["refresh_token"].(string)), "")
	if status != 200 || !jsonEqual(claims(t, narrowed["access_token"].(string))["permissions"], []any{"mcp:tools:read"}) {
		t.Fatalf("narrowed refresh: %d %v", status, narrowed)
	}

	// Connected apps: alice sees the client by host and verified preset.
	me := "?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
	alice := e.Login(e.AliceEmail)
	apps := e.Must("GET", "/identity/v1/me/connected-apps"+me, alice, nil, 200).JSON["items"].([]any)
	if len(apps) != 1 {
		t.Fatalf("connected apps = %v", apps)
	}
	app := apps[0].(map[string]any)
	client := app["client"].(map[string]any)
	if client["host"] != "claude.ai" || client["verified_name"] != "Claude Code" || app["resource"] != mcpURI || app["active_sessions"].(float64) < 1 || !jsonEqual(scopeNames(app["scopes"]), []any{"mcp:tools:read"}) {
		t.Fatalf("connected app = %v", app)
	}
	// The operator reads the same list.
	if ops := e.Must("GET", e.Base+"/users/"+e.Alice+"/connected-apps", e.Owner, nil, 200).JSON["items"].([]any); len(ops) != 1 {
		t.Fatalf("operator connected apps = %v", ops)
	}

	// Disconnect: the consent is revoked (kept as a record), every
	// session of the client for alice ends, refresh and introspection
	// stop.
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	rid, rsecret := registered["client_id"].(string), registered["client_secret"].(string)
	if got := e.introspectAs(rid, rsecret, narrowed["access_token"].(string)); got["active"] != true {
		t.Fatalf("introspect before disconnect: %v", got)
	}
	e.Must("DELETE", "/identity/v1/me/connected-apps/"+row+me, alice, nil, 204)
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, narrowed["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after disconnect: %d %v", status, out)
	}
	if got := e.introspectAs(rid, rsecret, narrowed["access_token"].(string)); got["active"] != false {
		t.Fatalf("introspect after disconnect: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, row); n != 0 {
		t.Fatalf("%d sessions outlived the disconnect", n)
	}
	if n := e.count(`SELECT count(*) FROM oauth_consents WHERE client_id=$1 AND revoked_reason='user'`, row); n != 1 {
		t.Fatalf("revoked consent records = %d", n)
	}
	revoked := e.eventData("oauth_consent.revoked")
	if revoked["reason"] != "user" || revoked["revoked_sessions"].(float64) < 1 {
		t.Fatalf("revoked event = %v", revoked)
	}
	if d := e.eventData("session.revoked"); d["reason"] != "consent_revoked" {
		t.Fatalf("disconnect session reason = %v", d)
	}
	e.Must("DELETE", "/identity/v1/me/connected-apps/"+row+me, alice, nil, 404)
	if apps := e.Must("GET", "/identity/v1/me/connected-apps"+me, alice, nil, 200).JSON["items"].([]any); len(apps) != 0 {
		t.Fatalf("connected apps after disconnect = %v", apps)
	}
	// The next authorization asks again.
	if !e.startConsent(claudeCodeID, loopback, nil).Asks() {
		t.Fatal("no page after disconnect")
	}

	// No consent event carries a token.
	var leaked int
	e.DB.Get(&leaked, `SELECT count(*) FROM events WHERE type LIKE 'oauth_consent.%' AND (data::text LIKE '%ory_%' OR data::text LIKE '%eyJ%' OR data::text LIKE '%ik_authorize_%')`)
	if leaked != 0 {
		t.Fatalf("%d consent events carry tokens", leaked)
	}
}

// TestConsentPolicy: operator-registered clients skip consent unless
// configured (D29); a client made from a preset and an external one
// always require it, in the API and in the database.
func TestConsentPolicy(t *testing.T) {
	e := newEnv(t)
	client, protected, resource := e.mcpServer(fiber.Map{})
	b := e.browser()
	// First-party: no page.
	code := b.signIn(b.get(resourceAuthorize(client, nil)))
	if status, _, _ := e.tokenCall(codeForm(client, code), ""); status != 200 {
		t.Fatalf("first-party code: %d", status)
	}
	view := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON
	if view["consent_policy"] != "skip" {
		t.Fatalf("default consent_policy = %v", view["consent_policy"])
	}
	// Required: the registered client asks too.
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"consent_policy": "required"}, 204)
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"consent_policy": "maybe"}, 400)
	asked := e.startConsent(client, "https://app.example/callback", nil)
	if !asked.Asks() {
		t.Fatalf("required registered client did not ask: %q", asked.Done.Location)
	}
	codeOf(t, asked.Decide(true), "https://app.example/callback")

	// A preset template is third-party: required, never skip.
	tpl := e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "gemini_cli"}, 201).JSON["client"].(map[string]any)
	tplID := tpl["client_id"].(string)
	if got := e.Must("GET", e.Base+"/oauth-clients/"+tplID, e.Owner, nil, 200).JSON["consent_policy"]; got != "required" {
		t.Fatalf("template consent_policy = %v", got)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+tplID, e.Owner, fiber.Map{"consent_policy": "skip"}, 400)
	if _, err := e.DB.Exec(`UPDATE oauth_clients SET consent_policy='skip' WHERE id=$1`, tplID); err == nil || !strings.Contains(err.Error(), "oauth_clients_third_party_consent_check") {
		t.Fatalf("database let a template skip consent: %v", err)
	}
	_ = resource
}

// TestConsentCustomUI is D30: an environment with consent_ui custom lets
// its own sign-in UI read what to ask (GET /identity/v1/authorize/:ticket)
// and post the decision under the binding cookie; without the cookie it
// cannot, and an environment on the hosted page refuses the custom
// decision and sends the UI to the hosted page.
func TestConsentCustomUI(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})
	const origin = "https://login.example.com"
	// A first-party UI client that requires consent and signs in with its
	// own UI (no hosted login).
	ui := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{origin}, "consent_policy": "required"}, 201).JSON["client_id"].(string)

	start := func() (*browser, string) {
		b := e.browser()
		p := b.get(resourceAuthorize(ui, nil))
		var begin map[string]any
		json.Unmarshal([]byte(p.Body), &begin)
		ticket, _ := begin["authorization_ticket"].(string)
		if p.Status != 200 || ticket == "" {
			t.Fatalf("authorize: %d %s", p.Status, p.Body)
		}
		return b, ticket
	}
	complete := func(b *browser, ticket string) map[string]any {
		login := e.LoginBody(e.AliceEmail, e.Pass)
		login["resource_id"] = resource
		token := e.Must("POST", "/identity/v1/login", "", login, 200).JSON["access_token"].(string)
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": ticket, "approve": true})
		req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", origin)
		for _, c := range b.cookies {
			req.AddCookie(c)
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out := map[string]any{}
		json.NewDecoder(res.Body).Decode(&out)
		if res.StatusCode != 200 {
			t.Fatalf("complete: %d %v", res.StatusCode, out)
		}
		return out
	}
	decide := func(b *browser, ticket string, approve bool, cookies bool) Response {
		raw, _ := json.Marshal(fiber.Map{"approve": approve})
		req := httptest.NewRequest("POST", "/identity/v1/authorize/"+url.PathEscape(ticket)+"/consent", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		if cookies {
			for _, c := range b.cookies {
				req.AddCookie(c)
			}
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out := Response{Status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(&out.JSON)
		return out
	}

	// Hosted (the default): complete answers consent_required with the
	// hosted page; the custom decision is refused.
	b, ticket := start()
	done := complete(b, ticket)
	if done["consent_required"] != true || !strings.Contains(done["redirect_to"].(string), "/hosted/consent?ticket=") {
		t.Fatalf("hosted consent: %v", done)
	}
	info := b.get("/identity/v1/authorize/" + url.PathEscape(ticket))
	var described map[string]any
	json.Unmarshal([]byte(info.Body), &described)
	consent, _ := described["consent"].(map[string]any)
	if info.Status != 200 || described["consent_required"] != true || consent["ui"] != "hosted" || !jsonEqual(scopeNames(consent["scopes"]), []any{"mcp:tools:read"}) {
		t.Fatalf("ticket waiting for hosted consent: %d %s", info.Status, info.Body)
	}
	if r := decide(b, ticket, true, true); r.Status != 403 || r.JSON["error"].(map[string]any)["code"] != "CONSENT_UI_HOSTED" {
		t.Fatalf("custom decision with consent_ui hosted: %d %v", r.Status, r.JSON)
	}

	// Custom: the UI decides, with the binding cookie only.
	e.Must("PUT", e.Base+"/protected-resource-policy", e.Owner, fiber.Map{"max_idle_ttl_seconds": 2592000, "max_lifetime_ttl_seconds": 7776000, "consent_ui": "custom"}, 200)
	b, ticket = start()
	complete(b, ticket)
	if r := decide(b, ticket, true, false); r.Status != 401 {
		t.Fatalf("decision without the binding: %d %v", r.Status, r.JSON)
	}
	r := decide(b, ticket, true, true)
	redirect, _ := r.JSON["redirect_to"].(string)
	if r.Status != 200 || !strings.HasPrefix(redirect, "https://app.example/callback?") || !strings.Contains(redirect, "code=") {
		t.Fatalf("custom approve: %d %v", r.Status, r.JSON)
	}
	if d := e.eventData("oauth_consent.granted"); d["consent_ui"] != "custom" {
		t.Fatalf("custom granted event = %v", d)
	}
	if r := decide(b, ticket, true, true); r.Status == 200 {
		t.Fatalf("spent ticket decided again: %v", r.JSON)
	}

	// Rejection from a custom UI: access_denied, and the UI's own session
	// is left alone (it is the application's).
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"default_scopes": []string{"mcp:tools:read", "mcp:tools:write"}}, 200)
	b, ticket = start()
	complete(b, ticket)
	live := e.count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, e.Alice)
	r = decide(b, ticket, false, true)
	redirect, _ = r.JSON["redirect_to"].(string)
	if r.Status != 200 || !strings.Contains(redirect, "error=access_denied") {
		t.Fatalf("custom deny: %d %v", r.Status, r.JSON)
	}
	if after := e.count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, e.Alice); after != live {
		t.Fatalf("custom denial ended sessions: %d → %d", live, after)
	}
}

// TestAdminGrants is D31: at an admin_granted server an administrator's
// grant covers users without a page; a step-up beyond it asks for the
// extra scopes only; revoking or expiring it ends the sessions it covered.
func TestAdminGrants(t *testing.T) {
	e := newEnv(t)
	_, protected, _ := e.mcpServer(fiber.Map{})
	e.openServer(protected)
	// The client exists once a user signed in for it.
	if !e.startConsent(claudeCodeID, loopback, nil).Asks() {
		t.Fatal("per_user server did not ask")
	}
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	grants := e.Base + "/protected-resources/" + protected + "/clients/" + row + "/grants"

	// per_user refuses grants; scopes must be the server's permissions.
	e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"mcp:tools:read"}}, 409)
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"consent_mode": "admin_granted"}, 200)
	e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"billing:read"}}, 400)
	e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"mcp:tools:read"}, "expires_at": time.Now().Add(-time.Hour)}, 400)
	grant := e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"mcp:tools:read"}, "organization_id": e.Org}, 200).JSON
	if grant["organization_id"] != e.Org || !jsonEqual(grant["scopes"], []any{"mcp:tools:read"}) {
		t.Fatalf("grant = %v", grant)
	}
	if g := e.eventData("oauth_client.granted"); !jsonEqual(g["scopes"], []any{"mcp:tools:read"}) {
		t.Fatalf("granted event = %v", g)
	}

	// Covered: no page.
	flow := e.startConsent(claudeCodeID, loopback, nil)
	if flow.Asks() {
		t.Fatal("asked for what the administrator granted")
	}
	tokens := e.redeem(claudeCodeID, codeOf(t, flow.Done, loopback))
	// Step-up beyond the grant: the page asks for write only.
	step := e.startConsent(claudeCodeID, loopback, url.Values{"scope": {"mcp:tools:read mcp:tools:write"}})
	sp := step.Page()
	if !strings.Contains(sp.Body, "mcp:tools:write") || strings.Contains(sp.Body[:strings.Index(sp.Body, "mcp:tools:write")], "<li>mcp:tools:read") {
		t.Fatalf("step-up beyond the grant: %s", sp.Body)
	}
	stepped := e.redeem(claudeCodeID, codeOf(t, step.Decide(true), loopback))
	var consented string
	e.DB.Get(&consented, `SELECT array_to_string(scopes,' ') FROM oauth_consents WHERE client_id=$1 AND revoked_at IS NULL`, row)
	if consented != "mcp:tools:write" {
		t.Fatalf("user consent beside the grant = %q", consented)
	}

	// Revoking the grant ends the sessions it covered (in its
	// organization): both grants' refresh tokens stop.
	e.Must("DELETE", grants+"/"+grant["id"].(string), e.Owner, nil, 204)
	for name, tok := range map[string]any{"granted": tokens["refresh_token"], "stepped": stepped["refresh_token"]} {
		if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tok.(string)), ""); status != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("%s refresh after the grant was revoked: %d %v", name, status, out)
		}
	}
	if d := e.eventData("oauth_client.grant_revoked"); d["reason"] != "operator" || d["revoked_sessions"].(float64) < 1 {
		t.Fatalf("grant_revoked event = %v", d)
	}
	if d := e.eventData("session.revoked"); d["reason"] != "client_grant_revoked" {
		t.Fatalf("grant session reason = %v", d)
	}
	e.Must("DELETE", grants+"/"+grant["id"].(string), e.Owner, nil, 404)
	if list := e.Must("GET", grants+"?revoked=true", e.Owner, nil, 200).JSON["items"].([]any); len(list) != 1 || list[0].(map[string]any)["revoked_reason"] != "operator" {
		t.Fatalf("grants with revoked = %v", list)
	}

	// Expiry: the job revokes it with an event and ends its sessions.
	e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"mcp:tools:read"}, "expires_at": time.Now().Add(time.Hour)}, 200)
	expiring := e.startConsent(claudeCodeID, loopback, nil)
	if expiring.Asks() {
		t.Fatal("asked under an environment-wide grant")
	}
	tokens = e.redeem(claudeCodeID, codeOf(t, expiring.Done, loopback))
	e.DB.MustExec(`UPDATE oauth_client_grants SET expires_at=now()-interval '1 second' WHERE client_id=$1 AND revoked_at IS NULL`, row)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_grant_expire"); !found || err != nil {
		t.Fatalf("client_grant_expire: %v %v", found, err)
	}
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after expiry: %d %v", status, out)
	}
	if d := e.eventData("oauth_client.grant_revoked"); d["reason"] != "expired" {
		t.Fatalf("expiry event = %v", d)
	}

	// Back to per_user: the live grants end at once with their sessions,
	// and never return with the mode.
	e.Must("PUT", grants, e.Owner, fiber.Map{"scopes": []string{"mcp:tools:read"}}, 200)
	again := e.startConsent(claudeCodeID, loopback, nil)
	if again.Asks() {
		t.Fatal("asked under a new grant")
	}
	tokens = e.redeem(claudeCodeID, codeOf(t, again.Done, loopback))
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"consent_mode": "per_user"}, 200)
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after leaving admin_granted: %d %v", status, out)
	}
	if d := e.eventData("oauth_client.grant_revoked"); d["reason"] != "consent_mode_changed" || d["revoked_sessions"].(float64) < 1 {
		t.Fatalf("mode change event = %v", d)
	}
	if n := e.count(`SELECT count(*) FROM oauth_client_grants WHERE client_id=$1 AND revoked_at IS NULL`, row); n != 0 {
		t.Fatalf("%d grants live after leaving admin_granted", n)
	}
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"consent_mode": "admin_granted"}, 200)
	if !e.startConsent(claudeCodeID, loopback, nil).Asks() {
		t.Fatal("a revoked grant came back with the mode")
	}

	// The prune job deletes revoked records past the security retention.
	e.DB.MustExec(`UPDATE oauth_client_grants SET revoked_at=now()-interval '400 days' WHERE client_id=$1`, row)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "oauth_consent_prune"); !found || err != nil {
		t.Fatalf("oauth_consent_prune: %v %v", found, err)
	}
	if n := e.count(`SELECT count(*) FROM oauth_client_grants WHERE client_id=$1`, row); n != 0 {
		t.Fatalf("%d old grants survived the prune", n)
	}
}

// TestConsentBlockAndRevocation: blocking a client revokes its consents
// (client_blocked); RFC 7009 revocation of a resource grant's refresh
// token ends its session and its exchanged children (D34), while an
// OpenID Connect grant without resource only loses the token.
func TestConsentBlockAndRevocation(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})
	e.openServer(protected)
	flow := e.startConsent(claudeCodeID, loopback, nil)
	tokens := e.redeem(claudeCodeID, codeOf(t, flow.Decide(true), loopback))
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)

	// RFC 7009: revoking the refresh token disconnects the grant.
	sid := claims(t, tokens["access_token"].(string))["sid"]
	if got := httpForm(t, e, "/oauth/revoke", url.Values{"client_id": {claudeCodeID}, "token": {tokens["refresh_token"].(string)}}); got != 200 {
		t.Fatalf("revoke: %d", got)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NULL`, sid); n != 0 {
		t.Fatal("the resource grant's session outlived RFC 7009 revocation")
	}
	if d := e.eventData("session.revoked"); d["reason"] != "token_revoked" {
		t.Fatalf("revocation session reason = %v", d)
	}
	// The consent stays: revoking a token is not withdrawing consent.
	if e.startConsent(claudeCodeID, loopback, nil).Asks() {
		t.Fatal("token revocation withdrew the consent")
	}

	// Block: consents revoked as client_blocked, kept as records.
	e.approveClient(e.Base+"/protected-resources/"+protected, row)
	e.Must("POST", e.Base+"/protected-resources/"+protected+"/clients/"+row+"/block", e.Owner, nil, 200)
	if n := e.count(`SELECT count(*) FROM oauth_consents WHERE client_id=$1 AND revoked_reason='client_blocked'`, row); n != 1 {
		t.Fatalf("blocked consents = %d", n)
	}
	if d := e.eventData("oauth_consent.revoked"); d["reason"] != "client_blocked" {
		t.Fatalf("block event = %v", d)
	}

	// An OpenID Connect grant without resource (a hosted registered
	// client): revoking its refresh token leaves the session.
	oidc := e.hostedClient()
	b := e.browser()
	tk := b.authorize(oidc).field("ticket")
	oidcTokens := b.exchange(oidc, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	oidcSID := claims(t, oidcTokens["access_token"].(string))["sid"]
	if got := httpForm(t, e, "/oauth/revoke", url.Values{"client_id": {oidc}, "token": {oidcTokens["refresh_token"].(string)}}); got != 200 {
		t.Fatalf("OIDC revoke: %d", got)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NULL`, oidcSID); n != 1 {
		t.Fatal("OIDC revocation ended the session")
	}
	_ = resource
}

// TestConsentAccessTokenTTL is D36: the server's access_token_ttl_seconds
// sets expires_in and exp of resource-flow access tokens, at issue and
// refresh, and stays within 60..3600 and the idle TTL.
func TestConsentAccessTokenTTL(t *testing.T) {
	e := newEnv(t)
	client, protected, _ := e.mcpServer(fiber.Map{})
	path := e.Base + "/protected-resources/" + protected
	if got := e.Must("GET", path, e.Owner, nil, 200).JSON["access_token_ttl_seconds"]; got != float64(900) {
		t.Fatalf("default access_token_ttl_seconds = %v", got)
	}
	e.Must("PATCH", path, e.Owner, fiber.Map{"access_token_ttl_seconds": 30}, 400)
	e.Must("PATCH", path, e.Owner, fiber.Map{"access_token_ttl_seconds": 7200}, 400)
	e.Must("PATCH", path, e.Owner, fiber.Map{"access_token_ttl_seconds": 300}, 200)
	b := e.browser()
	status, tokens, _ := e.tokenCall(codeForm(client, b.signIn(b.get(resourceAuthorize(client, nil)))), "")
	check := func(name string, tokens map[string]any) {
		c := claims(t, tokens["access_token"].(string))
		ttl := c["exp"].(float64) - c["iat"].(float64)
		if in := tokens["expires_in"].(float64); in < 290 || in > 300 || ttl != 300 {
			t.Fatalf("%s: expires_in %v, exp-iat %v", name, in, ttl)
		}
	}
	if status != 200 {
		t.Fatalf("code: %d %v", status, tokens)
	}
	check("issue", tokens)
	status, refreshed, _ := e.tokenCall(refreshForm(client, tokens["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	check("refresh", refreshed)
}

// TestReplicasDisconnectAtOnce: a disconnect through replica A stops the
// refresh and introspection of tokens replica B issued at once (shared
// Redis caches, D32).
func TestReplicasDisconnectAtOnce(t *testing.T) {
	p := newPair(t, 0)
	A, B := p.A, p.B
	_, protected, _ := A.mcpServer(fiber.Map{})
	A.Must("PATCH", A.Base+"/protected-resources/"+protected, A.Owner, fiber.Map{"client_admission": "open"}, 200)
	p.Host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	registered := A.Must("POST", A.Base+"/oauth-clients", A.Owner, fiber.Map{"application_id": A.Client, "resource_id": A.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	rid, rsecret := registered["client_id"].(string), registered["client_secret"].(string)

	flow := B.startConsent(claudeCodeID, loopback, nil)
	tokens := B.redeem(claudeCodeID, codeOf(t, flow.Decide(true), loopback))
	// Warm B.
	if got := B.introspectAs(rid, rsecret, tokens["access_token"].(string)); got["active"] != true {
		t.Fatalf("B introspection before: %v", got)
	}
	status, refreshed, _ := B.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("B refresh before: %d %v", status, refreshed)
	}
	var row string
	A.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	A.Must("DELETE", A.Base+"/users/"+A.Alice+"/connected-apps/"+row, A.Owner, nil, 204)
	if d := A.eventData("oauth_consent.revoked"); d["reason"] != "operator" {
		t.Fatalf("operator disconnect event = %v", d)
	}
	if status, out, _ := B.tokenCall(refreshForm(claudeCodeID, refreshed["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("B refresh after A disconnected: %d %v", status, out)
	}
	if got := B.introspectAs(rid, rsecret, refreshed["access_token"].(string)); got["active"] != false {
		t.Fatalf("B introspection after A disconnected: %v", got)
	}
}

// TestConsentTexts is D41: the consent page reads the environment's and
// the client's custom texts (client over environment), the refusal page of
// an external client the environment's; the defaults name no one but "an
// administrator".
func TestConsentTexts(t *testing.T) {
	e := newEnv(t)
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	settings := e.Base + "/login-settings"

	// Pending (registered-only by default): the neutral default, then the
	// environment's own wording.
	if p := e.loginAndAsk(claudeCodeID); p.Status != 403 || !strings.Contains(p.Body, "an administrator") {
		t.Fatalf("pending page: %d %s", p.Status, p.Body)
	}
	e.Must("PUT", settings+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.client.pending": "The platform team reviews new applications."}}, 200)
	if p := e.loginAndAsk(claudeCodeID); !strings.Contains(p.Body, "The platform team reviews new applications.") {
		t.Fatalf("custom pending text: %s", p.Body)
	}

	// Consent: environment text, then the client's over it.
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	e.Must("PUT", settings+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.consent.title": "Connect this assistant?"}}, 200)
	if p := e.startConsent(claudeCodeID, loopback, nil).Page(); !strings.Contains(p.Body, "Connect this assistant?") {
		t.Fatalf("environment consent title: %s", p.Body)
	}
	var row string
	e.DB.Get(&row, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	e.Must("PUT", settings+"/clients/"+row+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.consent.title": "Connect Claude Code?"}}, 200)
	p := e.startConsent(claudeCodeID, loopback, nil).Page()
	if !strings.Contains(p.Body, "Connect Claude Code?") || strings.Contains(p.Body, "Connect this assistant?") {
		t.Fatalf("client consent title: %s", p.Body)
	}
	// Spanish keeps the catalog's neutral text.
	es := e.startConsent(claudeCodeID, loopback, url.Values{"ui_locales": {"es"}}).Page()
	if !strings.Contains(es.Body, `lang="es"`) || !strings.Contains(es.Body, "¿Permitir el acceso?") {
		t.Fatalf("spanish consent page: %s", es.Body)
	}
}
