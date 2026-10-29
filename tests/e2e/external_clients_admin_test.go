package e2e_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	loopback   = "http://localhost:53682/callback"
	unknownApp = "https://apps.example/client/one"
)

// authorizeExternal runs the whole authorization of an admitted external
// client (alice, loopback redirect) and returns the token response.
func (e *Env) authorizeExternal(clientID string, scope ...string) (int, map[string]any) {
	e.t.Helper()
	b := e.browser()
	q := url.Values{"redirect_uri": {loopback}}
	if len(scope) > 0 {
		q.Set("scope", scope[0])
		q.Set("nonce", "unpredictable-nonce-123456")
	}
	start := b.get(resourceAuthorize(clientID, q))
	code := b.signInTo(start, loopback)
	form := codeForm(clientID, code)
	form.Set("redirect_uri", loopback)
	status, out, _ := e.tokenCall(form, "")
	return status, out
}

// introspectAs asks /oauth/introspect, as the registered confidential
// client id, about token.
func (e *Env) introspectAs(id, secret, token string) map[string]any {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, url.QueryEscape(secret))
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

// approveClient approves the client as the operator reviewing its page
// does: with the metadata_hash the list shows.
func (e *Env) approveClient(base, row string) {
	e.t.Helper()
	hash := e.Must("GET", base+"/clients/"+row, e.Owner, nil, 200).JSON["metadata_hash"]
	e.Must("POST", base+"/clients/"+row+"/approve", e.Owner, fiber.Map{"metadata_hash": hash}, 200)
}

// TestAdmissionManagement is IT at work: a client waits (its page names the
// host, never trusts the document's name), is approved with an expiry that
// ends its access, is blocked (refresh, introspection and opaque tokens all
// refused), unblocked and forgotten.
func TestAdmissionManagement(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	host.Put(unknownApp, map[string]any{"client_id": unknownApp, "client_name": "Totally Trusted Bank", "logo_uri": "https://cdn.evil.example/logo.png", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	base := e.Base + "/protected-resources/" + protected

	// M5: the page of a client waiting for IT. A preset-verified client
	// shows the preset's name with a check; any other shows its host
	// first and its own name marked unverified. The logo comes from
	// another host, so it is not shown.
	page := e.loginAndAsk(unknownApp)
	if page.Status != 403 || page.Location != "" || !strings.Contains(page.Body, "apps.example") || !strings.Contains(page.Body, "Totally Trusted Bank") || !strings.Contains(page.Body, "unverified") || !strings.Contains(page.Body, "sent to IT") || strings.Contains(page.Body, "cdn.evil.example") {
		t.Fatalf("pending page: %d %q %s", page.Status, page.Location, page.Body)
	}
	if p := e.loginAndAsk(claudeCodeID); p.Status != 403 || !strings.Contains(p.Body, "claude.ai") || !strings.Contains(p.Body, "Claude Code") || strings.Contains(p.Body, "unverified") {
		t.Fatalf("verified page: %d %s", p.Status, p.Body)
	}

	// The list, one client and who asked.
	list := e.Must("GET", base+"/clients?admission=pending", e.Owner, nil, 200).JSON["items"].([]any)
	if len(list) != 2 {
		t.Fatalf("pending clients = %d", len(list))
	}
	e.Must("GET", base+"/clients?admission=bogus", e.Owner, nil, 400)
	var rowID string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	one := e.Must("GET", base+"/clients/"+rowID, e.Owner, nil, 200).JSON
	if one["client_id"] != claudeCodeID || one["host"] != "claude.ai" || one["preset"] != "claude_code" || one["admission"] != "pending" {
		t.Fatalf("client = %v", one)
	}
	if reqs := e.Must("GET", base+"/clients/"+rowID+"/requests", e.Owner, nil, 200).JSON["items"].([]any); len(reqs) != 1 {
		t.Fatalf("access requests = %v", reqs)
	}
	// Another server's id is a 404.
	e.Must("GET", e.Base+"/protected-resources/00000000-0000-4000-8000-000000000000/clients/"+rowID, e.Owner, nil, 404)

	// The registered-client routes never write a client named by a document:
	// its redirects and state come from the document and the admission API.
	var stored string
	e.DB.Get(&stored, `SELECT array_to_string(redirect_uris, ',') FROM oauth_clients WHERE id=$1`, rowID)
	e.Must("PATCH", e.Base+"/oauth-clients/"+rowID, e.Owner, fiber.Map{"redirect_uris": []string{"https://evil.example/callback"}}, 404)
	e.Must("DELETE", e.Base+"/oauth-clients/"+rowID, e.Owner, nil, 404)
	var after string
	var active bool
	e.DB.QueryRow(`SELECT array_to_string(redirect_uris, ','), active FROM oauth_clients WHERE id=$1`, rowID).Scan(&after, &active)
	if after != stored || !active {
		t.Fatalf("a registered-client route changed an external client: %q -> %q (active %v)", stored, after, active)
	}

	// An expiry in the past is refused; a future one approves by hand.
	e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "metadata_hash": one["metadata_hash"]}, 400)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	// M-1: the approval names the document the operator reviewed; none, or
	// another, is refused and nothing is approved.
	e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"expires_at": expires}, 400)
	if c := e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"expires_at": expires, "metadata_hash": "stale"}, 409).JSON; c["error"].(map[string]any)["code"] != "CLIENT_METADATA_CHANGED" {
		t.Fatalf("stale hash: %v", c)
	}
	if got := e.Must("GET", base+"/clients/"+rowID, e.Owner, nil, 200).JSON["admission"]; got != "pending" {
		t.Fatalf("a refused approval approved the client: %v", got)
	}
	// The reviewed hash is that of the document as it was; the document
	// changing underneath (a refresh) makes the same click a conflict.
	var original string
	e.DB.Get(&original, `SELECT array_to_string(redirect_uris, ',') FROM oauth_clients WHERE id=$1`, rowID)
	e.DB.MustExec(`UPDATE oauth_clients SET redirect_uris=ARRAY['http://localhost/evil'] WHERE id=$1`, rowID)
	e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"expires_at": expires, "metadata_hash": one["metadata_hash"]}, 409)
	if changed := e.Must("GET", base+"/clients/"+rowID, e.Owner, nil, 200).JSON["metadata_hash"]; changed == one["metadata_hash"] {
		t.Fatalf("the hash did not follow the document: %v", changed)
	}
	e.DB.MustExec(`UPDATE oauth_clients SET redirect_uris=string_to_array($2, ',') WHERE id=$1`, rowID, original)
	approved := e.Must("POST", base+"/clients/"+rowID+"/approve", e.Owner, fiber.Map{"expires_at": expires, "metadata_hash": one["metadata_hash"]}, 200).JSON
	if approved["admission"] != "approved" || approved["admission_source"] != "manual" || approved["admission_expires_at"] == nil {
		t.Fatalf("approved = %v", approved)
	}
	var hash string
	e.DB.Get(&hash, `SELECT approved_metadata_hash FROM oauth_clients WHERE id=$1`, rowID)
	if hash == "" {
		t.Fatal("approval is not bound to the document")
	}
	status, tokens := e.authorizeExternal(claudeCodeID)
	if status != 200 || tokens["refresh_token"] == nil {
		t.Fatalf("approved client: %d %v", status, tokens)
	}

	// The approval ends: at use the refresh is refused; the job then
	// revokes the sessions and the client waits for IT again.
	e.DB.MustExec(`UPDATE oauth_clients SET admission_expires_at=now()-interval '1 minute' WHERE id=$1`, rowID)
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after expiry: %d %v", status, out)
	}
	if p := e.loginAndAsk(claudeCodeID); p.Status != 403 {
		t.Fatalf("expired client authorizes: %d", p.Status)
	}
	if found, err := e.Server.Workers.RunOnce(context.Background(), "client_admission_expire"); !found || err != nil {
		t.Fatalf("expire job: %v %v", found, err)
	}
	var admission string
	e.DB.Get(&admission, `SELECT admission FROM oauth_clients WHERE id=$1`, rowID)
	if admission != "pending" || e.count(`SELECT count(*) FROM events WHERE type='oauth_client.expired' AND subject_id=$1`, rowID) != 1 {
		t.Fatalf("after the job: admission %q", admission)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, rowID); n != 0 {
		t.Fatalf("%d sessions outlived the approval", n)
	}

	// Approve again; block it with live tokens: the JWT's refresh,
	// introspection and the opaque token all stop.
	e.approveClient(base, rowID)
	e.DB.MustExec(`UPDATE oauth_clients SET access_token_format='opaque' WHERE id=$1`, rowID)
	status, tokens = e.authorizeExternal(claudeCodeID, "openid mcp:tools:read")
	if status != 200 || !strings.HasPrefix(tokens["access_token"].(string), "ory_at_") {
		t.Fatalf("opaque client: %d %v", status, tokens)
	}
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	access := tokens["access_token"].(string)
	if got := e.introspectAs(registered["client_id"].(string), registered["client_secret"].(string), access); got["active"] != true {
		t.Fatalf("introspect before block: %v", got)
	}
	if res := e.Do("GET", "/oauth/userinfo", access, nil); res.Status != 200 {
		t.Fatalf("userinfo before block: %d %s", res.Status, res.Body)
	}
	// The impact counts what the block ends: the live sessions, their people.
	live := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL AND expires_at>now()`, rowID)
	if impact := e.Must("GET", base+"/clients/"+rowID+"/impact", e.Owner, nil, 200).JSON; live < 1 || impact["active_sessions"] != float64(live) || impact["users"] != float64(1) {
		t.Fatalf("client impact = %v, live sessions %d", impact, live)
	}
	e.Must("GET", base+"/clients/"+uuid.NewString()+"/impact", e.Owner, nil, 404)
	e.Must("POST", base+"/clients/"+rowID+"/block", e.Owner, nil, 200)
	if impact := e.Must("GET", base+"/clients/"+rowID+"/impact", e.Owner, nil, 200).JSON; impact["active_sessions"] != float64(0) || impact["users"] != float64(0) {
		t.Fatalf("client impact after block = %v", impact)
	}
	if status, out, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after block: %d %v", status, out)
	}
	if got := e.introspectAs(registered["client_id"].(string), registered["client_secret"].(string), access); got["active"] != false {
		t.Fatalf("introspect after block: %v", got)
	}
	if res := e.Do("GET", "/oauth/userinfo", access, nil); res.Status != 401 {
		t.Fatalf("opaque token after block: %d %s", res.Status, res.Body)
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, rowID); n != 0 {
		t.Fatalf("%d sessions outlived the block", n)
	}
	if p := e.browser().get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {loopback}})); p.Status != 403 || p.Location != "" || !strings.Contains(p.Body, "claude.ai") || !strings.Contains(p.Body, "blocked") {
		t.Fatalf("blocked page: %d %s", p.Status, p.Body)
	}
	// The operator is the actor of the decisions.
	var actor string
	e.DB.Get(&actor, `SELECT actor_kind FROM events WHERE type='oauth_client.blocked' AND subject_id=$1`, rowID)
	if actor != "operator" {
		t.Fatalf("blocked actor kind = %q", actor)
	}

	// Unblock returns it to pending; forgetting deletes it.
	if got := e.Must("POST", base+"/clients/"+rowID+"/unblock", e.Owner, nil, 200).JSON; got["admission"] != "pending" {
		t.Fatalf("unblocked = %v", got)
	}
	e.Must("DELETE", base+"/clients/"+rowID, e.Owner, nil, 204)
	e.Must("GET", base+"/clients/"+rowID, e.Owner, nil, 404)
	if e.count(`SELECT count(*) FROM events WHERE type='oauth_client.forgotten' AND subject_id=$1`, rowID) != 1 {
		t.Fatal("no oauth_client.forgotten event")
	}

	// An open server admits what it discovers; a registered-only server
	// shows its own page.
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	fresh := "https://apps.example/client/fresh"
	host.Put(fresh, map[string]any{"client_id": fresh, "client_name": "Fresh", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	if status, out := e.authorizeExternal(fresh); status != 200 {
		t.Fatalf("open server: %d %v", status, out)
	}
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "bogus"}, 400)
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"allow_client_metadata": false}, 200)
	if p := e.browser().get(resourceAuthorize(chatGPTID, url.Values{"redirect_uri": {loopback}})); p.Status != 403 || p.Location != "" || !strings.Contains(p.Body, "chatgpt.com") || !strings.Contains(p.Body, "registered applications only") {
		t.Fatalf("registered only: %d %s", p.Status, p.Body)
	}
}

// TestAdmissionAllowlistAndPresets: an allowlist entry approves what waits
// and what is discovered next; CIMD presets add entries in one click, with
// the exposure warning of a public client; template presets create
// registered clients that authorize on a loopback port of their choosing;
// MCP Inspector exists only where development_clients is on.
func TestAdmissionAllowlistAndPresets(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	host := e.metadataHost()
	doc := func(id string) {
		host.Put(id, map[string]any{"client_id": id, "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	}
	waiting, later := "https://apps.example/client/waiting", "https://apps.example/client/later"
	doc(waiting)
	doc(later)
	if p := e.loginAndAsk(waiting); p.Status != 403 {
		t.Fatalf("waiting: %d", p.Status)
	}

	// Allowlist: validated, listed, approving what waits, then what comes.
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "http://apps.example", "path_prefix": "/client"}, 400)
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://apps.example", "path_prefix": "client"}, 400)
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://apps.example", "path_prefix": "/client", "protected_resource_id": "00000000-0000-4000-8000-000000000000"}, 404)
	entry := e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://apps.example", "path_prefix": "/client", "protected_resource_id": protected}, 201).JSON
	e.Must("POST", e.Base+"/oauth-client-allowlist", e.Owner, fiber.Map{"origin": "https://apps.example", "path_prefix": "/client", "protected_resource_id": protected}, 409)
	if items := e.Must("GET", e.Base+"/oauth-client-allowlist?protected_resource_id="+protected, e.Owner, nil, 200).JSON["items"].([]any); len(items) != 1 {
		t.Fatalf("allowlist = %v", items)
	}
	if status, out := e.authorizeExternal(waiting); status != 200 {
		t.Fatalf("waiting client after the entry: %d %v", status, out)
	}
	if status, out := e.authorizeExternal(later); status != 200 {
		t.Fatalf("allowlisted on discovery: %d %v", status, out)
	}
	var source string
	e.DB.Get(&source, `SELECT admission_source FROM oauth_clients WHERE external_id=$1`, later)
	if source != "allowlist" {
		t.Fatalf("admission_source = %q", source)
	}
	e.Must("DELETE", e.Base+"/oauth-client-allowlist/"+entry["id"].(string), e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/oauth-client-allowlist/"+entry["id"].(string), e.Owner, nil, 404)
	for _, typ := range []string{"oauth_client_allowlist.created", "oauth_client_allowlist.deleted"} {
		if e.count(`SELECT count(*) FROM events WHERE type=$1 AND subject_id=$2`, typ, entry["id"]) != 1 {
			t.Fatalf("no %s event", typ)
		}
	}

	// Catalog: Inspector is not offered by default.
	catalog := e.Must("GET", e.Base+"/oauth-client-presets", e.Owner, nil, 200).JSON["items"].([]any)
	keys := map[string]bool{}
	for _, p := range catalog {
		keys[p.(map[string]any)["key"].(string)] = true
	}
	if !keys["claude_code"] || !keys["cursor"] || !keys["gemini_cli"] || !keys["antigravity"] || keys["mcp_inspector"] {
		t.Fatalf("catalog = %v", keys)
	}

	// CIMD presets: one click adds the entry; a public client warns.
	got := e.Must("POST", e.Base+"/oauth-client-presets", e.Owner, fiber.Map{"preset": "chatgpt", "protected_resource_id": protected}, 201).JSON
	if got["network"] != "public" || len(got["warnings"].([]any)) == 0 || got["allowlist_entry"] == nil {
		t.Fatalf("chatgpt preset = %v", got)
	}
	e.Must("POST", e.Base+"/oauth-client-presets", e.Owner, fiber.Map{"preset": "claude_code", "protected_resource_id": protected}, 201)
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	if status, out := e.authorizeExternal(claudeCodeID); status != 200 {
		t.Fatalf("claude_code preset: %d %v", status, out)
	}
	e.Must("POST", e.Base+"/oauth-client-presets", e.Owner, fiber.Map{"preset": "nope"}, 400)
	e.Must("POST", e.Base+"/oauth-client-presets", e.Owner, fiber.Map{}, 400)

	// Templates: a registered public client with known redirects.
	tpl := e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "gemini_cli"}, 201).JSON
	made := tpl["client"].(map[string]any)
	if made["loopback_any_port"] != true || made["created"] != true {
		t.Fatalf("gemini_cli = %v", tpl)
	}
	id := made["client_id"].(string)
	if again := e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "gemini_cli"}, 200).JSON["client"].(map[string]any); again["client_id"] != id || again["created"] != false {
		t.Fatalf("second gemini_cli = %v", again)
	}
	e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "claude_code"}, 400)
	// It authorizes on a free port the client picked.
	port := "http://localhost:54871/oauth/callback"
	b := e.browser()
	code := b.signInTo(b.get(resourceAuthorize(id, url.Values{"redirect_uri": {port}})), port)
	form := codeForm(id, code)
	form.Set("redirect_uri", port)
	if status, out, _ := e.tokenCall(form, ""); status != 200 || out["refresh_token"] == nil {
		t.Fatalf("template client: %d %v", status, out)
	}
	// Another path or host is refused at the redirect check.
	if p := e.browser().get(resourceAuthorize(id, url.Values{"redirect_uri": {"http://localhost:54871/other"}})); p.Status == 303 && strings.HasPrefix(p.Location, "/hosted/login") {
		t.Fatalf("unregistered path accepted: %q", p.Location)
	}
	e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "cursor"}, 201)
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE protected_resource_id IS NULL AND preset<>'' AND public AND hosted_login`); n != 2 {
		t.Fatalf("template clients = %d", n)
	}

	// Inspector: refused until the environment turns the feature on.
	e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "mcp_inspector"}, 400)
	e.Must("PUT", e.Base+"/features/development_clients", e.Owner, fiber.Map{"enabled": true}, 200)
	inspector := e.Must("POST", e.Base+"/protected-resources/"+protected+"/client-templates", e.Owner, fiber.Map{"preset": "mcp_inspector"}, 201).JSON["client"].(map[string]any)
	if len(inspector["redirect_uris"].([]any)) != 2 {
		t.Fatalf("inspector = %v", inspector)
	}
	catalog = e.Must("GET", e.Base+"/oauth-client-presets", e.Owner, nil, 200).JSON["items"].([]any)
	found := false
	for _, p := range catalog {
		found = found || p.(map[string]any)["key"] == "mcp_inspector"
	}
	if !found {
		t.Fatal("inspector missing from the development catalog")
	}
}

// TestProtectedResourceDeleteWithExternalClients is M2: a server whose
// external clients hold sessions and grants can be deleted; the impact
// counts those clients first.
func TestProtectedResourceDeleteWithExternalClients(t *testing.T) {
	e := newEnv(t)
	e.Server.RateLimitPerMinute = 100000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	_, protected, _ := e.mcpServer(fiber.Map{})
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"client_admission": "open"}, 200)
	host := e.metadataHost()
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	status, tokens := e.authorizeExternal(claudeCodeID)
	if status != 200 || tokens["refresh_token"] == nil {
		t.Fatalf("authorize: %d %v", status, tokens)
	}
	// A parked request and a device-less authorization row of the client
	// are what blocked the delete.
	b := e.browser()
	b.get(resourceAuthorize(claudeCodeID, url.Values{"redirect_uri": {loopback}}))

	impact := e.Must("GET", e.Base+"/protected-resources/"+protected+"/impact", e.Owner, nil, 200).JSON
	if impact["external_clients"] != float64(1) || impact["active_sessions"].(float64) < 1 {
		t.Fatalf("impact = %v", impact)
	}
	var rowID string
	e.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	if e.count(`SELECT count(*) FROM oauth_authorizations WHERE client_id=$1`, rowID) == 0 {
		t.Fatal("the client holds no grant to delete")
	}
	e.Must("DELETE", e.Base+"/protected-resources/"+protected, e.Owner, nil, 204)
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE id=$1`, rowID); n != 0 {
		t.Fatalf("external client survived the server")
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE oauth_client_id=$1 AND revoked_at IS NULL`, rowID); n != 0 {
		t.Fatalf("%d sessions outlived the server", n)
	}
	if status, _, _ := e.tokenCall(refreshForm(claudeCodeID, tokens["refresh_token"].(string)), ""); status == 200 {
		t.Fatal("refresh works after the server was deleted")
	}
}
