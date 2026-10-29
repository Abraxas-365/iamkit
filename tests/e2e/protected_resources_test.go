package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

const mcpURI = "https://mcp.example/mcp"

// mcpServer registers a resource whose audience is an MCP server's URL, a
// protected resource over it and a hosted public client for it; alice holds
// both its permissions. It returns the client and protected resource ids.
func (e *Env) mcpServer(body fiber.Map) (client, protected, resource string) {
	e.t.Helper()
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	resource = e.ID("POST", e.Base+"/resources", fiber.Map{"name": "MCP", "prefix": "mcp", "audience": mcpURI, "permissions": []string{"mcp:tools:read", "mcp:tools:write"}})
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource}, 201)
	in := fiber.Map{"application_id": e.Client, "resource_id": resource, "name": "Tools", "default_scopes": []string{"mcp:tools:read"}}
	for k, v := range body {
		in[k] = v
	}
	protected = e.Must("POST", e.Base+"/protected-resources", e.Owner, in, 201).JSON["id"].(string)
	client = e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "hosted_login": true}, 201).JSON["client_id"].(string)
	e.Grant(e.Org, e.Alice, resource, "mcp:tools:read", "mcp:tools:write")
	return client, protected, resource
}

// resourceAuthorize is an MCP client's authorization request: PKCE, state,
// the resource and no openid or nonce.
func resourceAuthorize(client string, extra url.Values) string {
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "state": {"unpredictable-state-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "resource": {mcpURI}}
	for k, v := range extra {
		q[k] = v
	}
	return "/oauth/authorize?" + q.Encode()
}

// tokenCall posts a token request (with an Origin when origin is set).
func (e *Env) tokenCall(form url.Values, origin string) (int, map[string]any, http.Header) {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out, res.Header
}

// signIn runs the hosted sign-in of an authorization and returns the code.
func (b *browser) signIn(start page) string {
	b.t.Helper()
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		b.t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	tk := b.get(start.Location).field("ticket")
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {b.e.AliceEmail}, "password": {b.e.Pass}})
	loc, err := url.Parse(done.Location)
	if done.Status != 303 || err != nil || loc.Query().Get("code") == "" || loc.Query().Get("state") != "unpredictable-state-123456" || loc.Query().Get("iss") != testIssuer {
		b.t.Fatalf("finish: %d %q %s", done.Status, done.Location, done.Body)
	}
	return loc.Query().Get("code")
}

func codeForm(client, code string, resource ...string) url.Values {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {hostedVerifier}}
	if len(resource) > 0 {
		form["resource"] = resource
	}
	return form
}

func refreshForm(client, token string, resource ...string) url.Values {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {token}}
	if len(resource) > 0 {
		form["resource"] = resource
	}
	return form
}

func scopesOf(token map[string]any) []string {
	return strings.Fields(token["scope"].(string))
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		if !contains(b, v) {
			return false
		}
	}
	return true
}

// TestProtectedResources covers phase (a) of IAMKit as an MCP authorization
// server: RFC 8414 metadata, protected resource management, RFC 8707
// resource indicators (aud, invalid_target), scopes = permissions with
// D12 recomputation, refresh rotation and reuse detection, per-server TTLs
// held to the environment policy, membership removal (D11), public CORS and
// unchanged OpenID Connect clients.
func TestProtectedResources(t *testing.T) {
	e := newEnv(t)
	client, protected, _ := e.mcpServer(nil)

	// RFC 8414 metadata: the OpenID configuration under the OAuth name.
	oidc := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).Body
	as := e.Must("GET", "/.well-known/oauth-authorization-server", "", nil, 200)
	if as.Body != oidc || as.JSON["issuer"] == nil || !contains(strs(as.JSON["code_challenge_methods_supported"]), "S256") {
		t.Fatalf("authorization server metadata: %s", as.Body)
	}

	// Management: read, conflicts, validation, policy ceilings.
	got := e.Must("GET", e.Base+"/protected-resources/"+protected, e.Owner, nil, 200).JSON
	if got["uri"] != mcpURI || got["idle_ttl_seconds"].(float64) != 7*86400 || got["max_ttl_seconds"].(float64) != 30*86400 || got["active"] != true {
		t.Fatalf("protected resource: %v", got)
	}
	if list := e.Must("GET", e.Base+"/protected-resources", e.Owner, nil, 200).JSON; list["page"].(map[string]any)["total"].(float64) != 1 {
		t.Fatalf("list: %v", list)
	}
	e.Must("POST", e.Base+"/protected-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": got["resource_id"], "name": "Again"}, 409)
	// The console offers only applications linked to the resource.
	if apps := e.Must("GET", e.Base+"/applications?resource_id="+got["resource_id"].(string), e.Owner, nil, 200).JSON; apps["page"].(map[string]any)["total"].(float64) != 1 || apps["items"].([]any)[0].(map[string]any)["id"] != e.Client {
		t.Fatalf("applications of the resource: %v", apps)
	}
	e.Must("GET", e.Base+"/applications?resource_id=nope", e.Owner, nil, 400)
	e.Must("POST", e.Base+"/protected-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "name": "Billing", "default_scopes": []string{"mcp:tools:read"}}, 400)
	if res := e.Do("POST", e.Base+"/protected-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.IAMResource(), "name": "IAM"}); res.Status < 400 {
		t.Fatalf("IAM resource protected: %d %s", res.Status, res.Body)
	}
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"max_ttl_seconds": 200 * 86400}, 400)
	if p := e.Must("GET", e.Base+"/protected-resource-policy", e.Owner, nil, 200).JSON; p["max_idle_ttl_seconds"].(float64) != 30*86400 || p["max_lifetime_ttl_seconds"].(float64) != 90*86400 {
		t.Fatalf("default policy: %v", p)
	}
	// The resource's audience never changes (the API ignores it, a trigger
	// refuses it).
	e.Do("PUT", e.Base+"/resources/"+got["resource_id"].(string), e.Owner, fiber.Map{"name": "MCP", "audience": "https://other.example/mcp", "permissions": []string{"mcp:tools:read", "mcp:tools:write"}})
	if _, err := e.DB.Exec(`UPDATE resources SET audience='https://other.example/mcp' WHERE id=$1`, got["resource_id"]); err == nil {
		t.Fatal("trigger accepted an audience change")
	}
	var audience string
	e.DB.Get(&audience, `SELECT audience FROM resources WHERE id=$1`, got["resource_id"])
	if audience != mcpURI {
		t.Fatalf("audience changed to %s", audience)
	}

	// invalid_target, at the redirect with state once the client is known.
	for name, query := range map[string]string{
		"unknown resource": resourceAuthorize(client, url.Values{"resource": {"https://elsewhere.example/mcp"}}),
		"two resources":    resourceAuthorize(client, url.Values{"resource": {mcpURI, mcpURI}}),
		"plain client":     resourceAuthorize(e.hostedClient(), url.Values{"resource": {e.Audience}}),
	} {
		p := e.browser().get(query)
		loc, _ := url.Parse(p.Location)
		if p.Status != 303 || loc == nil || loc.Query().Get("error") != "invalid_target" || loc.Query().Get("state") != "unpredictable-state-123456" || loc.Query().Get("iss") != testIssuer {
			t.Fatalf("%s: %d %q %s", name, p.Status, p.Location, p.Body)
		}
	}
	// Permissions are scopes only with the resource.
	if p := e.browser().get(authorizeQuery(client, url.Values{"scope": {"openid mcp:tools:read"}})); p.Status != 400 {
		t.Fatalf("permission scope without resource: %d %s", p.Status, p.Body)
	}

	// The resource flow: no openid, no nonce; the default scope, a refresh
	// token (implicit offline_access), aud = the server.
	b := e.browser()
	code := b.signIn(b.get(resourceAuthorize(client, nil)))
	status, tokens, _ := e.tokenCall(codeForm(client, code, "https://MCP.example:443/mcp/"), "")
	if status != 200 || tokens["refresh_token"] == nil || tokens["id_token"] != nil {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}
	if !sameSet(scopesOf(tokens), []string{"mcp:tools:read", "offline_access"}) {
		t.Fatalf("default scopes: %v", tokens["scope"])
	}
	c := claims(t, tokens["access_token"].(string))
	if aud := strs(c["aud"]); !equal(aud, []string{mcpURI}) || c["resource"] != mcpURI || c["environment_id"] != e.EnvID || c["purpose"] != "application" || !equal(strs(c["permissions"]), []string{"mcp:tools:read"}) || !contains(strs(c["scp"]), "mcp:tools:read") {
		t.Fatalf("access token claims: %v", c)
	}
	if exp := c["exp"].(float64) - c["iat"].(float64); exp < 899 || exp > 901 {
		t.Fatalf("access token lifetime %vs", exp)
	}

	// Requested scopes, with openid: an ID token too.
	b = e.browser()
	code = b.signIn(b.get(resourceAuthorize(client, url.Values{"scope": {"openid mcp:tools:read mcp:tools:write"}, "nonce": {"unpredictable-nonce-123456"}})))
	status, tokens, _ = e.tokenCall(codeForm(client, code), "")
	if status != 200 || tokens["id_token"] == nil || !sameSet(scopesOf(tokens), []string{"openid", "mcp:tools:read", "mcp:tools:write", "offline_access"}) {
		t.Fatalf("requested scopes: %d %v", status, tokens)
	}
	if !equal(strs(claims(t, tokens["access_token"].(string))["permissions"]), []string{"mcp:tools:read", "mcp:tools:write"}) {
		t.Fatalf("permissions: %v", claims(t, tokens["access_token"].(string)))
	}
	// openid without a nonce is still refused.
	if p := e.browser().get(resourceAuthorize(client, url.Values{"scope": {"openid"}})); p.Status != 400 {
		t.Fatalf("openid without nonce: %d %s", p.Status, p.Body)
	}

	// Refresh: another resource is invalid_target, the same one (or none)
	// rotates.
	refresh := tokens["refresh_token"].(string)
	if status, out, _ := e.tokenCall(refreshForm(client, refresh, "https://elsewhere.example/mcp"), ""); status != 400 || out["error"] != "invalid_target" {
		t.Fatalf("refresh to another resource: %d %v", status, out)
	}
	if status, out, _ := e.tokenCall(refreshForm(client, refresh, mcpURI, mcpURI), ""); status != 400 || out["error"] != "invalid_target" {
		t.Fatalf("refresh with two resources: %d %v", status, out)
	}
	status, rotated, _ := e.tokenCall(refreshForm(client, refresh, mcpURI), "")
	if status != 200 || rotated["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, rotated)
	}

	// D12: a permission lost without ending the session (a group role,
	// here) is gone from the next refresh; regained, it returns, never
	// beyond what was consented. Direct grant changes end the session.
	resourceID := got["resource_id"].(string)
	groups := e.Base + "/organizations/" + e.Org + "/groups"
	writers := e.ID("POST", groups, fiber.Map{"name": "MCP writers"})
	writer := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "mcp-writer", "resource_id": resourceID, "permissions": []string{"mcp:tools:write"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": writer, "organization_id": e.Org, "group_id": writers}, 204)
	e.Must("POST", groups+"/"+writers+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 204)
	e.Grant(e.Org, e.Alice, resourceID, "mcp:tools:read")
	if status, out, _ := e.tokenCall(refreshForm(client, rotated["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after a direct grant change: %d %v", status, out)
	}
	b = e.browser()
	code = b.signIn(b.get(resourceAuthorize(client, url.Values{"scope": {"mcp:tools:read mcp:tools:write"}})))
	status, tokens, _ = e.tokenCall(codeForm(client, code), "")
	if status != 200 || !contains(scopesOf(tokens), "mcp:tools:write") {
		t.Fatalf("authorize with a group role: %d %v", status, tokens)
	}
	refresh = tokens["refresh_token"].(string)
	e.Must("POST", groups+"/"+writers+"/members", e.Owner, fiber.Map{"remove": []string{e.Alice}}, 204)
	status, narrowed, _ := e.tokenCall(refreshForm(client, refresh), "")
	if status != 200 || contains(scopesOf(narrowed), "mcp:tools:write") || !contains(scopesOf(narrowed), "mcp:tools:read") || !equal(strs(claims(t, narrowed["access_token"].(string))["permissions"]), []string{"mcp:tools:read"}) {
		t.Fatalf("refresh after losing a permission: %d %v", status, narrowed)
	}
	e.Must("POST", groups+"/"+writers+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 204)
	status, widened, _ := e.tokenCall(refreshForm(client, narrowed["refresh_token"].(string)), "")
	if status != 200 || !contains(scopesOf(widened), "mcp:tools:write") {
		t.Fatalf("refresh after regaining a permission: %d %v", status, widened)
	}
	// RFC 6749 §6: a refresh may ask for less, never for more; the refresh
	// token keeps the consent, so the next refresh gets everything again.
	less := refreshForm(client, widened["refresh_token"].(string))
	less.Set("scope", "mcp:tools:read")
	status, fewer, _ := e.tokenCall(less, "")
	if status != 200 || contains(scopesOf(fewer), "mcp:tools:write") || !equal(strs(claims(t, fewer["access_token"].(string))["permissions"]), []string{"mcp:tools:read"}) {
		t.Fatalf("narrower refresh: %d %v", status, fewer)
	}
	more := refreshForm(client, fewer["refresh_token"].(string))
	more.Set("scope", "mcp:tools:read mcp:admin")
	if status, out, _ := e.tokenCall(more, ""); status != 400 || out["error"] != "invalid_scope" {
		t.Fatalf("wider refresh: %d %v", status, out)
	}
	status, widened, _ = e.tokenCall(refreshForm(client, fewer["refresh_token"].(string)), "")
	if status != 200 || !contains(scopesOf(widened), "mcp:tools:write") {
		t.Fatalf("refresh after a narrower one: %d %v", status, widened)
	}

	// D10: replaying a rotated refresh token revokes the whole family.
	if status, out, _ := e.tokenCall(refreshForm(client, refresh), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out)
	}
	if status, out, _ := e.tokenCall(refreshForm(client, widened["refresh_token"].(string)), ""); status == 200 {
		t.Fatalf("family survived reuse: %v", out)
	}

	// Plain OpenID Connect clients keep working, without aud or scope changes.
	plain := e.hostedClient()
	pb := e.browser()
	oidcTokens := pb.exchange(plain, pb.post("/hosted/login/password", url.Values{"ticket": {pb.authorize(plain).field("ticket")}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	if pc := claims(t, oidcTokens["access_token"].(string)); !equal(strs(pc["aud"]), []string{e.Audience}) || !equal(strs(pc["permissions"]), []string{"invoices:read"}) || pc["resource"] != nil {
		t.Fatalf("plain client token: %v", pc)
	}
	if status, out, _ := e.tokenCall(refreshForm(plain, oidcTokens["refresh_token"].(string), e.Audience), ""); status != 400 || out["error"] != "invalid_target" {
		t.Fatalf("plain refresh with resource: %d %v", status, out)
	}
	if status, out, _ := e.tokenCall(refreshForm(plain, oidcTokens["refresh_token"].(string)), ""); status != 200 {
		t.Fatalf("plain refresh: %d %v", status, out)
	}

	// Public CORS: an MCP client in a browser reads the token answer.
	if status, out, header := e.tokenCall(refreshForm(client, "nope"), "https://inspector.example"); status != 400 || header.Get("Access-Control-Allow-Origin") != "*" || header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("token CORS: %d %v %v", status, out, header)
	}
	pre := httptest.NewRequest("OPTIONS", "/oauth/token", nil)
	pre.Header.Set("Origin", "https://inspector.example")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	pre.Header.Set("Access-Control-Request-Headers", "content-type,mcp-protocol-version")
	if res, err := e.App.Test(pre, 10000); err != nil || res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("token preflight: %v %v", err, res)
	}

	// D11: removing the membership ends the grant.
	b = e.browser()
	code = b.signIn(b.get(resourceAuthorize(client, nil)))
	_, tokens, _ = e.tokenCall(codeForm(client, code), "")
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+e.Alice, e.Owner, nil, 204)
	if status, out, _ := e.tokenCall(refreshForm(client, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after membership removal: %d %v", status, out)
	}

	// Events of the management writes.
	var types []string
	e.DB.Select(&types, `SELECT type FROM events WHERE environment_id=$1 AND type LIKE 'protected_resource%' ORDER BY id`, e.EnvID)
	if !contains(types, "protected_resource.created") {
		t.Fatalf("events: %v", types)
	}
}

// TestProtectedResourceSharedSession: a custom sign-in UI may complete two
// authorizations with one sign-in. The resource grant lives the server's
// lifetime, and a later plain OpenID Connect grant on the same session
// stays within the ordinary session window.
func TestProtectedResourceSharedSession(t *testing.T) {
	e := newEnv(t)
	_, _, resource := e.mcpServer(fiber.Map{"max_ttl_seconds": 7 * 24 * 3600})
	custom := func() string {
		return e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{"https://login.example.com"}}, 201).JSON["client_id"].(string)
	}
	mcp, plain := custom(), custom()
	login := e.LoginBody(e.AliceEmail, e.Pass)
	login["resource_id"] = resource
	token := e.Must("POST", "/identity/v1/login", "", login, 200).JSON["access_token"].(string)
	sid := claims(t, token)["sid"].(string)
	complete := func(client string, q url.Values) map[string]any {
		b := e.browser()
		var begin map[string]any
		json.Unmarshal([]byte(b.get(resourceAuthorize(client, q)).Body), &begin)
		ticket, _ := begin["authorization_ticket"].(string)
		if ticket == "" {
			t.Fatalf("authorize %s: %v", client, begin)
		}
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": ticket, "approve": true})
		req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		for _, c := range b.cookies {
			req.AddCookie(c)
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		code, _ := url.Parse(res.Header.Get("Location"))
		status, tokens, _ := e.tokenCall(codeForm(client, code.Query().Get("code")), "")
		if status != 200 || claims(t, tokens["access_token"].(string))["sid"] != sid {
			t.Fatalf("complete %s: %d %v", client, status, tokens)
		}
		return tokens
	}

	complete(mcp, nil)
	var lifetime float64
	e.DB.Get(&lifetime, `SELECT extract(epoch FROM expires_at-created_at) FROM sessions WHERE id=$1`, sid)
	if lifetime != 7*24*3600 {
		t.Fatalf("session lifetime %vs, want the resource's", lifetime)
	}
	// The plain grant on the same session ends with the ordinary window.
	oidc := complete(plain, url.Values{"resource": nil, "scope": {"openid offline_access"}, "nonce": {"unpredictable-nonce-123456"}})
	// Its token is for the MCP server's audience too, but carries no
	// resource indicator: resource servers refuse it (C1).
	if pc := claims(t, oidc["access_token"].(string)); !equal(strs(pc["aud"]), []string{mcpURI}) || pc["resource"] != nil {
		t.Fatalf("plain grant token on the MCP resource: %v", pc)
	}
	var deadline float64
	e.DB.Get(&deadline, `SELECT extract(epoch FROM max(r.expires_at)-s.created_at) FROM oauth_requests r JOIN sessions s ON s.id=$2 WHERE r.environment_id=$1 AND r.client_id=$3 AND r.kind='refresh' AND r.active GROUP BY s.created_at`, e.EnvID, sid, plain)
	if deadline <= 0 || deadline > 24*3600+5 {
		t.Fatalf("plain grant's refresh token lives %vs from the sign-in, want ≤ 24h", deadline)
	}
	if status, out, _ := e.tokenCall(refreshForm(plain, oidc["refresh_token"].(string)), ""); status != 200 {
		t.Fatalf("plain refresh: %d %v", status, out)
	}
}

// TestProtectedResourceTTLs: the session of a resource authorization lives
// the server's max TTL (held to the environment's ceiling) from its start,
// each refresh token its idle TTL, and lowering the policy trims servers.
func TestProtectedResourceTTLs(t *testing.T) {
	e := newEnv(t)
	client, protected, _ := e.mcpServer(fiber.Map{"idle_ttl_seconds": 3600, "max_ttl_seconds": 7200})

	b := e.browser()
	code := b.signIn(b.get(resourceAuthorize(client, nil)))
	status, tokens, _ := e.tokenCall(codeForm(client, code), "")
	if status != 200 {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}
	sid := claims(t, tokens["access_token"].(string))["sid"].(string)
	var lifetime float64
	e.DB.Get(&lifetime, `SELECT extract(epoch FROM expires_at-created_at) FROM sessions WHERE id=$1`, sid)
	if lifetime != 7200 {
		t.Fatalf("session lifetime %vs, want 7200", lifetime)
	}
	idle := func() float64 {
		var left float64
		e.DB.Get(&left, `SELECT extract(epoch FROM max(expires_at)-now()) FROM oauth_requests WHERE environment_id=$1 AND kind='refresh' AND active`, e.EnvID)
		return left
	}
	if left := idle(); left < 3500 || left > 3600 {
		t.Fatalf("refresh token lives %vs, want ~3600", left)
	}
	// The sign-in's own identity refresh tokens end with the binding.
	var live int
	e.DB.Get(&live, `SELECT count(*) FROM refresh_tokens WHERE session_id=$1 AND expires_at>now()`, sid)
	if live != 0 {
		t.Fatalf("%d identity refresh tokens outlive the binding", live)
	}

	// A lower ceiling trims the server and holds the next refresh to it.
	e.Must("PUT", e.Base+"/protected-resource-policy", e.Owner, fiber.Map{"max_idle_ttl_seconds": 600, "max_lifetime_ttl_seconds": 7200}, 200)
	if got := e.Must("GET", e.Base+"/protected-resources/"+protected, e.Owner, nil, 200).JSON; got["idle_ttl_seconds"].(float64) != 600 {
		t.Fatalf("not trimmed: %v", got)
	}
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"idle_ttl_seconds": 3600}, 400)
	status, rotated, _ := e.tokenCall(refreshForm(client, tokens["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if left := idle(); left < 500 || left > 600 {
		t.Fatalf("refresh token lives %vs after the ceiling, want ~600", left)
	}

	// The session's end ends the grant.
	e.DB.MustExec(`UPDATE sessions SET expires_at=now()+interval '2 seconds' WHERE id=$1`, sid)
	status, last, _ := e.tokenCall(refreshForm(client, rotated["refresh_token"].(string)), "")
	if status != 200 {
		t.Fatalf("refresh near the deadline: %d %v", status, last)
	}
	time.Sleep(2500 * time.Millisecond)
	if status, out, _ := e.tokenCall(refreshForm(client, last["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after the session's lifetime: %d %v", status, out)
	}

	// Deleting the server ends its grants' refreshes (and the resource
	// parameter is no longer accepted).
	b = e.browser()
	code = b.signIn(b.get(resourceAuthorize(client, nil)))
	_, tokens, _ = e.tokenCall(codeForm(client, code), "")
	e.Must("DELETE", e.Base+"/protected-resources/"+protected, e.Owner, nil, 204)
	if status, out, _ := e.tokenCall(refreshForm(client, tokens["refresh_token"].(string)), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after delete: %d %v", status, out)
	}
	p := e.browser().get(resourceAuthorize(client, nil))
	if loc, _ := url.Parse(p.Location); p.Status != 303 || loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("authorize after delete: %d %q", p.Status, p.Location)
	}
}

// TestProtectedResourceLoweredCeiling: lowering the environment's lifetime
// ceiling shortens authorizations already issued. Each refresh holds the
// grant to min(stored end, sign-in + current lifetime), so after TI cuts
// the ceiling from 90 to 30 days, a 40-day-old session ends at its next
// refresh while a 10-day-old one keeps going until day 30.
func TestProtectedResourceLoweredCeiling(t *testing.T) {
	e := newEnv(t)
	const day = 86400
	client, _, _ := e.mcpServer(fiber.Map{"idle_ttl_seconds": 7 * day, "max_ttl_seconds": 90 * day})
	e.Must("PUT", e.Base+"/protected-resource-policy", e.Owner, fiber.Map{"max_idle_ttl_seconds": 30 * day, "max_lifetime_ttl_seconds": 90 * day}, 200)

	grant := func(age int) (string, string) {
		b := e.browser()
		code := b.signIn(b.get(resourceAuthorize(client, nil)))
		status, tokens, _ := e.tokenCall(codeForm(client, code), "")
		if status != 200 {
			t.Fatalf("code exchange: %d %v", status, tokens)
		}
		sid := claims(t, tokens["access_token"].(string))["sid"].(string)
		var lifetime float64
		e.DB.Get(&lifetime, `SELECT extract(epoch FROM expires_at-created_at) FROM sessions WHERE id=$1`, sid)
		if lifetime != 90*day {
			t.Fatalf("session lifetime %vs, want 90 days", lifetime)
		}
		// Age the authorization: it began age days ago. Both the session row
		// and the stored grant (its start and its end, 90 days from the
		// sign-in at issuance) move back.
		e.DB.MustExec(`UPDATE sessions SET created_at=created_at-make_interval(days => $2), expires_at=expires_at-make_interval(days => $2) WHERE id=$1`, sid, age)
		e.DB.MustExec(`UPDATE oauth_requests SET data=jsonb_set(jsonb_set(data, '{Session,started}', to_jsonb((data#>>'{Session,started}')::timestamptz-make_interval(days => $3))),
			'{Session,deadline}', to_jsonb((data#>>'{Session,deadline}')::timestamptz-make_interval(days => $3)))
			WHERE environment_id=$1 AND data#>>'{Session,access_claims,Extra,sid}'=$2`, e.EnvID, sid, age)
		var aged int
		if err := e.DB.Get(&aged, `SELECT count(*) FROM oauth_requests WHERE environment_id=$1 AND kind='refresh' AND data#>>'{Session,access_claims,Extra,sid}'=$2`, e.EnvID, sid); err != nil || aged == 0 {
			t.Fatalf("no stored refresh grant found to age: %v", err)
		}
		return sid, tokens["refresh_token"].(string)
	}
	_, old := grant(40)
	recentSID, recent := grant(10)

	// Before the change both refresh.
	status, out, _ := e.tokenCall(refreshForm(client, old), "")
	if status != 200 {
		t.Fatalf("old grant under the 90-day ceiling: %d %v", status, out)
	}
	old = out["refresh_token"].(string)

	e.Must("PUT", e.Base+"/protected-resource-policy", e.Owner, fiber.Map{"max_idle_ttl_seconds": 7 * day, "max_lifetime_ttl_seconds": 30 * day}, 200)

	if status, out, _ = e.tokenCall(refreshForm(client, old), ""); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("40-day-old grant after the ceiling fell to 30 days: %d %v", status, out)
	}
	status, out, _ = e.tokenCall(refreshForm(client, recent), "")
	if status != 200 {
		t.Fatalf("10-day-old grant: %d %v", status, out)
	}
	// The new grant ends at sign-in + 30 days, not the stored 90.
	var end float64
	if err := e.DB.Get(&end, `SELECT max(extract(epoch FROM (r.data#>>'{Session,deadline}')::timestamptz-s.created_at))::float8 FROM oauth_requests r JOIN sessions s ON s.id=$2::uuid
		WHERE r.environment_id=$1 AND r.kind='refresh' AND r.active AND r.data#>>'{Session,access_claims,Extra,sid}'=$2::text`, e.EnvID, recentSID); err != nil {
		t.Fatal(err)
	}
	if end < 30*day-60 || end > 30*day {
		t.Fatalf("grant ends %v days after the sign-in, want 30", end/day)
	}
}

// TestProtectedResourceDownstream: an MCP server never forwards the
// client's token; its own confidential client exchanges it (RFC 8693) for a
// token of a downstream API of the same application, with the user's
// permissions there, in a child session that ends with the authorization's.
func TestProtectedResourceDownstream(t *testing.T) {
	e := newEnv(t)
	client, protected, resource := e.mcpServer(nil)
	downstream := e.ID("POST", e.Base+"/resources", fiber.Map{"name": "Notes API", "prefix": "notesapi", "audience": "https://notes-api.example", "permissions": []string{"notesapi:read"}})
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": downstream}, 201)
	e.Grant(e.Org, e.Alice, downstream, "notesapi:read")
	server := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "grant_types": []string{exchangeGrant}}, 201).JSON
	id, secret := server["client_id"].(string), server["client_secret"].(string)

	b := e.browser()
	code := b.signIn(b.get(resourceAuthorize(client, nil)))
	status, tokens, _ := e.tokenCall(codeForm(client, code), "")
	if status != 200 {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}
	access := tokens["access_token"].(string)
	original := claims(t, access)
	exchange := func(audience string) Response {
		return e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "subject_token": {access}, "subject_token_type": {accessTokenType}, "audience": {audience}}, id, secret)
	}
	res := exchange("https://notes-api.example")
	if res.Status != 200 {
		t.Fatalf("exchange: %d %s", res.Status, res.Body)
	}
	got := claims(t, res.JSON["access_token"].(string))
	if !jsonEqual(got["aud"], []any{"https://notes-api.example"}) || !jsonEqual(got["permissions"], []any{"notesapi:read"}) || got["sub"] != original["sub"] || got["sid"] == original["sid"] || got["act"] != nil || got["resource"] != nil {
		t.Fatalf("exchanged claims = %v (original %v)", got, original)
	}
	// The public MCP client cannot exchange, and an unrelated audience is
	// not a target.
	if res := e.tokenRequest(url.Values{"grant_type": {exchangeGrant}, "client_id": {client}, "subject_token": {access}, "subject_token_type": {accessTokenType}, "audience": {"https://notes-api.example"}}, "", ""); res.Status == 200 {
		t.Fatalf("public client exchanged: %s", res.Body)
	}
	if res := exchange("https://elsewhere.example"); res.Status != 400 || res.JSON["error"] != "invalid_target" {
		t.Fatalf("unknown audience: %d %s", res.Status, res.Body)
	}

	// Deactivating the server ends its authorizations' sessions, and with
	// them the downstream token's child session. The console first asks how
	// many sessions that would cut.
	impact := func() float64 {
		return e.Must("GET", e.Base+"/protected-resources/"+protected+"/impact", e.Owner, nil, 200).JSON["active_sessions"].(float64)
	}
	var before float64
	e.DB.Get(&before, `SELECT count(*) FROM sessions s JOIN protected_resources p ON p.id=$1 WHERE s.resource_id=p.resource_id AND s.oauth_client_id IS NOT NULL AND s.revoked_at IS NULL AND s.expires_at>now()`, protected)
	if n := impact(); n < 1 || n != before {
		t.Fatalf("impact before deactivation: %v sessions, want %v", n, before)
	}
	e.Must("GET", e.Base+"/protected-resources/00000000-0000-4000-8000-000000000000/impact", e.Owner, nil, 404)
	e.Must("PATCH", e.Base+"/protected-resources/"+protected, e.Owner, fiber.Map{"active": false}, 200)
	if n := impact(); n != 0 {
		t.Fatalf("impact after deactivation: %v sessions", n)
	}
	var live int
	e.DB.Get(&live, `SELECT count(*) FROM sessions WHERE id IN ($1,$2) AND revoked_at IS NULL`, original["sid"], got["sid"])
	if live != 0 {
		t.Fatalf("%d sessions outlived the deactivated server", live)
	}
}
