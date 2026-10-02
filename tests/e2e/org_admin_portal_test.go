package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// portalAuthorize starts the portal's authorization code + PKCE flow, as
// the portal SPA does, and returns the hosted login page.
func (b *browser) portalAuthorize(client, redirect string, extra url.Values) page {
	b.t.Helper()
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	for k, v := range extra {
		q[k] = v
	}
	start := b.get("/oauth/authorize?" + q.Encode())
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
		b.t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	return b.get(start.Location)
}

// portalToken posts the form request the portal SPA sends to /oauth/token.
func (e *Env) portalToken(form url.Values) (int, map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// TestOrgAdminPortal: operators turn on the hosted organization admin
// portal; IAMKit registers its own public client on the IAM resource, and
// an organization administrator who signs in through the hosted login gets
// a token that works on the organization's /admin routes. The client is
// IAMKit's: operators cannot edit it, and turning the portal off ends its
// sessions.
func TestOrgAdminPortal(t *testing.T) {
	e := newEnv(t)
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	portal := e.Base + "/org-admin-portal"
	discover := "/identity/v1/org-admin/" + e.EnvID

	// Off until an operator turns it on; viewers cannot.
	if p := e.Must("GET", portal, e.Owner, nil, 200).JSON; p["enabled"] != false || p["client_id"] != nil {
		t.Fatalf("initial portal = %v", p)
	}
	e.Must("GET", discover, "", nil, 404)
	e.Must("GET", "/identity/v1/org-admin/not-an-id", "", nil, 404)
	e.Must("DELETE", portal, e.Owner, nil, 404)
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	e.Must("PUT", portal, viewer, nil, 403)

	on := e.Must("PUT", portal, e.Owner, nil, 200).JSON
	client, _ := on["client_id"].(string)
	base := "https://iam.example/org-admin/" + e.EnvID
	if on["enabled"] != true || client == "" || on["url"] != base {
		t.Fatalf("enabled portal = %v", on)
	}
	if again := e.Must("PUT", portal, e.Owner, nil, 200).JSON; again["client_id"] != client || again["application_id"] != on["application_id"] {
		t.Fatalf("enabling again = %v, want the same client", again)
	}
	if d := e.Must("GET", discover, "", nil, 200).JSON; d["client_id"] != client || d["url"] != base {
		t.Fatalf("discovery = %v", d)
	}
	var enabled int
	e.DB.Get(&enabled, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action='org_admin_portal.enabled'`, e.EnvID)
	if enabled != 2 {
		t.Fatalf("enabled audit events = %d", enabled)
	}

	// The client is public, hosted, on the IAM resource — and IAMKit's.
	view := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON
	if view["system"] != "org_admin" || view["public"] != true || view["hosted_login"] != true || view["resource_id"] != e.IAMResource() || view["application_name"] != "Organization admin portal" {
		t.Fatalf("portal client = %v", view)
	}
	if r := view["redirect_uris"].([]any); len(r) != 1 || r[0] != base+"/callback" {
		t.Fatalf("redirect uris = %v", r)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"redirect_uris": []string{"https://evil.example/cb"}}, 409)
	e.Must("DELETE", e.Base+"/oauth-clients/"+client, e.Owner, nil, 409)

	// Alice owns Acme; Bob is a plain member without iam:org:* roles.
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)

	// Alice signs in through the hosted pages, as the portal sends her.
	b := e.browser()
	login := b.portalAuthorize(client, base+"/callback", url.Values{"organization_id": {e.Org}})
	done := b.post("/hosted/login/password", url.Values{"ticket": {login.field("ticket")}, "email": {e.AliceEmail}, "password": {e.Pass}})
	location, err := url.Parse(done.Location)
	if done.Status != 303 || err != nil || !strings.HasPrefix(done.Location, base+"/callback?") || location.Query().Get("code") == "" {
		t.Fatalf("finish: %d %q %s", done.Status, done.Location, done.Body)
	}
	// Another redirect URI is refused.
	if r := b.get("/oauth/authorize?" + url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"unpredictable-state-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {"x"}}.Encode()); r.Status == 303 && strings.HasPrefix(r.Location, "/hosted/login") {
		t.Fatalf("foreign redirect accepted: %q", r.Location)
	}
	status, tokens := e.portalToken(url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {base + "/callback"}, "code": {location.Query().Get("code")}, "code_verifier": {hostedVerifier}})
	access, _ := tokens["access_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)
	if status != 200 || access == "" || refresh == "" || tokens["id_token"] == nil {
		t.Fatalf("token: %d %v", status, tokens)
	}
	c := claims(t, access)
	if c["organization_id"] != e.Org || c["resource_id"] != e.IAMResource() || !contains(anyStrings(c["permissions"]), "iam:org:settings:write") {
		t.Fatalf("claims = %v", c)
	}

	// The token administers Acme through /api/v1 — and nothing else.
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	if org := e.Must("GET", admin, access, nil, 200).JSON; org["name"] != "Acme" {
		t.Fatalf("organization = %v", org)
	}
	e.Must("PATCH", admin, access, fiber.Map{"name": "Acme Inc"}, 204)
	if m := e.Must("GET", admin+"/members", access, nil, 200).JSON; m["page"].(map[string]any)["total"].(float64) != 2 {
		t.Fatalf("members = %v", m)
	}
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/users", access, nil, 403)
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+globex+"/admin", access, nil, 403)

	// Refreshing keeps it working (the portal refreshes in the background).
	status, refreshed := e.portalToken(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {refresh}})
	if status != 200 || refreshed["access_token"] == nil {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	access = refreshed["access_token"].(string)
	refresh, _ = refreshed["refresh_token"].(string)
	e.Must("GET", admin, access, nil, 200)

	// Bob gets in (he is a member) but his token administers nothing.
	bb := e.browser()
	bl := bb.portalAuthorize(client, base+"/callback", nil)
	bd := bb.post("/hosted/login/password", url.Values{"ticket": {bl.field("ticket")}, "email": {"bob@example.com"}, "password": {e.Pass}})
	bloc, _ := url.Parse(bd.Location)
	if bd.Status == 303 && bloc != nil && bloc.Query().Get("code") != "" {
		_, bt := e.portalToken(url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {base + "/callback"}, "code": {bloc.Query().Get("code")}, "code_verifier": {hostedVerifier}})
		if bob, _ := bt["access_token"].(string); bob != "" {
			e.Must("GET", admin, bob, nil, 403)
		}
	}

	// Turning it off ends Alice's portal session at once.
	e.Must("DELETE", portal, e.Owner, nil, 204)
	e.Must("GET", admin, access, nil, 401)
	if status, _ := e.portalToken(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {refresh}}); status == 200 {
		t.Fatal("refresh worked after the portal was turned off")
	}
	e.Must("GET", discover, "", nil, 404)
	if p := e.Must("GET", portal, e.Owner, nil, 200).JSON; p["enabled"] != false || p["url"] != nil {
		t.Fatalf("disabled portal = %v", p)
	}
	var disabled int
	e.DB.Get(&disabled, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action='org_admin_portal.disabled'`, e.EnvID)
	if disabled != 1 {
		t.Fatalf("disabled audit events = %d", disabled)
	}

	// Back on: the same client, signing in works again.
	if p := e.Must("PUT", portal, e.Owner, nil, 200).JSON; p["client_id"] != client {
		t.Fatalf("re-enabled = %v", p)
	}
	b2 := e.browser()
	l2 := b2.portalAuthorize(client, base+"/callback", nil)
	d2 := b2.post("/hosted/login/password", url.Values{"ticket": {l2.field("ticket")}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if d2.Status != 303 || !strings.HasPrefix(d2.Location, base+"/callback?") {
		t.Fatalf("sign-in after re-enabling: %d %q %s", d2.Status, d2.Location, d2.Body)
	}
	e.Must("GET", discover, "", nil, 200)
}
