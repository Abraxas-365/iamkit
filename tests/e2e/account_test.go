package e2e_test

import (
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/gofiber/fiber/v2"
)

func (e *Env) meQ() string { return "?environment_id=" + e.EnvID + "&audience=" + e.Audience }

func (e *Env) loginResult(email string) map[string]any {
	e.t.Helper()
	return e.Must("POST", "/identity/v1/login", "", e.LoginBody(email, e.Pass), 200).JSON
}

func (e *Env) refreshBody(org, refresh string) fiber.Map {
	return fiber.Map{"environment_id": e.EnvID, "organization_id": org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": refresh}
}

// TestChangePassword covers POST /identity/v1/me/password: a fresh sign-in,
// the current password (counted toward the lockout), the policy and breach
// check, other sessions ending while the current one stays, and the event.
func TestChangePassword(t *testing.T) {
	breaches := &fakeBreaches{breached: map[string]bool{"Breached-Password-1": true}}
	e := newEnv(t, bootstrap.WithBreaches(breaches))
	e.Must("PUT", e.Base+"/password-policy", e.Owner, fiber.Map{"min_length": 14, "breach_check": true, "lockout_threshold": 3, "lockout_minutes": 10}, 200)
	url := "/identity/v1/me/password" + e.meQ()
	change := func(token, current, next string, want int) Response {
		return e.Must("POST", url, token, fiber.Map{"current_password": current, "new_password": next}, want)
	}
	const fresh = "a much better passphrase"

	current := e.Login(e.AliceEmail)

	// Authentication, shape, wrong current password, rules.
	change("", e.Pass, fresh, 401)
	e.Must("POST", url, current, fiber.Map{"current_password": e.Pass}, 400)
	if r := change(current, "wrong password here", fresh, 422); !strings.Contains(r.Body, "INVALID_CURRENT_PASSWORD") {
		t.Fatalf("wrong current = %s", r.Body)
	}
	if r := change(current, e.Pass, "short", 400); ruleOf(r) != "length" {
		t.Fatalf("short = %s", r.Body)
	}
	if r := change(current, e.Pass, "Breached-Password-1", 400); ruleOf(r) != "breached" {
		t.Fatalf("breached = %s", r.Body)
	}
	if r := change(current, e.Pass, e.Pass, 400); ruleOf(r) != "reused" {
		t.Fatalf("reused = %s", r.Body)
	}

	// Wrong passwords count toward the lockout like at sign-in.
	change(current, "wrong password two", fresh, 422)
	change(current, "wrong password three", fresh, 422)
	change(current, "wrong password four", fresh, 422)
	if r := e.Do("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass)); r.Status == 200 {
		t.Fatalf("locked login = %d %s", r.Status, r.Body)
	}
	e.Must("POST", e.Base+"/users/"+e.Alice+"/unlock", e.Owner, nil, 204)

}

// TestChangePasswordSessions: stale sign-ins, impersonation, other sessions
// ending while the current one stays (the route allows ten calls per window,
// so this is its own server).
func TestChangePasswordSessions(t *testing.T) {
	e := newEnv(t)
	url := "/identity/v1/me/password" + e.meQ()
	change := func(token, current, next string, want int) Response {
		return e.Must("POST", url, token, fiber.Map{"current_password": current, "new_password": next}, want)
	}
	const fresh = "a much better passphrase"
	current := e.Login(e.AliceEmail)
	other := e.Login(e.AliceEmail)
	otherLogin := e.loginResult(e.AliceEmail)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	bobToken := e.Login("bob@example.com")
	e.Must("GET", "/identity/v1/me"+e.meQ(), other, nil, 200)

	// Machine users, impersonated tokens and API keys cannot.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200).JSON["access_token"].(string)
	change(imp, e.Pass, fresh, 403)

	// A stale sign-in is asked to authenticate again, even after a refresh.
	if _, err := e.DB.Exec(`UPDATE sessions SET authenticated_at=now()-interval '1 hour' WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	stale := e.Must("POST", "/identity/v1/refresh", "", e.refreshBody(e.Org, otherLogin["refresh_token"].(string)), 200).JSON["access_token"].(string)
	if r := change(stale, e.Pass, fresh, 403); !strings.Contains(r.Body, "REAUTHENTICATION_REQUIRED") {
		t.Fatalf("stale = %s", r.Body)
	}
	if _, err := e.DB.Exec(`UPDATE sessions SET authenticated_at=now() WHERE user_id=$1`, e.Alice); err != nil {
		t.Fatal(err)
	}

	// Success: the current session stays, the others end, the new password works.
	live := e.Login(e.AliceEmail)
	out := change(live, e.Pass, fresh, 200).JSON
	if out["sessions_revoked"].(float64) < 3 {
		t.Fatalf("result = %v", out)
	}
	e.Must("GET", "/identity/v1/me"+e.meQ(), live, nil, 200)
	for name, token := range map[string]string{"current-before": current, "other": other, "stale": stale} {
		if r := e.Do("GET", "/identity/v1/me"+e.meQ(), token, nil); r.Status != 401 {
			t.Fatalf("%s session still works: %d", name, r.Status)
		}
	}
	e.Must("POST", "/identity/v1/refresh", "", e.refreshBody(e.Org, otherLogin["refresh_token"].(string)), 401)
	e.Must("GET", "/identity/v1/me"+e.meQ(), bobToken, nil, 200)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 401)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, fresh), 200)

	var method string
	var count int
	if err := e.DB.Get(&count, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='user.password_changed' AND data->>'method'='self_service' AND subject_id=$2`, e.EnvID, e.Alice); err != nil || count != 1 {
		t.Fatalf("self_service events = %d %v %s", count, err, method)
	}
	e.Must("POST", url, live, fiber.Map{"current_password": fresh, "new_password": "yet another passphrase"}, 200)
}

// TestChangePasswordWithoutPassword: an account with no password gets 422.
func TestChangePasswordWithoutPassword(t *testing.T) {
	e := newEnv(t)
	token := e.Login(e.AliceEmail)
	// The rehash switch keeps the session alive (migration 009).
	tx := e.DB.MustBegin()
	tx.MustExec(`SELECT set_config('iamkit.password_rehash','on',true)`)
	tx.MustExec(`UPDATE users SET password_hash='' WHERE id=$1`, e.Alice)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r := e.Must("POST", "/identity/v1/me/password"+e.meQ(), token, fiber.Map{"current_password": e.Pass, "new_password": "a much better passphrase"}, 422)
	if !strings.Contains(r.Body, "NO_PASSWORD") {
		t.Fatalf("no password = %s", r.Body)
	}
}

// TestSwitchOrganization covers /identity/v1/refresh with
// switch_organization_id: access, methods, SSO and MFA of the target, the
// new session and the dead old refresh token.
func TestSwitchOrganization(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "beta-client")
	e.IdP.Set(idp.Client().Transport)
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	gamma := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Gamma"})
	e.Join(beta, e.Alice)
	e.Grant(beta, e.Alice, e.Res, "invoices:write")
	e.Join(gamma, e.Alice)
	e.Grant(gamma, e.Alice, e.Res, "invoices:read")
	empty := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Empty"})
	e.Join(empty, e.Alice) // member without grants on the resource

	switchTo := func(refresh, org string, want int) Response {
		body := e.refreshBody(e.Org, refresh)
		body["switch_organization_id"] = org
		return e.Must("POST", "/identity/v1/refresh", "", body, want)
	}
	login := e.loginResult(e.AliceEmail)
	old := login["refresh_token"].(string)
	oldAccess := login["access_token"].(string)

	// Not a member, unknown, and no access to the resource: refused alike.
	stranger := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Stranger"})
	for _, org := range []string{stranger, empty, "00000000-0000-4000-8000-000000000000"} {
		if r := switchTo(old, org, 403); strings.Contains(r.Body, "REAUTHENTICATION_REQUIRED") {
			t.Fatalf("no access answered %s", r.Body)
		}
	}
	e.Must("POST", "/identity/v1/refresh", "", map[string]any{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": old, "switch_organization_id": "nope"}, 400)
	// The same organization is not a switch; a wrong token is 401.
	switchTo(old, e.Org, 400)
	switchTo("ik_refresh_nope", beta, 401)

	// Success: a new session in Beta with the same auth_time and amr.
	var before struct {
		Auth string `db:"authenticated_at"`
		AMR  string `db:"amr"`
		ID   string `db:"id"`
	}
	if err := e.DB.Get(&before, `SELECT id,authenticated_at::text,amr::text FROM sessions WHERE user_id=$1 AND organization_id=$2 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, e.Alice, e.Org); err != nil {
		t.Fatal(err)
	}
	moved := switchTo(old, beta, 200).JSON
	if moved["access_token"] == nil || moved["refresh_token"] == nil || moved["refresh_token"] == old {
		t.Fatalf("switch = %v", moved)
	}
	if got := e.permissions(moved["access_token"].(string)); !equal(got, []string{"invoices:write"}) {
		t.Fatalf("permissions in Beta = %v", got)
	}
	var after struct {
		ID   string `db:"id"`
		Auth string `db:"authenticated_at"`
		AMR  string `db:"amr"`
	}
	if err := e.DB.Get(&after, `SELECT id,authenticated_at::text,amr::text FROM sessions WHERE user_id=$1 AND organization_id=$2 AND revoked_at IS NULL`, e.Alice, beta); err != nil {
		t.Fatal(err)
	}
	if after.Auth != before.Auth || after.AMR != before.AMR || after.ID == before.ID {
		t.Fatalf("session copy: before=%+v after=%+v", before, after)
	}
	// The old session and refresh token are dead; the new tokens work.
	e.Must("GET", "/identity/v1/me"+e.meQ(), oldAccess, nil, 401)
	switchTo(old, gamma, 401)
	e.Must("POST", "/identity/v1/refresh", "", e.refreshBody(e.Org, old), 401)
	e.Must("GET", "/identity/v1/me"+e.meQ(), moved["access_token"].(string), nil, 200)
	again := e.Must("POST", "/identity/v1/refresh", "", e.refreshBody(beta, moved["refresh_token"].(string)), 200).JSON
	if e.permissions(again["access_token"].(string))[0] != "invoices:write" {
		t.Fatalf("refresh in Beta = %v", again)
	}
	var events int
	if err := e.DB.Get(&events, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='user.organization_switched' AND data->>'from'=$2 AND data->>'to'=$3`, e.EnvID, e.Org, beta); err != nil || events != 1 {
		t.Fatalf("switched events = %d %v", events, err)
	}

	// Impersonated sessions never switch.
	imp := e.Must("POST", e.Base+"/impersonations", e.Owner, fiber.Map{"user_id": e.Alice, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "reason": "support ticket 42"}, 200).JSON
	if rt, _ := imp["refresh_token"].(string); rt != "" {
		switchTo(rt, gamma, 403)
	}

	// MFA required by the target while the session has no second factor.
	e.Must("PATCH", e.Base+"/organizations/"+gamma, e.Owner, fiber.Map{"mfa_required": true}, 204)
	fresh := e.loginResult(e.AliceEmail)["refresh_token"].(string)
	r := switchTo(fresh, gamma, 403)
	needs := errorOf(r)["details"].(map[string]any)
	if errorOf(r)["code"] != "REAUTHENTICATION_REQUIRED" || needs["reason"] != "mfa" || needs["organization_id"] != gamma {
		t.Fatalf("mfa switch = %s", r.Body)
	}
	e.Must("POST", "/identity/v1/refresh", "", e.refreshBody(e.Org, fresh), 200) // refused switches keep the token

	// The target does not allow the session's method.
	e.Must("PATCH", e.Base+"/organizations/"+gamma, e.Owner, fiber.Map{"mfa_required": false}, 204)
	e.Must("PATCH", e.Base+"/organizations/"+gamma, e.Owner, fiber.Map{"allow_password": false}, 204)
	fresh = e.loginResult(e.AliceEmail)["refresh_token"].(string)
	r = switchTo(fresh, gamma, 403)
	if needs = errorOf(r)["details"].(map[string]any); needs["reason"] != "method" {
		t.Fatalf("method switch = %s", r.Body)
	}
	e.Must("PATCH", e.Base+"/organizations/"+gamma, e.Owner, fiber.Map{"allow_password": true}, 204)

	// The target enforces single sign-on for the user's domain.
	connections := e.Base + "/federation-connections"
	conn := e.ID("POST", connections, fiber.Map{"organization_id": gamma, "name": "Gamma", "issuer": idp.URL, "client_id": "beta-client", "client_secret": "sealed-secret"})
	domain := e.ID("POST", e.Base+"/organizations/"+gamma+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+gamma+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	fresh = e.loginResult(e.AliceEmail)["refresh_token"].(string)
	r = switchTo(fresh, gamma, 403)
	if needs = errorOf(r)["details"].(map[string]any); errorOf(r)["code"] != "REAUTHENTICATION_REQUIRED" || needs["reason"] != "sso" || needs["organization_id"] != gamma {
		t.Fatalf("sso switch = %s", r.Body)
	}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "optional"}, 204)
	switchTo(fresh, gamma, 200)
}

// TestSwitchOrganizationKeepsSingleLogout: the copy keeps the session's
// single-logout links (identity provider and SAML applications), and ending
// the switched-away session notifies no application.
func TestSwitchOrganizationKeepsSingleLogout(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "beta-client")
	e.IdP.Set(idp.Client().Transport)
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, e.Alice)
	e.Grant(beta, e.Alice, e.Res, "invoices:read")
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Alpha", "issuer": idp.URL, "client_id": "beta-client", "client_secret": "sealed-secret"})
	sp := samltest.New("https://soap.example.com/saml", "https://soap.example.com/acs")
	provider := e.ID("POST", e.Base+"/saml/service-providers", fiber.Map{"name": "Soap", "application_id": e.Client, "resource_id": e.Res, "entity_id": "https://soap.example.com/saml", "acs_urls": []string{"https://soap.example.com/acs"}, "certificate": sp.Certificate(), "slo_soap_url": "https://soap.example.com/soap"})

	refresh := e.loginResult(e.AliceEmail)["refresh_token"].(string)
	live := func() string {
		t.Helper()
		var id string
		if err := e.DB.Get(&id, `SELECT id FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND parent_session_id IS NULL ORDER BY created_at DESC LIMIT 1`, e.Alice); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := live()
	e.DB.MustExec(`INSERT INTO federation_sessions (session_id, environment_id, connection_id, name_id, session_index) VALUES ($1,$2,$3,$4,'idx-1')`, old, e.EnvID, conn, e.AliceEmail)
	e.DB.MustExec(`INSERT INTO saml_idp_sessions (session_id, service_provider_id, environment_id, name_id) VALUES ($1,$2,$3,$4)`, old, provider, e.EnvID, e.AliceEmail)

	body := e.refreshBody(e.Org, refresh)
	body["switch_organization_id"] = beta
	e.Must("POST", "/identity/v1/refresh", "", body, 200)
	next := live()
	if next == old {
		t.Fatal("switch kept the old session")
	}
	count := func(query string, args ...any) (n int) {
		t.Helper()
		if err := e.DB.Get(&n, query, args...); err != nil {
			t.Fatal(err)
		}
		return
	}
	if n := count(`SELECT count(*) FROM federation_sessions WHERE session_id=$1 AND connection_id=$2 AND session_index='idx-1'`, next, conn); n != 1 {
		t.Fatalf("identity provider link of the new session = %d", n)
	}
	if n := count(`SELECT count(*) FROM saml_idp_sessions WHERE session_id=$1 AND service_provider_id=$2`, next, provider); n != 1 {
		t.Fatalf("application link of the new session = %d", n)
	}
	if n := count(`SELECT count(*) FROM saml_logout_notifications`); n != 0 {
		t.Fatalf("switch queued %d back-channel logouts", n)
	}
	// Ending the new session still tells the application.
	e.Must("POST", e.Base+"/users/"+e.Alice+"/revoke-sessions", e.Owner, nil, 200)
	if n := count(`SELECT count(*) FROM saml_logout_notifications WHERE session_id=$1 AND service_provider_id=$2`, next, provider); n != 1 {
		t.Fatalf("revoking the switched session queued %d notifications", n)
	}
}
