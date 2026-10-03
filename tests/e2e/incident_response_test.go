package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestIncidentResponseUserActions covers the operator's containment
// actions for a suspicious user (F-054): sign out everywhere ends every
// live session and only those, audited with the count; require password
// change makes the next password sign-in (headless and hosted) choose a
// new password, and setting one clears it.
func TestIncidentResponseUserActions(t *testing.T) {
	e := newEnv(t)
	user := e.Base + "/users/" + e.Alice
	refresh := func(token any) fiber.Map {
		return fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "refresh_token": token}
	}

	// Two live sessions, one already revoked: only the live ones count.
	first := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON
	second := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON
	gone := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON
	e.Must("POST", "/identity/v1/logout", gone["access_token"].(string), fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 204)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	bystander := e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200).JSON

	if got := e.Must("POST", user+"/revoke-sessions", e.Owner, nil, 200).JSON["revoked"]; got != float64(2) {
		t.Fatalf("revoked = %v", got)
	}
	e.Must("POST", "/identity/v1/refresh", "", refresh(first["refresh_token"]), 401)
	e.Must("POST", "/identity/v1/refresh", "", refresh(second["refresh_token"]), 401)
	e.Must("POST", "/identity/v1/refresh", "", refresh(bystander["refresh_token"]), 200)
	if got := e.Must("POST", user+"/revoke-sessions", e.Owner, nil, 200).JSON["revoked"]; got != float64(0) {
		t.Fatalf("second revoke = %v", got)
	}
	events := e.Must("GET", e.Base+"/events?type=user.sessions_revoked&subject="+e.Alice, e.Owner, nil, 200).JSON["items"].([]any)
	if len(events) != 2 || events[1].(map[string]any)["data"].(map[string]any)["count"] != float64(2) {
		t.Fatalf("sessions_revoked events = %v", events)
	}
	e.Must("POST", e.Base+"/users/00000000-0000-0000-0000-000000000000/revoke-sessions", e.Owner, nil, 404)
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/users/"+e.Alice+"/revoke-sessions", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/users/"+bob+"/revoke-sessions", e.scopedToken("iam:users:write"), nil, 200)

	// Require a password change: shown on the user, refused for users
	// without a password, audited.
	e.Must("POST", user+"/require-password-change", e.Owner, nil, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["password_change_required"]; got != true {
		t.Fatalf("password_change_required = %v", got)
	}
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": "Deploy bot"})
	e.Must("POST", e.Base+"/users/"+bot+"/require-password-change", e.Owner, nil, 422)
	e.Must("GET", e.Base+"/events?type=user.password_change_required&subject="+e.Alice, e.Owner, nil, 200)

	// Headless: 403 until a new password comes with the current one; the
	// new password must differ; then the flag is gone.
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 403); errorOf(r)["code"] != "PASSWORD_CHANGE_REQUIRED" {
		t.Fatalf("required: %s", r.Body)
	}
	body := e.LoginBody(e.AliceEmail, e.Pass)
	body["new_password"] = e.Pass
	if r := e.Must("POST", "/identity/v1/login", "", body, 400); ruleOf(r) != "reused" {
		t.Fatalf("reused: %s", r.Body)
	}
	body["new_password"] = "a fresh correct horse"
	e.Must("POST", "/identity/v1/login", "", body, 200)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["password_change_required"]; got != false {
		t.Fatalf("flag kept after change: %v", got)
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "a fresh correct horse"), 200)

	// Hosted: the password page leads to the new-password page.
	e.Must("POST", user+"/require-password-change", e.Owner, nil, 204)
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	page := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"a fresh correct horse"}})
	if page.Status != 200 || !strings.Contains(page.Body, `action="/hosted/login/password/new"`) {
		t.Fatalf("hosted required: %d %s", page.Status, page.Body)
	}
	tokens := b.exchange(client, b.post("/hosted/login/password/new", url.Values{"ticket": {tk}, "password": {"another fresh horse"}}))
	if claims(t, tokens["access_token"].(string))["sub"] != e.Alice {
		t.Fatal("hosted change signed in the wrong user")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "another fresh horse"), 200)
}
