package e2e_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/gofiber/fiber/v2"
)

// fakeBreaches reports the passwords in breached as known breaches.
type fakeBreaches struct {
	mu       sync.Mutex
	breached map[string]bool
	asked    int
}

func (f *fakeBreaches) Breached(_ context.Context, password string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	return f.breached[password], nil
}

func errorOf(r Response) map[string]any {
	out, _ := r.JSON["error"].(map[string]any)
	return out
}

func ruleOf(r Response) string {
	e := errorOf(r)
	details, _ := e["details"].(map[string]any)
	if e["code"] != "PASSWORD_POLICY" {
		return ""
	}
	rule, _ := details["rule"].(string)
	return rule
}

// TestPasswordPolicyJourney covers the environment password policy: CRUD
// and audit, composition and breach checks on every way a password is
// set, counted failures and lockout with operator unlock, and expiry for
// headless and hosted sign-in (after the second factor).
func TestPasswordPolicyJourney(t *testing.T) {
	breaches := &fakeBreaches{breached: map[string]bool{"Breached-Password-1": true}}
	e := newEnv(t, bootstrap.WithBreaches(breaches))
	policy := e.Base + "/password-policy"

	// Default until saved; validated; audited; delete returns to default.
	got := e.Must("GET", policy, e.Owner, nil, 200).JSON
	if got["custom"] != false || got["min_length"] != float64(12) || got["lockout_threshold"] != float64(0) {
		t.Fatalf("default policy = %v", got)
	}
	e.Must("PUT", policy, e.Owner, fiber.Map{"min_length": 7, "lockout_minutes": 15}, 400)
	e.Must("PUT", policy, e.Owner, fiber.Map{"min_length": 12, "lockout_minutes": 0}, 400)
	strict := fiber.Map{"min_length": 14, "require_upper": true, "require_lower": true, "require_digit": true, "require_symbol": true,
		"lockout_threshold": 3, "lockout_minutes": 10, "breach_check": true}
	got = e.Must("PUT", policy, e.Owner, strict, 200).JSON
	if got["custom"] != true || got["min_length"] != float64(14) {
		t.Fatalf("saved policy = %v", got)
	}
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action='password_policy.update'`, e.EnvID)
	if audits != 1 {
		t.Fatalf("policy update audits = %d", audits)
	}

	// New passwords follow it everywhere: user creation...
	user := func(password string) Response {
		return e.Do("POST", e.Base+"/users", e.Owner, fiber.Map{"name": "Bob", "email": "bob@example.com", "password": password})
	}
	for password, want := range map[string]string{"Sh0rt!": "length", "no-upper-case-12": "upper", "No-Digits-Here-Now": "digit", "NoSymbols12345678": "symbol", "Breached-Password-1": "breached"} {
		if r := user(password); r.Status != 400 || ruleOf(r) != want {
			t.Fatalf("%q: %d %s, want rule %s", password, r.Status, r.Body, want)
		}
	}
	bob := user("Strong-Password-1")
	if bob.Status != 201 {
		t.Fatalf("strong password refused: %s", bob.Body)
	}
	// ...and the password reset.
	reset := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": "bob@example.com", "purpose": "password_reset"}, 202).JSON
	mail, _ := e.Mail.Last("password_reset")
	verify := fiber.Map{"environment_id": e.EnvID, "challenge_id": reset["challenge_id"], "purpose": "password_reset", "code": mail.Code, "password": "weak password without capitals"}
	if r := e.Do("POST", "/identity/v1/challenges/verify", "", verify); r.Status != 400 || ruleOf(r) != "upper" {
		t.Fatalf("weak reset: %d %s", r.Status, r.Body)
	}

	// Lockout: wrong passwords lock after 3; a locked account refuses the
	// right password with the same answer; the operator unlocks it.
	bobID := bob.JSON["id"].(string)
	e.Join(e.Org, bobID)
	e.Grant(e.Org, bobID, e.Res, "invoices:read")
	wrong := e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Wrong-Password-1"), 401)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Wrong-Password-1"), 401)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Wrong-Password-1"), 401)
	locked := e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Strong-Password-1"), 401)
	if errorOf(locked)["message"] != errorOf(wrong)["message"] || errorOf(locked)["code"] != errorOf(wrong)["code"] {
		t.Fatalf("lockout is distinguishable: %s vs %s", locked.Body, wrong.Body)
	}
	if e.audited("user.locked", bobID) != 1 {
		t.Fatal("lockout not audited")
	}
	shown := e.Must("GET", e.Base+"/users/"+bobID, e.Owner, nil, 200).JSON
	if shown["failed_logins"] != float64(3) || shown["locked_until"] == nil {
		t.Fatalf("user = %v", shown)
	}
	e.Must("POST", e.Base+"/users/"+bobID+"/unlock", e.Owner, nil, 204)
	if e.audited("user.unlocked", e.Base+"/users/"+bobID+"/unlock") != 1 {
		t.Fatal("unlock not audited")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Strong-Password-1"), 200)
	// /api/v1 unlock needs iam:users:write.
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/users/"+bobID+"/unlock", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/users/"+bobID+"/unlock", e.scopedToken("iam:users:write"), nil, 204)

	// Expiry, headless: 403 until new_password is sent with the password;
	// the new one must follow the policy and differ from the current one.
	strict["max_age_days"] = 30
	e.Must("PUT", policy, e.Owner, strict, 200)
	e.DB.MustExec(`UPDATE users SET password_changed_at=now()-interval '31 days' WHERE id=$1`, bobID)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Strong-Password-1"), 403); errorOf(r)["code"] != "PASSWORD_CHANGE_REQUIRED" {
		t.Fatalf("expired: %s", r.Body)
	}
	body := e.LoginBody("bob@example.com", "Strong-Password-1")
	body["new_password"] = "Strong-Password-1"
	if r := e.Must("POST", "/identity/v1/login", "", body, 400); ruleOf(r) != "reused" {
		t.Fatalf("reused: %s", r.Body)
	}
	body["new_password"] = "Newer-Password-22"
	e.Must("POST", "/identity/v1/login", "", body, 200)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Newer-Password-22"), 200)
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Strong-Password-1"), 401)

	// Expiry, hosted: the password page leads to the new-password page,
	// which rejects policy failures in the page's language, then finishes.
	e.DB.MustExec(`UPDATE users SET password_changed_at=now()-interval '31 days' WHERE id=$1`, bobID)
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	expired := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {"bob@example.com"}, "password": {"Newer-Password-22"}})
	if expired.Status != 200 || !strings.Contains(expired.Body, `action="/hosted/login/password/new"`) {
		t.Fatalf("hosted expired: %d %s", expired.Status, expired.Body)
	}
	if p := b.post("/hosted/login/password/new", url.Values{"ticket": {tk}, "password": {"short"}}); p.Status != 400 || !strings.Contains(p.Body, "must be 14 to 72 characters") {
		t.Fatalf("hosted weak password: %d %s", p.Status, p.Body)
	}
	tokens := b.exchange(client, b.post("/hosted/login/password/new", url.Values{"ticket": {tk}, "password": {"Hosted-Password-33"}}))
	if claims(t, tokens["access_token"].(string))["sub"] != bobID {
		t.Fatal("hosted change signed in the wrong user")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "Hosted-Password-33"), 200)

	// Expiry with a second factor: the new password is applied only once
	// the code passes.
	e.DB.MustExec(`UPDATE users SET password_changed_at=now()-interval '31 days' WHERE id=$1`, bobID)
	access := e.Must("POST", "/identity/v1/login", "", func() fiber.Map {
		m := e.LoginBody("bob@example.com", "Hosted-Password-33")
		m["new_password"] = "Mfa-Changed-Pass-44"
		return m
	}(), 200).JSON["access_token"].(string)
	self := func(path string, body fiber.Map, want int) Response {
		body["environment_id"], body["audience"] = e.EnvID, e.Audience
		return e.Must("POST", path, access, body, want)
	}
	secret := self("/identity/v1/me/factors/totp", fiber.Map{}, 201).JSON["secret"].(string)
	self("/identity/v1/me/factors/totp/confirm", fiber.Map{"code": totp(t, secret, 0)}, 200)
	e.DB.MustExec(`UPDATE users SET password_changed_at=now()-interval '31 days' WHERE id=$1`, bobID)
	body = e.LoginBody("bob@example.com", "Mfa-Changed-Pass-44")
	body["new_password"] = "After-Second-Factor-5"
	pending := e.Must("POST", "/identity/v1/login", "", body, 200).JSON
	if pending["mfa_required"] != true {
		t.Fatalf("want second factor: %v", pending)
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "After-Second-Factor-5"), 401)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": pending["mfa_token"], "code": totp(t, secret, 1)}, 200)
	var changed time.Time
	e.DB.Get(&changed, `SELECT password_changed_at FROM users WHERE id=$1`, bobID)
	if time.Since(changed) > time.Minute {
		t.Fatalf("password_changed_at not updated: %v", changed)
	}
	if r := e.Do("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", "After-Second-Factor-5")); r.JSON["mfa_required"] != true {
		t.Fatalf("new password after mfa: %d %s", r.Status, r.Body)
	}

	// Invitation acceptance follows the policy too.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "carol@example.com"}, 201).JSON["token"].(string)
	if r := e.Do("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv, "password": "all lowercase password 1!"}); r.Status != 400 || ruleOf(r) != "upper" {
		t.Fatalf("weak invitation password: %d %s", r.Status, r.Body)
	}
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv, "password": "Invited-Password-6"}, 200)

	// Delete returns to the default policy; audited.
	e.Must("DELETE", policy, e.Owner, nil, 204)
	e.Must("DELETE", policy, e.Owner, nil, 404)
	if got = e.Must("GET", policy, e.Owner, nil, 200).JSON; got["custom"] != false {
		t.Fatalf("after delete = %v", got)
	}
	if breaches.asked == 0 {
		t.Fatal("breach check never ran")
	}
}
