package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestSignInPolicyJourney covers the environment sign-in policy (methods,
// password reset, default MFA) and the organization's narrowing of it,
// headless and hosted.
func TestSignInPolicyJourney(t *testing.T) {
	e := newEnv(t)
	policy := e.Base + "/sign-in-policy"
	codeOf := func(r Response) any { return errorOf(r)["code"] }

	// Default until saved; validated; audited.
	got := e.Must("GET", policy, e.Owner, nil, 200).JSON
	if got["custom"] != false || got["allow_password"] != true || got["allow_password_reset"] != true || got["mfa_required"] != false {
		t.Fatalf("default = %v", got)
	}
	all := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true}
	e.Must("PUT", policy, e.Owner, fiber.Map{"allow_password": false, "allow_password_reset": true}, 400)

	// No password: refused before the account is looked up (unknown emails
	// get the same answer), nothing counted.
	noPassword := fiber.Map{"allow_password": false, "allow_email_code": true, "allow_social": true, "allow_password_reset": false}
	if got = e.Must("PUT", policy, e.Owner, noPassword, 200).JSON; got["custom"] != true {
		t.Fatalf("saved = %v", got)
	}
	if e.audited("sign_in_policy.update", "/environments/"+e.EnvID+"/sign-in-policy") != 1 {
		t.Fatal("update not audited")
	}
	for _, email := range []string{e.AliceEmail, "nobody@example.com"} {
		if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(email, e.Pass), 403); codeOf(r) != "METHOD_NOT_ALLOWED" {
			t.Fatalf("%s: %s", email, r.Body)
		}
	}
	if r := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "password_reset"}, 403); codeOf(r) != "PASSWORD_RESET_DISABLED" {
		t.Fatalf("reset: %s", r.Body)
	}
	// Hosted: the password step and "forgot password" disappear; posting
	// the password anyway is refused.
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	step := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if strings.Contains(step.Body, `name="password"`) || strings.Contains(step.Body, "/hosted/login/reset") || !strings.Contains(step.Body, "/hosted/login/code") {
		t.Fatalf("hosted password step: %s", step.Body)
	}
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 {
		t.Fatalf("hosted password: %d", p.Status)
	}

	// Password allowed, reset not: the link is gone and the reset refused.
	noReset := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": false}
	e.Must("PUT", policy, e.Owner, noReset, 200)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	step = b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if !strings.Contains(step.Body, `name="password"`) || strings.Contains(step.Body, "/hosted/login/reset") {
		t.Fatalf("hosted without reset: %s", step.Body)
	}
	if p := b.post("/hosted/login/reset", url.Values{"ticket": {tk}, "email": {e.AliceEmail}}); p.Status != 403 {
		t.Fatalf("hosted reset: %d", p.Status)
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200)

	// The organization narrows: Acme refuses passwords; Beta allows them.
	e.Must("PUT", policy, e.Owner, all, 200)
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"allow_password": false}, 204)
	org := e.Must("GET", e.Base+"/organizations/"+e.Org, e.Owner, nil, 200).JSON
	if org["allow_password"] != false || org["allow_email_code"] != true {
		t.Fatalf("organization = %v", org)
	}
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 403); codeOf(r) != "METHOD_NOT_ALLOWED" {
		t.Fatalf("organization refuses password: %s", r.Body)
	}
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, e.Alice)
	e.Grant(beta, e.Alice, e.Res, "invoices:read")
	// Hosted: the chooser skips Acme, so Beta signs in directly.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	tokens := b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	if claims(t, tokens["access_token"].(string))["organization_id"] != beta {
		t.Fatal("hosted password login did not skip the organization refusing it")
	}
	// Only Acme left: the method is the reason.
	e.Must("PATCH", e.Base+"/organizations/"+beta, e.Owner, fiber.Map{"allow_password": false}, 204)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 {
		t.Fatalf("hosted no organization allows password: %d %s", p.Status, p.Body)
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"allow_password": true}, 204)

	// Environment-wide MFA: a member without a factor must enroll.
	mfa := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true, "mfa_required": true}
	e.Must("PUT", policy, e.Owner, mfa, 200)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200).JSON; r["mfa_required"] != true {
		t.Fatalf("environment MFA ignored: %v", r)
	}

	// Delete returns to the default; audited.
	e.Must("DELETE", policy, e.Owner, nil, 204)
	e.Must("DELETE", policy, e.Owner, nil, 404)
	if e.audited("sign_in_policy.delete", "/environments/"+e.EnvID+"/sign-in-policy") != 1 {
		t.Fatal("delete not audited")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200)
}

// TestOrganizationPasswordPolicy: an organization tightens the environment
// policy for its members' new passwords and their expiry; users outside it
// keep the environment's.
func TestOrganizationPasswordPolicy(t *testing.T) {
	e := newEnv(t)
	orgPolicy := e.Base + "/organizations/" + e.Org + "/password-policy"

	got := e.Must("GET", orgPolicy, e.Owner, nil, 200).JSON
	if got["custom"] != false || got["min_length"] != float64(0) {
		t.Fatalf("default = %v", got)
	}
	e.Must("GET", e.Base+"/organizations/00000000-0000-4000-8000-000000000000/password-policy", e.Owner, nil, 404)
	e.Must("PUT", orgPolicy, e.Owner, fiber.Map{"min_length": 7}, 400)
	strict := fiber.Map{"min_length": 16, "require_symbol": true, "max_age_days": 30}
	if got = e.Must("PUT", orgPolicy, e.Owner, strict, 200).JSON; got["custom"] != true || got["min_length"] != float64(16) {
		t.Fatalf("saved = %v", got)
	}
	if e.audited("organization_password_policy.update", "/environments/"+e.EnvID+"/organizations/"+e.Org+"/password-policy") != 1 {
		t.Fatal("update not audited")
	}

	// Reset: Alice (Acme member) must meet Acme's rules; Bob (no
	// organization) only the environment's.
	reset := func(email, password string) Response {
		r := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": email, "purpose": "password_reset"}, 202).JSON
		mail, _ := e.Mail.Last("password_reset")
		return e.Do("POST", "/identity/v1/challenges/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": r["challenge_id"], "purpose": "password_reset", "code": mail.Code, "password": password})
	}
	if r := reset(e.AliceEmail, "twelve chars ok"); r.Status != 400 || ruleOf(r) != "length" {
		t.Fatalf("member reset: %d %s", r.Status, r.Body)
	}
	if r := reset(e.AliceEmail, "sixteen chars no symbol"); r.Status != 400 || ruleOf(r) != "symbol" {
		t.Fatalf("member reset symbol: %d %s", r.Status, r.Body)
	}
	if r := reset(e.AliceEmail, "sixteen chars & symbol"); r.Status != 204 && r.Status != 200 {
		t.Fatalf("member reset ok: %d %s", r.Status, r.Body)
	}
	e.User("Bob", "bob@example.com")
	if r := reset("bob@example.com", "twelve chars ok"); r.Status != 204 && r.Status != 200 {
		t.Fatalf("non-member reset: %d %s", r.Status, r.Body)
	}

	// Expiry: Acme's 30 days apply to Alice though the environment has none.
	e.DB.MustExec(`UPDATE users SET password_changed_at=now()-interval '31 days' WHERE id=$1`, e.Alice)
	if r := e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "sixteen chars & symbol"), 403); errorOf(r)["code"] != "PASSWORD_CHANGE_REQUIRED" {
		t.Fatalf("member expiry: %s", r.Body)
	}
	body := e.LoginBody(e.AliceEmail, "sixteen chars & symbol")
	body["new_password"] = "too short now!"
	if r := e.Must("POST", "/identity/v1/login", "", body, 400); ruleOf(r) != "length" {
		t.Fatalf("member expiry change: %s", r.Body)
	}
	body["new_password"] = "a newer sixteen+ password"
	e.Must("POST", "/identity/v1/login", "", body, 200)

	// Invitation into Acme: a new account follows Acme's rules.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "carol@example.com"}, 201).JSON["token"].(string)
	if r := e.Do("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv, "password": "twelve chars ok"}); r.Status != 400 || ruleOf(r) != "length" {
		t.Fatalf("invitation: %d %s", r.Status, r.Body)
	}
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv, "password": "invited & sixteen chars"}, 200)

	// Delete: the member follows the environment again.
	e.Must("DELETE", orgPolicy, e.Owner, nil, 204)
	e.Must("DELETE", orgPolicy, e.Owner, nil, 404)
	if r := reset(e.AliceEmail, "twelve chars ok"); r.Status != 204 && r.Status != 200 {
		t.Fatalf("after delete: %d %s", r.Status, r.Body)
	}
}
