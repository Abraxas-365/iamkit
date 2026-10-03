package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestSignupJourney covers self-registration: the settings, the headless
// API (never revealing existing accounts, verification before the account
// exists) and the hosted "Create account" pages.
func TestSignupJourney(t *testing.T) {
	e := newEnv(t)
	policy := e.Base + "/sign-in-policy"
	codeOf := func(r Response) any { return errorOf(r)["code"] }
	signup := func(email, name, password string) Response {
		return e.Do("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": email, "name": name, "password": password})
	}
	verify := func(challenge any, code string) Response {
		return e.Do("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": challenge, "code": code})
	}
	lastCode := func() string {
		m, ok := e.Mail.Last("email_verification")
		if !ok {
			t.Fatal("no verification email")
		}
		return m.Code
	}
	sent := func() int {
		n := 0
		for _, m := range e.Mail.Sent {
			if m.Purpose == "email_verification" {
				n++
			}
		}
		return n
	}

	// Off by default: refused before anything is looked up.
	if got := e.Must("GET", policy, e.Owner, nil, 200).JSON; got["allow_signup"] != false || got["signup_organization_id"] != "" {
		t.Fatalf("default = %v", got)
	}
	if r := signup("new@example.com", "New", "a long enough password"); r.Status != 403 || codeOf(r) != "SIGNUP_DISABLED" {
		t.Fatalf("disabled: %d %s", r.Status, r.Body)
	}

	// Settings: an organization of this environment is required; the group
	// must belong to it.
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Customers"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Other"})
	all := func(extra fiber.Map) fiber.Map {
		m := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": true}), 400)
	e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": true, "signup_organization_id": "00000000-0000-4000-8000-000000000000"}), 400)
	e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": true, "signup_organization_id": other, "signup_group_id": group}), 400)
	got := e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": true, "signup_organization_id": e.Org, "signup_group_id": group}), 200).JSON
	if got["allow_signup"] != true || got["signup_organization_id"] != e.Org || got["signup_group_id"] != group {
		t.Fatalf("saved = %v", got)
	}

	// Validation and the password policy apply before anything is sent.
	if r := signup("new@example.com", "", "a long enough password"); r.Status != 400 {
		t.Fatalf("no name: %d %s", r.Status, r.Body)
	}
	if r := signup("new@example.com", "New", "short"); r.Status != 400 || codeOf(r) != "PASSWORD_POLICY" {
		t.Fatalf("weak password: %d %s", r.Status, r.Body)
	}

	// An existing account: the same answer, nothing sent.
	before := sent()
	r := signup(e.AliceEmail, "Alice again", "a long enough password")
	if r.Status != 202 || r.JSON["challenge_id"] == "" || sent() != before {
		t.Fatalf("existing: %d %s sent=%d", r.Status, r.Body, sent()-before)
	}
	if v := verify(r.JSON["challenge_id"], "12345678"); v.Status != 401 {
		t.Fatalf("existing verify: %d %s", v.Status, v.Body)
	}

	// A new email: code, then the account exists in Acme and the group.
	r = e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "New@Example.com", "name": "New Person", "password": "a long enough password"}, 202)
	challenge := r.JSON["challenge_id"]
	code := lastCode()
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='new@example.com'`); n != 0 {
		t.Fatal("account exists before verification")
	}
	if v := verify(challenge, "00000000"); v.Status != 401 {
		t.Fatalf("wrong code: %d", v.Status)
	}
	done := e.Must("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": challenge, "code": code}, 201).JSON
	user, _ := done["user_id"].(string)
	if user == "" || done["organization_id"] != e.Org || done["email"] != "new@example.com" || done["access_token"] != nil {
		t.Fatalf("signed up = %v", done)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND email_verified AND name='New Person' AND NOT otp_enabled`, user); n != 1 {
		t.Fatal("user not created as verified")
	}
	if n := count(t, e.DB, `SELECT count(*) FROM group_members WHERE group_id=$1 AND user_id=$2`, group, user); n != 1 {
		t.Fatal("not in the sign-up group")
	}
	if e.audited("user.signup", "/users/"+user) != 1 {
		t.Fatal("sign-up not audited")
	}
	if v := verify(challenge, code); v.Status != 401 {
		t.Fatalf("replayed: %d", v.Status)
	}
	// The new user signs in and gets the group's role.
	tokens := e.Must("POST", "/identity/v1/login", "", e.LoginBody("new@example.com", "a long enough password"), 200).JSON
	if claims(t, tokens["access_token"].(string))["organization_id"] != e.Org {
		t.Fatal("new user cannot sign in to the sign-up organization")
	}

	// Five wrong codes end a sign-up; an email taken meanwhile is a
	// conflict.
	r = e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "late@example.com", "name": "Late", "password": "a long enough password"}, 202)
	late, lateCode := r.JSON["challenge_id"], lastCode()
	e.User("Late", "late@example.com")
	if v := verify(late, lateCode); v.Status != 409 || codeOf(v) != "ACCOUNT_EXISTS" {
		t.Fatalf("taken: %d %s", v.Status, v.Body)
	}
	r = e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "tries@example.com", "name": "Tries", "password": "a long enough password"}, 202)
	tries, triesCode := r.JSON["challenge_id"], lastCode()
	for range 5 {
		verify(tries, "00000000")
	}
	if v := verify(tries, triesCode); v.Status != 401 {
		t.Fatalf("after five wrong codes: %d", v.Status)
	}

	// An organization refusing passwords: passwordless sign-up only.
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"allow_password": false}, 204)
	if r = signup("nopass@example.com", "No Pass", "a long enough password"); r.Status != 400 {
		t.Fatalf("password refused: %d %s", r.Status, r.Body)
	}
	r = e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "nopass@example.com", "name": "No Pass"}, 202)
	e.Must("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": r.JSON["challenge_id"], "code": lastCode()}, 201)
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='nopass@example.com' AND password_hash='' AND otp_enabled`); n != 1 {
		t.Fatal("passwordless account not created")
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"allow_password": true}, 204)

	// Hosted: "Create account" → code → signed in to the application.
	client := e.hostedClient()
	b := e.browser()
	login := b.authorize(client)
	tk := login.field("ticket")
	if !strings.Contains(login.Body, "/hosted/signup") {
		t.Fatalf("no create-account link: %s", login.Body)
	}
	form := b.get("/hosted/signup?ticket=" + url.QueryEscape(tk))
	if form.Status != 200 || !strings.Contains(form.Body, `name="name"`) {
		t.Fatalf("signup page: %d %s", form.Status, form.Body)
	}
	step := b.post("/hosted/signup", url.Values{"ticket": {tk}, "email": {"hosted@example.com"}, "name": {"Hosted"}, "password": {"a long enough password"}})
	if step.Status != 200 || step.field("challenge_id") == "" {
		t.Fatalf("hosted signup: %d %s", step.Status, step.Body)
	}
	finished := b.post("/hosted/signup/verify", url.Values{"ticket": {tk}, "challenge_id": {step.field("challenge_id")}, "code": {lastCode()}})
	hosted := b.exchange(client, finished)
	c := claims(t, hosted["access_token"].(string))
	if c["organization_id"] != e.Org || count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND email='hosted@example.com'`, c["sub"]) != 1 {
		t.Fatalf("hosted claims = %v", c)
	}

	// Without the group granting the role: the account exists, the page
	// says access is pending.
	e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": true, "signup_organization_id": e.Org}), 200)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	step = b.post("/hosted/signup", url.Values{"ticket": {tk}, "email": {"pending@example.com"}, "name": {"Pending"}, "password": {"a long enough password"}})
	pending := b.post("/hosted/signup/verify", url.Values{"ticket": {tk}, "challenge_id": {step.field("challenge_id")}, "code": {lastCode()}})
	if pending.Status != 403 || !strings.Contains(pending.Body, "Account created") {
		t.Fatalf("no access yet: %d %s", pending.Status, pending.Body)
	}
	if count(t, e.DB, `SELECT count(*) FROM users WHERE email='pending@example.com'`) != 1 {
		t.Fatal("pending account not created")
	}

	// The console previews show what the pages offer: the environment's
	// "Create account" link, hidden for a client that hides it (saved and
	// draft previews alike, whatever methods the preview picks).
	preview := e.Base + "/login-settings/preview"
	previewed := func(method, client string) string {
		if method == "GET" {
			return e.Must("GET", preview+"?client="+client, e.Owner, nil, 200).JSON["html"].(string)
		}
		body := fiber.Map{"settings": fiber.Map{}, "sign_in": fiber.Map{"password": true}}
		if client != "" {
			body["client_id"] = client
		}
		return e.Must("POST", preview, e.Owner, body, 200).JSON["html"].(string)
	}
	for _, method := range []string{"GET", "POST"} {
		if !strings.Contains(previewed(method, ""), "/hosted/signup") {
			t.Fatalf("%s preview: no sign-up link with sign-up on", method)
		}
	}

	// The client can hide it; turning sign-up off hides it everywhere.
	e.Must("PUT", e.Base+"/login-settings/clients/"+client+"/sign-in", e.Owner, fiber.Map{"password": true, "email_code": true, "organization_sso": true, "all_connections": true, "signup": false}, 200)
	for _, method := range []string{"GET", "POST"} {
		if strings.Contains(previewed(method, client), "/hosted/signup") || !strings.Contains(previewed(method, ""), "/hosted/signup") {
			t.Fatalf("%s preview: the client's hidden link", method)
		}
	}
	b = e.browser()
	login = b.authorize(client)
	if strings.Contains(login.Body, "/hosted/signup") {
		t.Fatal("hidden link still shown")
	}
	if p := b.post("/hosted/signup", url.Values{"ticket": {login.field("ticket")}, "email": {"x@example.com"}, "name": {"X"}, "password": {"a long enough password"}}); p.Status != 403 {
		t.Fatalf("hidden signup posted: %d", p.Status)
	}
	e.Must("DELETE", e.Base+"/login-settings/clients/"+client+"/sign-in", e.Owner, nil, 204)
	e.Must("PUT", policy, e.Owner, all(fiber.Map{"allow_signup": false, "signup_organization_id": e.Org}), 200)
	b = e.browser()
	if login = b.authorize(client); strings.Contains(login.Body, "/hosted/signup") {
		t.Fatal("link shown with sign-up off")
	}
	if strings.Contains(previewed("GET", ""), "/hosted/signup") {
		t.Fatal("preview: sign-up link with sign-up off")
	}
	if r = signup("off@example.com", "Off", "a long enough password"); codeOf(r) != "SIGNUP_DISABLED" {
		t.Fatalf("off again: %d %s", r.Status, r.Body)
	}
}
