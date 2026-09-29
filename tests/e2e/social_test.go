package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestSocialLogin covers environment connections used as social login:
// sign-up of unknown verified emails, linking to existing accounts by
// verified email, the SSO enforcement of the user's organization, and the
// per-client sign-in options of the hosted pages.
func TestSocialLogin(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "social-client")
	e.IdP.Set(idp.Client().Transport)
	connections := e.Base + "/federation-connections"
	client := e.hostedClient()

	// Sign-up needs an organization of the environment; organization
	// connections cannot sign up or link.
	e.Must("POST", connections, e.Owner, fiber.Map{"name": "Social", "issuer": idp.URL, "client_id": "social-client", "client_secret": "sealed-secret", "signup": true}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Org", "issuer": idp.URL, "client_id": "social-client", "client_secret": "sealed-secret", "signup": true, "signup_organization_id": e.Org}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"name": "Social", "provider": "google", "issuer": idp.URL, "client_id": "social-client", "client_secret": "x"}, 400)
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Customers"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	conn := e.ID("POST", connections, fiber.Map{"name": "Social", "issuer": idp.URL, "client_id": "social-client", "client_secret": "sealed-secret",
		"signup": true, "signup_organization_id": e.Org, "signup_group_id": group, "link_email": true})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	if detail["provider"] != "oidc" || detail["signup"] != true || detail["link_email"] != true || detail["signup_group_id"] != group || detail["callback_url"] != "https://iam.example/identity/v1/federation/callback" {
		t.Fatalf("detail = %v", detail)
	}

	// Unknown verified email: an account in the sign-up organization and
	// group, with access at once.
	dave := e.sso(idp, conn, e.Org, map[string]any{"sub": "dave-sub", "email": "Dave@Example.net", "email_verified": true, "name": "Dave"})
	if dave.Status != 200 || !equal(e.permissions(dave.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("signup: %d %v", dave.Status, dave.JSON)
	}
	var origin string
	if err := e.DB.Get(&origin, `SELECT x.origin FROM external_identities x JOIN users u ON u.id=x.user_id WHERE x.connection_id=$1 AND u.email='dave@example.net' AND u.email_verified AND u.password_hash=''`, conn); err != nil || origin != "signup" {
		t.Fatalf("signup identity: %q %v", origin, err)
	}
	// The same subject signs in again without a second account.
	if again := e.sso(idp, conn, e.Org, map[string]any{"sub": "dave-sub", "email": "other@example.net", "email_verified": true}); again.Status != 200 {
		t.Fatalf("returning user: %d %v", again.Status, again.JSON)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE environment_id=$1 AND email LIKE '%example.net'`, e.EnvID); n != 1 {
		t.Fatalf("users = %d", n)
	}

	// Unverified email: never a sign-up nor a link.
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "eve-sub", "email": "eve@example.net"}); r.Status != 401 {
		t.Fatalf("unverified: %d %v", r.Status, r.JSON)
	}
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "mallory-sub", "email": e.AliceEmail, "email_verified": false}); r.Status != 401 {
		t.Fatalf("unverified link: %d %v", r.Status, r.JSON)
	}

	// Existing account with the same verified email: linked, keeps its
	// password and access.
	alice := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-google", "email": e.AliceEmail, "email_verified": true})
	if alice.Status != 200 || claims(t, alice.JSON["access_token"].(string))["sub"] != e.Alice {
		t.Fatalf("link: %d %v", alice.Status, alice.JSON)
	}
	if err := e.DB.Get(&origin, `SELECT origin FROM external_identities WHERE connection_id=$1 AND user_id=$2`, conn, e.Alice); err != nil || origin != "email" {
		t.Fatalf("link identity: %q %v", origin, err)
	}
	e.Login(e.AliceEmail)

	// Linking off: an existing account is not taken over.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"link_email": false}, 204)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "bob-google", "email": "bob@example.com", "email_verified": true}); r.Status != 401 || r.JSON["error"].(map[string]any)["code"] != "ACCOUNT_EXISTS" {
		t.Fatalf("no link: %d %v", r.Status, r.JSON)
	}

	// Sign-up off: unknown emails are refused.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"signup": false}, 204)
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "fay-sub", "email": "fay@example.net", "email_verified": true}); r.Status != 401 {
		t.Fatalf("no signup: %d %v", r.Status, r.JSON)
	}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"link_email": true}, 204)

	// A social login does not bypass the organization's enforced SSO.
	orgIdP := newFakeIdP(t, e.Key, "acme-client")
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	orgConn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": orgIdP.URL, "client_id": "acme-client", "client_secret": "sealed-secret", "enforcement": "enforced"})
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-google", "email": e.AliceEmail, "email_verified": true}); r.Status != 403 || r.JSON["error"].(map[string]any)["code"] != "SSO_REQUIRED" {
		t.Fatalf("social under enforcement: %d %v", r.Status, r.JSON)
	}
	e.Must("PATCH", connections+"/"+orgConn, e.Owner, fiber.Map{"enforcement": "optional"}, 204)

	// Hosted pages: the connection is a button; the client's sign-in
	// options hide methods and refuse them on submit.
	b := e.browser()
	login := b.authorize(client)
	if !strings.Contains(login.Body, "Continue with Social") || !strings.Contains(login.Body, `name="email"`) {
		t.Fatalf("default page: %s", login.Body)
	}
	signIn := e.Base + "/login-settings/clients/" + client + "/sign-in"
	if d := e.Must("GET", signIn, e.Owner, nil, 200).JSON; d["custom"] != false || d["password"] != true || d["all_connections"] != true {
		t.Fatalf("default options = %v", d)
	}
	e.Must("PUT", signIn, e.Owner, fiber.Map{}, 400)
	e.Must("PUT", signIn, e.Owner, fiber.Map{"connection_ids": []string{orgConn}}, 400)
	e.Must("PUT", e.Base+"/login-settings/clients/"+e.ID("POST", e.Base+"/applications", fiber.Map{"name": "Unrelated"})+"/sign-in", e.Owner, fiber.Map{"password": true}, 404)
	saved := e.Must("PUT", signIn, e.Owner, fiber.Map{"connection_ids": []string{conn}}, 200).JSON
	if saved["custom"] != true || saved["password"] != false || len(saved["connection_ids"].([]any)) != 1 {
		t.Fatalf("saved = %v", saved)
	}
	if l := e.Must("GET", e.Base+"/login-settings/sign-in", e.Owner, nil, 200).JSON["items"].([]any); len(l) != 1 || l[0].(map[string]any)["client_id"] != client {
		t.Fatalf("listed = %v", l)
	}
	if e.audited("PUT", "/management/v1/environments/"+e.EnvID+"/login-settings/clients/"+client+"/sign-in") != 1 {
		t.Fatal("sign-in options not audited")
	}
	b = e.browser()
	login = b.authorize(client)
	tk := login.field("ticket")
	if strings.Contains(login.Body, `name="email"`) || !strings.Contains(login.Body, "Continue with Social") {
		t.Fatalf("connections-only page: %s", login.Body)
	}
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 {
		t.Fatalf("password must be refused: %d", p.Status)
	}
	redirect := b.post("/hosted/login/sso", url.Values{"ticket": {tk}, "connection_id": {conn}})
	if redirect.Status != 303 || !strings.HasPrefix(redirect.Location, idp.URL+"/authorize") {
		t.Fatalf("social start: %d %q %s", redirect.Status, redirect.Location, redirect.Body)
	}
	tokens := b.exchange(client, b.federate(idp, redirect.Location, map[string]any{"sub": "alice-google", "email": e.AliceEmail, "email_verified": true}))
	if claims(t, tokens["access_token"].(string))["sub"] != e.Alice {
		t.Fatal("hosted social login signed in the wrong user")
	}
	e.Must("DELETE", signIn, e.Owner, nil, 204)
	e.Must("DELETE", signIn, e.Owner, nil, 404)
	if !strings.Contains(e.browser().authorize(client).Body, `name="email"`) {
		t.Fatal("reset client must offer every method")
	}
}
