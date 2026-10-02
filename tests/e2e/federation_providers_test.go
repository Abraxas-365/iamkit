package e2e_test

import (
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestMoreFederationProviders covers the providers and linking options of
// migration 030: a generic OAuth 2.0 connection whose claim mapping decides
// what is verified, profile refresh on sign-in, organization connections
// that link existing members by email without JIT, and the GitLab / GitHub
// Enterprise presets.
func TestMoreFederationProviders(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "oauth-client")
	e.IdP.Set(idp.Client().Transport)
	connections := e.Base + "/federation-connections"

	// OAuth 2.0: endpoints and a claim mapping are required.
	options := fiber.Map{"authorize_url": idp.URL + "/authorize", "token_url": idp.URL + "/token", "userinfo_url": idp.URL + "/me", "scopes": []string{"identify", "email"},
		"claims": fiber.Map{"subject": "user.sub", "email": "user.email", "name": "user.name"}}
	e.Must("POST", connections, e.Owner, fiber.Map{"provider": "oauth2", "name": "Chat", "client_id": "oauth-client", "client_secret": "sealed-secret",
		"options": fiber.Map{"authorize_url": idp.URL + "/authorize", "token_url": idp.URL + "/token", "userinfo_url": idp.URL + "/me"}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"provider": "oauth2", "name": "Chat", "client_id": "oauth-client", "client_secret": "sealed-secret", "issuer": "https://other.example", "options": options}, 400)
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Chatters"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	conn := e.ID("POST", connections, fiber.Map{"provider": "oauth2", "name": "Chat", "client_id": "oauth-client", "client_secret": "sealed-secret", "options": options,
		"signup": true, "signup_organization_id": e.Org, "signup_group_id": group, "link_email": true})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	if detail["provider"] != "oauth2" || detail["issuer"] != idp.URL || detail["update_profile"] != false || detail["options"].(map[string]any)["claims"].(map[string]any)["subject"] != "user.sub" {
		t.Fatalf("detail = %v", detail)
	}

	// Without an email_verified mapping the email is never trusted: no
	// sign-up and no link, whatever the provider says.
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": "dana@example.net", "email_verified": true, "name": "Dana"}); r.Status != 401 {
		t.Fatalf("unmapped verification: %d %v", r.Status, r.JSON)
	}
	options["claims"] = fiber.Map{"subject": "user.sub", "email": "user.email", "email_verified": "user.email_verified", "name": "user.name", "picture": "user.picture"}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": options}, 204)
	moved := fiber.Map{"authorize_url": "https://elsewhere.example/authorize", "token_url": idp.URL + "/token", "userinfo_url": idp.URL + "/me", "claims": options["claims"]}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": moved}, 400)
	dana := e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": "dana@example.net", "email_verified": true, "name": "Dana"})
	if dana.Status != 200 || !equal(e.permissions(dana.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("oauth2 signup: %d %v", dana.Status, dana.JSON)
	}
	var danaID string
	if err := e.DB.Get(&danaID, `SELECT u.id FROM external_identities x JOIN users u ON u.id=x.user_id WHERE x.connection_id=$1 AND x.subject='u-1' AND u.email='dana@example.net' AND x.origin='signup'`, conn); err != nil {
		t.Fatal(err)
	}

	// Profile refresh: off by default; on, the name and the verified email
	// of a passwordless account follow the provider. A password account
	// keeps its email; an email another account has is not taken.
	e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": "dana@example.net", "email_verified": true, "name": "Dana Renamed"})
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND name='Dana'`, danaID); n != 1 {
		t.Fatal("profile refreshed while update_profile is off")
	}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"update_profile": true}, 204)
	if r := e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": "Dana.New@example.net", "email_verified": true, "name": "Dana Renamed", "picture": "https://cdn.example/dana.png"}); r.Status != 200 || claims(t, r.JSON["access_token"].(string))["sub"] != danaID {
		t.Fatalf("refresh sign-in: %d %v", r.Status, r.JSON)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND name='Dana Renamed' AND email='dana.new@example.net' AND email_verified AND avatar_url='https://cdn.example/dana.png'`, danaID); n != 1 {
		t.Fatal("profile not refreshed")
	}
	if e.audited("federation.profile_updated", "/users/"+danaID) != 1 {
		t.Fatal("profile refresh not audited")
	}
	e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": e.AliceEmail, "email_verified": true, "name": "Dana Renamed"})
	e.sso(idp, conn, e.Org, map[string]any{"sub": "u-1", "email": "unverified@example.net", "email_verified": false, "name": "Dana Renamed"})
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND email='dana.new@example.net'`, danaID); n != 1 {
		t.Fatal("refresh took another account's email or an unverified one")
	}
	alice := e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-chat", "email": e.AliceEmail, "email_verified": true, "name": "Alice"})
	if alice.Status != 200 {
		t.Fatalf("alice link: %d %v", alice.Status, alice.JSON)
	}
	e.sso(idp, conn, e.Org, map[string]any{"sub": "alice-chat", "email": "alice.other@example.net", "email_verified": true, "name": "Alice Chat"})
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE id=$1 AND email=$2 AND name='Alice Chat'`, e.Alice, e.AliceEmail); n != 1 {
		t.Fatal("a password account's email followed the provider")
	}

	// Organization connection linking by email without JIT: only existing
	// members on the organization's verified domains, never new accounts.
	orgIdP := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(orgIdP.Client().Transport)
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": orgIdP.URL, "client_id": "acme-client", "client_secret": "sealed-secret", "signup": true, "signup_organization_id": e.Org}, 400)
	orgConn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": orgIdP.URL, "client_id": "acme-client", "client_secret": "sealed-secret", "jit_provisioning": false, "link_email": true})
	if r := e.sso(orgIdP, orgConn, e.Org, map[string]any{"sub": "alice-acme", "email": e.AliceEmail}); r.Status != 200 || claims(t, r.JSON["access_token"].(string))["sub"] != e.Alice {
		t.Fatalf("member link: %d %v", r.Status, r.JSON)
	}
	var origin string
	if err := e.DB.Get(&origin, `SELECT origin FROM external_identities WHERE connection_id=$1 AND user_id=$2`, orgConn, e.Alice); err != nil || origin != "email" {
		t.Fatalf("member link origin: %q %v", origin, err)
	}
	e.User("Bob", "bob@example.com") // an account, but not a member
	for name, c := range map[string]map[string]any{
		"non-member": {"sub": "bob-acme", "email": "bob@example.com"},
		"unknown":    {"sub": "carol-acme", "email": "carol@example.com"},
		"unverified": {"sub": "x-acme", "email": e.AliceEmail, "email_verified": false},
	} {
		if r := e.sso(orgIdP, orgConn, e.Org, c); r.Status != 401 {
			t.Fatalf("%s: %d %v", name, r.Status, r.JSON)
		}
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE environment_id=$1 AND email='carol@example.com'`, e.EnvID); n != 0 {
		t.Fatal("linking without JIT created an account")
	}

	// GitLab self-managed and GitHub Enterprise presets derive the issuer
	// from base_url, which cannot change later.
	gitlab := e.ID("POST", connections, fiber.Map{"provider": "gitlab", "name": "GitLab", "client_id": "acme-client", "client_secret": "sealed-secret", "options": fiber.Map{"base_url": orgIdP.URL + "/"}, "link_email": true})
	if d := e.Must("GET", connections+"/"+gitlab, e.Owner, nil, 200).JSON; d["issuer"] != orgIdP.URL || d["provider"] != "gitlab" {
		t.Fatalf("gitlab = %v", d)
	}
	if r := e.sso(orgIdP, gitlab, e.Org, map[string]any{"sub": "alice-gitlab", "email": e.AliceEmail, "email_verified": true}); r.Status != 200 {
		t.Fatalf("gitlab sign-in: %d %v", r.Status, r.JSON)
	}
	e.Must("PATCH", connections+"/"+gitlab, e.Owner, fiber.Map{"options": fiber.Map{"base_url": "https://gitlab.example"}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"provider": "github_enterprise", "name": "GHE", "client_id": "c", "client_secret": "s"}, 400)
	ghe := e.ID("POST", connections, fiber.Map{"provider": "github_enterprise", "name": "GHE", "client_id": "c", "client_secret": "s", "options": fiber.Map{"base_url": "https://ghe.example.com"}})
	if d := e.Must("GET", connections+"/"+ghe, e.Owner, nil, 200).JSON; d["issuer"] != "https://ghe.example.com" {
		t.Fatalf("ghe = %v", d)
	}
}
