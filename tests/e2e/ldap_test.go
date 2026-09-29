package e2e_test

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedldap/ldaptest"
	"github.com/gofiber/fiber/v2"
)

// loopbackLDAP lets the directory connections of a test reach 127.0.0.1,
// which the production dialer refuses.
func loopbackLDAP() bootstrap.Option {
	return bootstrap.WithLDAPDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
}

const ldapBase = "ou=people,dc=example,dc=com"

func directory(t *testing.T, ldaps bool) *ldaptest.Server {
	return ldaptest.Start(t, ldaps,
		ldaptest.Entry{DN: "cn=iam,dc=example,dc=com", Password: "service-pass"},
		ldaptest.Entry{DN: "uid=dora," + ldapBase, Password: "dora-pass", Attributes: map[string][]string{"mail": {"dora@example.com"}, "displayName": {"Dora"}, "entryUUID": {"dora-uuid"}}},
		ldaptest.Entry{DN: "uid=otto," + ldapBase, Password: "otto-pass", Attributes: map[string][]string{"mail": {"otto@other.example"}, "entryUUID": {"otto-uuid"}}},
	)
}

// TestLDAPConnection covers an organization LDAP directory: creation rules
// (TLS required, secret with bind_dn, organization only, immutable host and
// base), discovery that asks for a password instead of redirecting, headless
// and hosted sign-in with JIT provisioning and a default group, wrong
// passwords, foreign domains, enforcement, and deactivation.
func TestLDAPConnection(t *testing.T) {
	e := newEnv(t, loopbackLDAP())
	dir := directory(t, true)
	connections := e.Base + "/federation-connections"
	options := fiber.Map{"url": dir.URL, "bind_dn": "cn=iam,dc=example,dc=com", "user_base_dn": ldapBase, "ca_pem": dir.CA}

	// Creation rules.
	e.Must("POST", connections, e.Owner, fiber.Map{"name": "AD", "provider": "ldap", "client_secret": "service-pass", "options": options}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "AD", "provider": "ldap", "options": options}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "AD", "provider": "ldap", "client_secret": "service-pass",
		"options": fiber.Map{"url": strings.Replace(dir.URL, "ldaps://", "ldap://", 1), "user_base_dn": ldapBase, "bind_dn": "cn=iam,dc=example,dc=com"}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "AD", "provider": "ldap", "client_secret": "service-pass",
		"options": fiber.Map{"url": dir.URL, "bind_dn": "cn=iam,dc=example,dc=com", "user_base_dn": ldapBase, "ca_pem": "not a certificate"}}, 400)
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "AD", "provider": "ldap", "client_secret": "service-pass", "options": options})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	if detail["provider"] != "ldap" || detail["issuer"] != dir.URL || detail["client_id"] != ldapBase || strings.Contains(e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).Body, "service-pass") {
		t.Fatalf("detail = %v", detail)
	}
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "AD twin", "provider": "ldap", "client_secret": "service-pass", "options": options}, 409)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"url": "ldaps://dc2.example.com", "bind_dn": "cn=iam,dc=example,dc=com", "user_base_dn": ldapBase}}, 400)

	// Discovery reports the provider; login needs a verified domain.
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	login := func(email, password string) Response {
		return e.Do("POST", "/identity/v1/federation/ldap/login", "", fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "connection_id": conn, "email": email, "password": password})
	}
	if r := login("dora@example.com", "dora-pass"); r.Status != 401 {
		t.Fatalf("unverified domain: %d %s", r.Status, r.Body)
	}
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	d := e.Must("POST", "/identity/v1/discover", "", fiber.Map{"environment_id": e.EnvID, "email": "dora@example.com"}, 200).JSON
	if d["provider"] != "ldap" || d["connection_id"] != conn {
		t.Fatalf("discover = %v", d)
	}

	// JIT with a default group: the directory user signs in with access.
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	if r := login("dora@example.com", "wrong"); r.Status != 401 {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
	if r := login("otto@other.example", "otto-pass"); r.Status != 401 {
		t.Fatalf("foreign domain: %d %s", r.Status, r.Body)
	}
	dora := login("Dora@Example.com", "dora-pass")
	if dora.Status != 200 || !equal(e.permissions(dora.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("ldap login: %d %s", dora.Status, dora.Body)
	}
	if amr := toString(claimsOf(t, dora.JSON["access_token"].(string))["amr"]); !strings.Contains(amr, `"fed"`) {
		t.Fatalf("amr = %s", amr)
	}
	var subject string
	if err := e.DB.Get(&subject, `SELECT x.subject FROM external_identities x JOIN users u ON u.id=x.user_id WHERE x.connection_id=$1 AND u.email='dora@example.com' AND x.origin='jit'`, conn); err != nil || subject != "dora-uuid" {
		t.Fatalf("jit dora: %q %v", subject, err)
	}
	if login("dora@example.com", "dora-pass").Status != 200 {
		t.Fatal("second login must reuse the link")
	}

	// The service account password is sealed; a wrong one is an upstream
	// failure, not the user's.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"client_secret": "rotated-wrong"}, 204)
	if r := login("dora@example.com", "dora-pass"); r.Status != 502 {
		t.Fatalf("wrong service password: %d %s", r.Status, r.Body)
	}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"client_secret": "service-pass"}, 204)

	// Hosted login: enforced directory asks for the password on the page.
	client := e.hostedClient()
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	if r := e.Do("POST", "/identity/v1/login", "", e.LoginBody("dora@example.com", e.Pass)); r.Status != 403 {
		t.Fatalf("enforced password login: %d %s", r.Status, r.Body)
	}
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	page := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {"dora@example.com"}})
	if page.Status != 200 || !strings.Contains(page.Body, `action="/hosted/login/directory"`) || page.field("connection_id") != conn {
		t.Fatalf("identify: %d %s", page.Status, page.Body)
	}
	wrong := b.post("/hosted/login/directory", url.Values{"ticket": {tk}, "email": {"dora@example.com"}, "connection_id": {conn}, "password": {"nope"}})
	if wrong.Status != 401 || !strings.Contains(wrong.Body, `action="/hosted/login/directory"`) {
		t.Fatalf("hosted wrong password: %d %s", wrong.Status, wrong.Body)
	}
	done := b.post("/hosted/login/directory", url.Values{"ticket": {tk}, "email": {"dora@example.com"}, "connection_id": {conn}, "password": {"dora-pass"}})
	tokens := b.exchange(client, done)
	if claims(t, tokens["access_token"].(string))["organization_id"] != e.Org {
		t.Fatal("LDAP must sign in to its organization")
	}

	// Deactivated: the directory is no longer consulted.
	e.Must("DELETE", connections+"/"+conn, e.Owner, nil, 204)
	if r := login("dora@example.com", "dora-pass"); r.Status != 404 {
		t.Fatalf("deactivated: %d %s", r.Status, r.Body)
	}
}

// TestLDAPStartTLSAnonymous covers ldap:// with StartTLS and an anonymous
// search, and the guarded dialer refusing a loopback directory in
// production.
func TestLDAPStartTLSAnonymous(t *testing.T) {
	dir := directory(t, false)
	for _, guarded := range []bool{false, true} {
		var e *Env
		if guarded {
			e = newEnv(t)
		} else {
			e = newEnv(t, loopbackLDAP())
		}
		domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
		e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
		conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "LDAP", "provider": "ldap", "jit_provisioning": true,
			"options": fiber.Map{"url": dir.URL, "start_tls": true, "user_base_dn": ldapBase, "user_filter": "(mail={email})", "ca_pem": dir.CA}})
		e.Must("PATCH", e.Base+"/federation-connections/"+conn, e.Owner, fiber.Map{"client_secret": "x"}, 400)
		r := e.Do("POST", "/identity/v1/federation/ldap/login", "", fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "connection_id": conn, "email": "dora@example.com", "password": "dora-pass"})
		switch {
		case guarded && r.Status != 502:
			t.Fatalf("guarded dialer reached loopback: %d %s", r.Status, r.Body)
		case !guarded && r.Status != 403:
			// Signed in, but the new user has no roles yet.
			t.Fatalf("starttls anonymous: %d %s", r.Status, r.Body)
		}
	}
}
