package e2e_test

// Focused regression tests. Each runs on its own database (see harness_test.go)
// so one failure cannot mask another, unlike the long isolation journey.

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Self-service membership: POST /identity/v1/memberships adds the *target*
// user_id to the caller's token organization, gated by iam:members:write.
func TestSelfServiceAddMember(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	body := fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "user_id": bob}

	token := e.Login(e.AliceEmail)
	e.Must("POST", "/identity/v1/memberships", token, body, 403) // no iam:members:write yet
	if contains(e.Members(e.Org), bob) {
		t.Fatal("bob added without permission")
	}

	e.Grant(e.Org, e.Alice, e.IAMResource(), "iam:members:write")
	e.Must("POST", "/identity/v1/memberships", token, body, 201)
	if !contains(e.Members(e.Org), bob) {
		t.Fatalf("bob not in org members after 201: %v", e.Members(e.Org))
	}
	e.Must("POST", "/identity/v1/memberships", token, body, 409) // already a member

	e.Must("POST", "/identity/v1/memberships", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 400)
	e.Must("POST", "/identity/v1/memberships", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "user_id": "not-a-uuid"}, 400)
}

// The target org comes from the token; a body organization_id cannot redirect it.
func TestSelfServiceAddMemberIgnoresBodyOrganization(t *testing.T) {
	e := newEnv(t)
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	bob := e.User("Bob", "bob@example.com")
	e.Grant(e.Org, e.Alice, e.IAMResource(), "iam:members:write")
	token := e.Login(e.AliceEmail)

	e.Must("POST", "/identity/v1/memberships", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "user_id": bob, "organization_id": other}, 201)
	if contains(e.Members(other), bob) {
		t.Fatal("body organization_id was honoured")
	}
	if !contains(e.Members(e.Org), bob) {
		t.Fatal("bob not added to the token's organization")
	}
}

// Login must not reveal whether an account exists.
func TestLoginDoesNotEnumerateAccounts(t *testing.T) {
	e := newEnv(t)
	outsider := e.User("Outsider", "outsider@example.com") // valid password, no membership
	_ = outsider

	unknown := e.Do("POST", "/identity/v1/login", "", e.LoginBody("nobody@example.com", e.Pass))
	wrong := e.Do("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password here"))
	noAccess := e.Do("POST", "/identity/v1/login", "", e.LoginBody("outsider@example.com", e.Pass))

	for name, r := range map[string]Response{"unknown email": unknown, "wrong password": wrong, "no access": noAccess} {
		if r.Status != 401 {
			t.Errorf("%s: status %d, want 401: %s", name, r.Status, r.Body)
		}
	}
	if unknown.Body != wrong.Body {
		t.Errorf("unknown email vs wrong password differ:\n  %s\n  %s", unknown.Body, wrong.Body)
	}
	if noAccess.Body != wrong.Body {
		t.Errorf("valid-password-no-access vs wrong password differ:\n  %s\n  %s", noAccess.Body, wrong.Body)
	}
}

// User detail scans email_verified/otp_enabled/metadata.
func TestUserDetail(t *testing.T) {
	e := newEnv(t)
	u := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON
	if u["email"] != e.AliceEmail || u["id"] != e.Alice {
		t.Fatalf("unexpected user: %v", u)
	}
	for _, k := range []string{"email_verified", "otp_enabled", "active", "metadata"} {
		if _, ok := u[k]; !ok {
			t.Errorf("missing %q in %v", k, u)
		}
	}
}

// SCIM create → read back by id and by filter (what Entra/Okta do).
func TestSCIMReadBack(t *testing.T) {
	e := newEnv(t)
	secret := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "HR", "organization_id": e.Org}, 201).JSON["secret"].(string)

	created := e.Must("POST", "/scim/v2/Users", secret, fiber.Map{"userName": "prov@example.com", "displayName": "Prov", "externalId": "ext-1"}, 201).JSON
	id := created["id"].(string)

	got := e.Must("GET", "/scim/v2/Users/"+id, secret, nil, 200).JSON
	if got["userName"] != "prov@example.com" || got["externalId"] != "ext-1" || got["active"] != true {
		t.Fatalf("read back mismatch: %v", got)
	}
	for _, filter := range []string{`externalId eq "ext-1"`, `userName eq "prov@example.com"`} {
		list := e.Must("GET", "/scim/v2/Users?filter="+url.QueryEscape(filter), secret, nil, 200).JSON
		if n, _ := list["totalResults"].(float64); n != 1 {
			t.Errorf("filter %s: totalResults=%v", filter, list["totalResults"])
		}
	}
	all := e.Must("GET", "/scim/v2/Users", secret, nil, 200).JSON
	if n, _ := all["totalResults"].(float64); n != 1 {
		t.Errorf("list: totalResults=%v", all["totalResults"])
	}
}

// Federation start + callback end-to-end against a mock OIDC provider.
func TestFederationLogin(t *testing.T) {
	e := newEnv(t)
	call := func(method, path, token string, body any, want int) map[string]any {
		t.Helper()
		return e.Must(method, path, token, body, want).JSON
	}
	federationJourney(t, e.App, e.Key, call, e.Owner, e.Base, e.EnvID, e.Org, e.Alice, e.Client, e.Res)
}

// PATCH /identity/v1/me updates the caller's display name (docs/reference/api/identity.md).
func TestSelfServiceUpdateProfile(t *testing.T) {
	e := newEnv(t)
	token := e.Login(e.AliceEmail)
	e.Must("PATCH", "/identity/v1/me", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "name": "Alice Renamed"}, 204)
	if got := e.Must("GET", e.Base+"/users/"+e.Alice, e.Owner, nil, 200).JSON["name"]; got != "Alice Renamed" {
		t.Fatalf("name not updated: %v", got)
	}
	e.Must("PATCH", "/identity/v1/me", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "name": "  "}, 400)
}
