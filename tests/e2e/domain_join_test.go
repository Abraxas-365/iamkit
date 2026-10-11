package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// verifyEmail marks the user's email as verified (users created through the
// management API start unverified).
func (e *Env) verifyEmail(user string) {
	e.t.Helper()
	if _, err := e.DB.Exec(`UPDATE users SET email_verified=true WHERE id=$1`, user); err != nil {
		e.t.Fatal(err)
	}
}

func (e *Env) isMember(org, user string) (member, active bool) {
	e.t.Helper()
	n := count(e.t, e.DB, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, org, user)
	a := count(e.t, e.DB, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2 AND active`, org, user)
	return n > 0, a > 0
}

// TestDomainJoin: auto-join by verified domain. A human with a verified
// email on a verified domain of an organization that turned domain_join on
// becomes a member (and joins the configured group) when they sign in by
// any method, unless they were removed.
func TestDomainJoin(t *testing.T) {
	e := newEnv(t)
	orgURL := e.Base + "/organizations/" + e.Org
	domain := e.ID("POST", orgURL+"/domains", fiber.Map{"domain": "acme.example"})
	group := e.ID("POST", orgURL+"/groups", fiber.Map{"name": "Staff"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)

	zed := e.User("Zed", "zed@acme.example")
	e.verifyEmail(zed)
	login := func(user string) Response {
		return e.Do("POST", "/identity/v1/login", "", e.LoginBody(user, e.Pass))
	}

	// Off by default, and the domain is not verified yet: no join.
	if r := login("zed@acme.example"); r.Status == 200 {
		t.Fatalf("joined with domain_join off: %s", r.Body)
	}
	if m, _ := e.isMember(e.Org, zed); m {
		t.Fatal("membership created with domain_join off")
	}

	// Settings validation: the group must be an operator group of the org.
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	foreign := e.ID("POST", e.Base+"/organizations/"+other+"/groups", fiber.Map{"name": "Foreign"})
	e.Must("PATCH", orgURL, e.Owner, fiber.Map{"domain_join": true, "domain_join_group_id": foreign}, 400)
	e.Must("PATCH", orgURL, e.Owner, fiber.Map{"domain_join": true, "domain_join_group_id": "00000000-0000-4000-8000-000000000000"}, 400)
	e.Must("PATCH", orgURL, e.Owner, fiber.Map{"domain_join": true, "domain_join_group_id": group}, 204)
	found := e.Must("GET", orgURL, e.Owner, nil, 200).JSON
	if found["domain_join"] != true || found["domain_join_group_id"] != group {
		t.Fatalf("organization = %v", found)
	}

	// Unverified domain: no join.
	if r := login("zed@acme.example"); r.Status == 200 {
		t.Fatalf("joined through an unverified domain: %s", r.Body)
	}
	if m, _ := e.isMember(e.Org, zed); m {
		t.Fatal("membership through an unverified domain")
	}
	e.Must("POST", orgURL+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)

	// Unverified email: no join. Machine users never.
	yuri := e.User("Yuri", "yuri@acme.example")
	if r := login("yuri@acme.example"); r.Status == 200 {
		t.Fatalf("unverified email joined: %s", r.Body)
	}
	if m, _ := e.isMember(e.Org, yuri); m {
		t.Fatal("membership for an unverified email")
	}
	// Another domain: no join.
	ivy := e.User("Ivy", "ivy@elsewhere.example")
	e.verifyEmail(ivy)
	if r := login("ivy@elsewhere.example"); r.Status == 200 {
		t.Fatalf("foreign domain joined: %s", r.Body)
	}

	// Verified email on the verified domain: membership + group + access.
	r := login("zed@acme.example")
	if r.Status != 200 || !equal(e.permissions(r.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("domain join login: %d %s", r.Status, r.Body)
	}
	if m, a := e.isMember(e.Org, zed); !m || !a {
		t.Fatal("no membership after login")
	}
	if n := count(t, e.DB, `SELECT count(*) FROM group_members WHERE group_id=$1 AND user_id=$2`, group, zed); n != 1 {
		t.Fatalf("group members = %d", n)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='membership.created' AND data->>'source'='domain_join' AND data->>'user_id'=$2 AND actor_id=$2 AND organization_id=$3`, e.EnvID, zed, e.Org); n != 1 {
		t.Fatalf("membership.created events = %d", n)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='group.members_changed' AND data->>'source'='domain_join' AND subject_id=$2`, e.EnvID, group); n != 1 {
		t.Fatalf("group.members_changed events = %d", n)
	}
	// The organization is listed for the user.
	orgs := e.Must("GET", "/identity/v1/organizations?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), r.JSON["access_token"].(string), nil, 200)
	if !strings.Contains(orgs.Body, e.Org) {
		t.Fatalf("organizations: %s", orgs.Body)
	}
	// A second login joins nothing twice.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("zed@acme.example", e.Pass), 200)
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='membership.created' AND data->>'source'='domain_join'`, e.EnvID); n != 1 {
		t.Fatalf("membership.created events after relogin = %d", n)
	}

	// An explicit removal is respected.
	e.Must("DELETE", orgURL+"/members/"+zed, e.Owner, nil, 204)
	if r := login("zed@acme.example"); r.Status == 200 {
		t.Fatalf("removed member rejoined: %s", r.Body)
	}
	if m, a := e.isMember(e.Org, zed); !m || a {
		t.Fatalf("removed member: row=%v active=%v", m, a)
	}

	// Hosted chooser: the capturing organization is offered next to the
	// user's own.
	client := e.hostedClient()
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	yan := e.User("Yan", "yan@acme.example")
	e.verifyEmail(yan)
	e.Join(beta, yan)
	e.Grant(beta, yan, e.Res, "invoices:write")
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	choose := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {"yan@acme.example"}, "password": {e.Pass}})
	if orgs := choose.fields("organization_id"); choose.Status != 200 || !contains(orgs, beta) || !contains(orgs, e.Org) {
		t.Fatalf("chooser: %d %v %s", choose.Status, orgs, choose.Body)
	}

	// Federation: a verified email linked by an environment connection joins too.
	idp := newFakeIdP(t, e.Key, "social-client")
	e.IdP.Set(idp.Client().Transport)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"name": "Social", "issuer": idp.URL, "client_id": "social-client", "client_secret": "sealed-secret", "signup": true, "signup_organization_id": other, "link_email": true})
	wes := e.User("Wes", "wes@acme.example")
	e.verifyEmail(wes)
	fed := e.sso(idp, conn, e.Org, map[string]any{"sub": "wes-sub", "email": "wes@acme.example", "email_verified": true})
	if fed.Status != 200 {
		t.Fatalf("federated login: %d %v", fed.Status, fed.JSON)
	}
	if m, a := e.isMember(e.Org, wes); !m || !a {
		t.Fatal("federated login did not join")
	}

	// Turning it off stops joining.
	e.Must("PATCH", orgURL, e.Owner, fiber.Map{"domain_join": false, "domain_join_group_id": ""}, 204)
	vic := e.User("Vic", "vic@acme.example")
	e.verifyEmail(vic)
	if r := login("vic@acme.example"); r.Status == 200 {
		t.Fatalf("joined after turning it off: %s", r.Body)
	}
	if m, _ := e.isMember(e.Org, vic); m {
		t.Fatal("membership after turning it off")
	}
}

// TestDomainJoinPortalSettings: organization administrators turn domain
// capture on with settings:write, but only with a group whose roles they may
// assign themselves.
func TestDomainJoinPortalSettings(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	manager := e.User("Mallory", "mallory@example.com")
	e.Join(e.Org, manager)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": manager, "role_id": e.systemRole("org_user_manager")}, 204)

	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	alice := e.orgAdminToken(e.Org, e.AliceEmail)
	mallory := e.orgAdminToken(e.Org, "mallory@example.com")

	billing := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "billing", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	heavy := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Billing"})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": billing, "organization_id": e.Org, "group_id": heavy}, 204)
	light := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})

	// Needs settings:write.
	e.Must("PATCH", admin, mallory, fiber.Map{"domain_join": true}, 403)
	// The group carries a role the administrator cannot assign: refused.
	e.Must("PATCH", admin, alice, fiber.Map{"domain_join": true, "domain_join_group_id": heavy}, 403)
	if org := e.Must("GET", e.Base+"/organizations/"+e.Org, e.Owner, nil, 200).JSON; org["domain_join"] != false {
		t.Fatalf("refused update changed the organization: %v", org)
	}
	// A group without roles is fine; so is clearing it.
	e.Must("PATCH", admin, alice, fiber.Map{"domain_join": true, "domain_join_group_id": light}, 204)
	if org := e.Must("GET", admin, alice, nil, 200).JSON; org["domain_join"] != true || org["domain_join_group_id"] != light {
		t.Fatalf("portal organization = %v", org)
	}
	// Switching the group to the heavy one is refused too; clearing is not.
	e.Must("PATCH", admin, alice, fiber.Map{"domain_join_group_id": heavy}, 403)
	e.Must("PATCH", admin, alice, fiber.Map{"domain_join": false, "domain_join_group_id": ""}, 204)
}
