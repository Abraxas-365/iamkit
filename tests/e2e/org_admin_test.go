package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// systemRole returns the environment's built-in IAM role with the key.
func (e *Env) systemRole(key string) string {
	e.t.Helper()
	var id string
	if err := e.DB.Get(&id, `SELECT id FROM roles WHERE environment_id=$1 AND system_role=$2`, e.EnvID, key); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// orgAdminToken signs email in to org for the IAM resource (the customer's
// own admin app), carrying their iam:org:* permissions there.
func (e *Env) orgAdminToken(org, email string) string {
	e.t.Helper()
	body := fiber.Map{"environment_id": e.EnvID, "organization_id": org, "application_id": e.Client, "resource_id": e.IAMResource(), "email": email, "password": e.Pass}
	return e.Must("POST", "/identity/v1/login", "", body, 200).JSON["access_token"].(string)
}

// TestOrganizationAdministration: an organization's own administrators
// manage it through /organizations/:organization/admin with iam:org:*
// permissions from the built-in roles, within the anti-escalation rules.
func TestOrganizationAdministration(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)

	// Built-in roles exist, cannot be edited or deleted.
	owner, manager, viewer := e.systemRole("org_owner"), e.systemRole("org_user_manager"), e.systemRole("org_viewer")
	e.systemRole("org_settings_manager")
	e.Must("PUT", e.Base+"/roles/"+owner, e.Owner, fiber.Map{"name": "Hacked", "resource_id": iam, "permissions": []string{"iam:org:read"}}, 404)
	e.Must("DELETE", e.Base+"/roles/"+owner, e.Owner, nil, 404)
	var perms []string
	if err := e.DB.Select(&perms, `SELECT unnest(permissions) FROM resources WHERE id=$1`, iam); err != nil || !contains(perms, "iam:org:audit:read") {
		t.Fatalf("IAM catalog lacks org permissions: %v %v", err, perms)
	}

	// Alice owns Acme; Mallory manages its users; Olga is a plain member.
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": owner}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	mallory := e.User("Mallory", "mallory@example.com")
	e.Join(e.Org, mallory)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": mallory, "role_id": manager}, 204)
	olga := e.ID("POST", e.Base+"/users", fiber.Map{"name": "Olga", "email": "olga@example.com", "password": e.Pass, "home_organization_id": e.Org})

	// Another organization and its user stay invisible.
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	gus := e.User("Gus", "gus@example.com")
	e.Join(globex, gus)
	// A user of both organizations is homed in neither.
	both := e.User("Bea", "bea@example.com")
	e.Join(e.Org, both)
	e.Join(globex, both)

	aliceToken := e.orgAdminToken(e.Org, e.AliceEmail)
	malloryToken := e.orgAdminToken(e.Org, "mallory@example.com")
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	globexAdmin := "/api/v1/environments/" + e.EnvID + "/organizations/" + globex + "/admin"

	// The token must be issued in the path's organization; machine tokens
	// and resource tokens without iam:org:* get nothing.
	e.Must("GET", globexAdmin, aliceToken, nil, 403)
	e.Must("GET", admin, e.Login(e.AliceEmail), nil, 403)
	e.Must("GET", admin, e.scopedToken("iam:org:read"), nil, 403)
	org := e.Must("GET", admin, aliceToken, nil, 200).JSON
	if org["name"] != "Acme" || org["metadata"] != nil {
		t.Fatalf("organization = %v", org)
	}
	// The plain iam:members:* routes still need their own permissions.
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+e.Org+"/members", aliceToken, nil, 403)

	// Settings: owners yes, user managers no; active/metadata ignored.
	e.Must("PATCH", admin, aliceToken, fiber.Map{"name": "Acme Inc", "active": false, "mfa_required": true}, 204)
	e.Must("PATCH", admin, malloryToken, fiber.Map{"name": "Mallory Inc"}, 403)
	found := e.Must("GET", e.Base+"/organizations/"+e.Org, e.Owner, nil, 200).JSON
	if found["name"] != "Acme Inc" || found["active"] != true || found["mfa_required"] != true {
		t.Fatalf("organization after settings = %v", found)
	}
	e.Must("PATCH", admin, aliceToken, fiber.Map{"mfa_required": false}, 204)

	// Members and users.
	members := e.Must("GET", admin+"/members", malloryToken, nil, 200).JSON
	if n := members["page"].(map[string]any)["total"].(float64); n != 4 {
		t.Fatalf("members = %v", members)
	}
	created := e.Must("POST", admin+"/users", malloryToken, fiber.Map{"email": "nina@example.com", "name": "Nina", "password": e.Pass}, 201).JSON["id"].(string)
	if !contains(e.Members(e.Org), created) {
		t.Fatal("created user is not a member")
	}
	nina := e.Must("GET", e.Base+"/users/"+created, e.Owner, nil, 200).JSON
	if nina["home_organization_id"] != e.Org {
		t.Fatalf("created user home = %v", nina["home_organization_id"])
	}
	home := e.Must("GET", admin+"/users", malloryToken, nil, 200).JSON["items"].([]any)
	ids := []string{}
	for _, u := range home {
		ids = append(ids, u.(map[string]any)["id"].(string))
	}
	if !contains(ids, created) || !contains(ids, olga) || contains(ids, both) || contains(ids, gus) {
		t.Fatalf("home users = %v", ids)
	}
	e.Must("PATCH", admin+"/users/"+olga, malloryToken, fiber.Map{"name": "Olga K"}, 204)
	e.Must("PATCH", admin+"/users/"+both, malloryToken, fiber.Map{"name": "x"}, 403)
	e.Must("PATCH", admin+"/users/"+gus, malloryToken, fiber.Map{"name": "x"}, 404)
	e.Must("GET", admin+"/users/"+gus, malloryToken, nil, 404)
	// Another organization's member, or the zero id (no filter), has no roles here.
	e.Must("GET", admin+"/members/"+gus+"/roles", malloryToken, nil, 404)
	e.Must("GET", admin+"/members/00000000-0000-0000-0000-000000000000/roles", malloryToken, nil, 404)
	e.Must("POST", admin+"/users/"+olga+"/deactivate", malloryToken, nil, 204)
	e.Must("POST", admin+"/users/"+olga+"/reactivate", malloryToken, nil, 204)

	// Anti-escalation: a user manager assigns only roles within its own
	// permissions, never ownership, and never acts on owners.
	e.Must("POST", admin+"/role-assignments", malloryToken, fiber.Map{"user_id": olga, "role_id": viewer}, 204)
	e.Must("POST", admin+"/role-assignments", malloryToken, fiber.Map{"user_id": olga, "role_id": owner}, 403)
	e.Must("POST", admin+"/role-assignments", malloryToken, fiber.Map{"user_id": mallory, "role_id": e.systemRole("org_settings_manager")}, 403)
	billing := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "billing", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", admin+"/role-assignments", aliceToken, fiber.Map{"user_id": olga, "role_id": billing}, 403)
	e.Must("POST", admin+"/role-assignments", malloryToken, fiber.Map{"user_id": gus, "role_id": viewer}, 404)
	e.Must("DELETE", admin+"/members/"+e.Alice, malloryToken, nil, 403)
	e.Must("POST", admin+"/users/"+e.Alice+"/deactivate", malloryToken, nil, 403)
	e.Must("DELETE", admin+"/role-assignments/"+e.Alice+"/"+owner, malloryToken, nil, 403)
	roles := e.Must("GET", admin+"/members/"+olga+"/roles", malloryToken, nil, 200).JSON
	if roles["page"].(map[string]any)["total"].(float64) != 1 {
		t.Fatalf("olga's roles = %v", roles)
	}
	assignable := e.Must("GET", admin+"/roles", malloryToken, nil, 200).JSON["items"].([]any)
	if len(assignable) != 5 || assignable[0].(map[string]any)["system_role"] == "" {
		t.Fatalf("assignable roles = %v", assignable)
	}

	// The last owner stays; with a second owner the first may step down.
	e.Must("DELETE", admin+"/role-assignments/"+e.Alice+"/"+owner, aliceToken, nil, 422)
	e.Must("DELETE", admin+"/members/"+e.Alice, aliceToken, nil, 422)
	e.Must("POST", admin+"/users/"+e.Alice+"/deactivate", aliceToken, nil, 422)
	e.Must("POST", admin+"/role-assignments", aliceToken, fiber.Map{"user_id": olga, "role_id": owner}, 204)
	e.Must("DELETE", admin+"/role-assignments/"+olga+"/"+owner, aliceToken, nil, 204)

	// Invitations carry only assignable roles.
	e.Must("POST", admin+"/invitations", malloryToken, fiber.Map{"email": "ivan@example.com", "role_ids": []string{owner}}, 403)
	inv := e.Must("POST", admin+"/invitations", malloryToken, fiber.Map{"email": "ivan@example.com", "role_ids": []string{viewer}}, 201).JSON
	if !strings.HasPrefix(inv["token"].(string), "ik_inv_") {
		t.Fatalf("invitation = %v", inv)
	}
	listed := e.Must("GET", admin+"/invitations", malloryToken, nil, 200).JSON
	if listed["page"].(map[string]any)["total"].(float64) != 1 {
		t.Fatalf("invitations = %v", listed)
	}
	e.Must("DELETE", admin+"/invitations/"+inv["id"].(string), malloryToken, nil, 204)

	// SSO connections: the organization's own, sealed secrets only.
	sso := admin + "/connections"
	conn := fiber.Map{"name": "Okta", "provider": "oidc", "issuer": "https://idp.example", "client_id": "acme", "secret_env": "DATABASE_URL"}
	e.Must("POST", sso, malloryToken, conn, 403)
	e.Must("POST", sso, aliceToken, conn, 400)
	globexConn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": globex, "name": "Globex SSO", "provider": "oidc", "issuer": "https://idp.globex.example", "client_id": "globex", "client_secret": "s3cret"})
	e.Must("GET", sso+"/"+globexConn, aliceToken, nil, 404)
	e.Must("DELETE", sso+"/"+globexConn, aliceToken, nil, 404)
	list := e.Must("GET", sso, aliceToken, nil, 200).JSON
	if list["page"].(map[string]any)["total"].(float64) != 0 {
		t.Fatalf("connections = %v", list)
	}

	// Audit: owners read their organization's events, attributed to users.
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"name": "Acme Inc"}, 204)
	e.Must("GET", admin+"/events", malloryToken, nil, 403)
	events := e.Must("GET", admin+"/events?limit=100", aliceToken, nil, 200).JSON["items"].([]any)
	var byAlice, byOperator bool
	for _, raw := range events {
		ev := raw.(map[string]any)
		if !strings.Contains(ev["target_id"].(string), e.Org) {
			t.Fatalf("event of another organization: %v", ev)
		}
		switch ev["actor_kind"] {
		case "user":
			byAlice = byAlice || (ev["actor_id"] == e.Alice && ev["actor_label"] == e.AliceEmail)
		case "operator":
			byOperator = true
			if ev["actor_label"] != "" {
				t.Fatalf("operator label leaked: %v", ev)
			}
		}
	}
	if !byAlice || !byOperator {
		t.Fatalf("events lack user or operator actors: %v", events)
	}
	e.Must("GET", globexAdmin+"/events", aliceToken, nil, 403)

	// Operators see who acted and in which organization.
	all := e.Must("GET", e.Base+"/audit-events?search=user.deactivated", e.Owner, nil, 200).JSON["items"].([]any)
	if len(all) == 0 || all[0].(map[string]any)["actor_kind"] != "user" || all[0].(map[string]any)["organization_id"] != e.Org {
		t.Fatalf("operator audit = %v", all)
	}
}
