package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestOrgAdminDirectories: an organization's administrators issue, list and
// revoke the SCIM credentials of their own organization only.
func TestOrgAdminDirectories(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	mallory := e.User("Mallory", "mallory@example.com")
	e.Join(e.Org, mallory)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": mallory, "role_id": e.systemRole("org_user_manager")}, 204)
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})

	alice := e.orgAdminToken(e.Org, e.AliceEmail)
	malloryToken := e.orgAdminToken(e.Org, "mallory@example.com")
	dirs := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin/directories"
	globexDirs := "/api/v1/environments/" + e.EnvID + "/organizations/" + globex + "/admin/directories"

	// Nothing yet; the SCIM base URL is published.
	empty := e.Must("GET", dirs, alice, nil, 200).JSON
	if empty["page"].(map[string]any)["total"].(float64) != 0 || !strings.HasSuffix(empty["scim_url"].(string), "/scim/v2") {
		t.Fatalf("empty list = %v", empty)
	}

	// Writes need iam:org:sso:write; reads iam:org:read. The body cannot
	// name another organization.
	e.Must("POST", dirs, malloryToken, fiber.Map{"name": "Okta"}, 403)
	e.Must("GET", dirs, malloryToken, nil, 200)
	e.Must("POST", dirs, alice, fiber.Map{"name": " "}, 400)
	e.Must("POST", globexDirs, alice, fiber.Map{"name": "Okta"}, 403)
	issued := e.Must("POST", dirs, alice, fiber.Map{"name": "Okta", "organization_id": globex, "adopt_existing_members": true, "adopt_scope": "verified_domains"}, 201).JSON
	secret := issued["secret"].(string)
	if !strings.HasPrefix(secret, "ik_scim_") || !strings.HasSuffix(issued["scim_url"].(string), "/scim/v2") {
		t.Fatalf("issued = %v", issued)
	}
	id := issued["id"].(string)

	// The secret authenticates SCIM calls for this organization.
	scim := &scimClient{e: e, header: map[string]string{"Authorization": "Bearer " + secret}, connection: issued["connection_id"].(string)}
	created := scim.must("POST", "/Users", `{"userName":"nina@example.com","externalId":"nina"}`, 201).JSON
	if !contains(e.Members(e.Org), created["id"].(string)) || contains(e.Members(globex), created["id"].(string)) {
		t.Fatalf("SCIM user landed in the wrong organization: %v", created)
	}

	// Listing never shows secrets, shows the connection's policy and no
	// other organization's credentials.
	e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Globex IdP", "organization_id": globex}, 201)
	list := e.Must("GET", dirs, malloryToken, nil, 200)
	if strings.Contains(list.Body, "secret") || strings.Contains(list.Body, "Globex") {
		t.Fatalf("list leaks: %s", list.Body)
	}
	items := list.JSON["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	item := items[0].(map[string]any)
	if item["id"] != id || item["name"] != "Okta" || item["adopt_existing_members"] != true || item["adopt_scope"] != "verified_domains" || item["revoked_at"] != nil {
		t.Fatalf("item = %v", item)
	}

	// Another organization's credential is not found, from either side.
	var foreign string
	if err := e.DB.Get(&foreign, `SELECT id FROM provisioning_credentials WHERE environment_id=$1 AND organization_id=$2`, e.EnvID, globex); err != nil {
		t.Fatal(err)
	}
	e.Must("DELETE", dirs+"/"+foreign, alice, nil, 404)
	e.Must("DELETE", dirs+"/00000000-0000-0000-0000-00000000dead", alice, nil, 404)
	e.Must("DELETE", dirs+"/not-a-uuid", alice, nil, 404)
	var revoked *string
	if err := e.DB.Get(&revoked, `SELECT revoked_at::text FROM provisioning_credentials WHERE id=$1`, foreign); err != nil || revoked != nil {
		t.Fatalf("foreign credential touched: %v %v", revoked, err)
	}

	// Revoking needs the write permission, then SCIM stops at once.
	e.Must("DELETE", dirs+"/"+id, malloryToken, nil, 403)
	scim.must("GET", "/Users", "", 200)
	e.Must("DELETE", dirs+"/"+id, alice, nil, 204)
	if res := scim.do("GET", "/Users", ""); res.Status != 401 {
		t.Fatalf("revoked credential: %d %s", res.Status, res.Body)
	}
	after := e.Must("GET", dirs, alice, nil, 200).JSON["items"].([]any)[0].(map[string]any)
	if after["revoked_at"] == nil {
		t.Fatalf("revoked credential not marked: %v", after)
	}

	// Audited with the administrator as the actor, as provisioning events.
	var n int
	if err := e.DB.Get(&n, `SELECT count(*) FROM events WHERE environment_id=$1 AND actor_id=$2 AND type IN ('provisioning_credential.created','provisioning_credential.revoked')`, e.EnvID, e.Alice); err != nil || n != 2 {
		t.Fatalf("events by the administrator: %d %v", n, err)
	}
}
