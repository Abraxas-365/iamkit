package e2e_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// permissions introspects token for the billing audience and returns its
// permissions claim, sorted.
func (e *Env) permissions(token string) []string {
	e.t.Helper()
	res := e.Must("POST", "/identity/v1/introspect", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 200)
	if res.JSON["active"] != true {
		e.t.Fatalf("token inactive: %s", res.Body)
	}
	claims, _ := res.JSON["claims"].(map[string]any)
	raw, _ := claims["permissions"].([]any)
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, p.(string))
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func items(r Response) []map[string]any {
	raw, _ := r.JSON["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}

// TestGroupRolesJourney: roles bound to a group reach members' tokens, compose
// with direct roles, and are revoked by leaving the group without touching
// direct assignments.
func TestGroupRolesJourney(t *testing.T) {
	e := newEnv(t)
	groups := e.Base + "/organizations/" + e.Org + "/groups"
	// Clear alice's direct grant so every permission below comes from roles.
	e.Grant(e.Org, e.Alice, e.Res)
	if got := e.permissions(e.Login(e.AliceEmail)); len(got) != 0 {
		t.Fatalf("baseline permissions = %v", got)
	}

	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	writer := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "writer", "resource_id": e.Res, "permissions": []string{"invoices:write"}})

	// Validation and uniqueness.
	e.Must("POST", groups, e.Owner, fiber.Map{"name": "  "}, 400)
	finance := e.ID("POST", groups, fiber.Map{"name": "Finance", "description": "Money people"})
	e.Must("POST", groups, e.Owner, fiber.Map{"name": "finance"}, 409)
	e.Must("GET", groups+"/not-a-uuid", e.Owner, nil, 404)

	// Members must belong to the organization.
	outsider := e.User("Mallory", "mallory@example.com")
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"add": []string{outsider}}, 400)
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{}, 400)
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 204)
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 204) // idempotent

	g := e.Must("GET", groups+"/"+finance, e.Owner, nil, 200)
	if g.JSON["member_count"] != float64(1) || g.JSON["connection_id"] != nil {
		t.Fatalf("group = %s", g.Body)
	}
	if m := items(e.Must("GET", groups+"/"+finance+"/members", e.Owner, nil, 200)); len(m) != 1 || m[0]["user_id"] != e.Alice {
		t.Fatalf("members = %v", m)
	}
	if l := items(e.Must("GET", e.Base+"/organizations/"+e.Org+"/members/"+e.Alice+"/groups", e.Owner, nil, 200)); len(l) != 1 {
		t.Fatalf("user groups = %v", l)
	}

	// Group role → token.
	bind := fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": finance}
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, bind, 204)
	if dup := e.Must("POST", e.Base+"/group-role-assignments", e.Owner, bind, 409); dup.Body == "" || !strings.Contains(dup.Body, "already holds this role") {
		t.Fatalf("duplicate group role = %s", dup.Body)
	}
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("group role permissions = %v", got)
	}
	if a := items(e.Must("GET", e.Base+"/group-role-assignments?group_id="+finance, e.Owner, nil, 200)); len(a) != 1 || a[0]["role_name"] != "reader" {
		t.Fatalf("group role assignments = %v", a)
	}

	// A group from another organization cannot be bound in this one.
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": other, "group_id": finance}, 404)

	// Direct role composes with group role; effective-roles explains both.
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"role_id": writer, "organization_id": e.Org, "user_id": e.Alice}, 204)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "user_id": e.Alice}, 204)
	if dup := e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "user_id": e.Alice}, 409); !strings.Contains(dup.Body, "already holds this role") {
		t.Fatalf("duplicate role = %s", dup.Body)
	}
	if out := e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "user_id": outsider}, 409); !strings.Contains(out.Body, "not a member") {
		t.Fatalf("outsider role = %s", out.Body)
	}
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("composed permissions = %v", got)
	}
	eff := e.Must("GET", e.Base+"/effective-roles?organization_id="+e.Org+"&user_id="+e.Alice, e.Owner, nil, 200)
	sources := map[string]int{}
	for _, r := range items(eff) {
		sources[r["role_name"].(string)+"/"+r["source"].(string)]++
	}
	if sources["reader/direct"] != 1 || sources["reader/group"] != 1 || sources["writer/direct"] != 1 || len(sources) != 3 {
		t.Fatalf("effective roles = %s", eff.Body)
	}
	// Without organization_id the same roles come back for every organization,
	// each row naming its organization.
	all := items(e.Must("GET", e.Base+"/effective-roles?user_id="+e.Alice, e.Owner, nil, 200))
	if len(all) != 3 || all[0]["organization_id"] != e.Org {
		t.Fatalf("effective roles across organizations = %v", all)
	}
	e.Must("GET", e.Base+"/effective-roles?organization_id=nope&user_id="+e.Alice, e.Owner, nil, 400)
	e.Must("GET", e.Base+"/effective-roles", e.Owner, nil, 400)

	// Leaving the group keeps the direct reader assignment.
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"remove": []string{e.Alice}}, 204)
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("after leaving group = %v", got)
	}
	e.Must("DELETE", e.Base+"/role-assignments/"+reader+"/"+e.Org+"/"+e.Alice, e.Owner, nil, 204)
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:write"}) {
		t.Fatalf("after direct unassign = %v", got)
	}

	// Removing the org membership drops group memberships; inactive members cannot be re-added.
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"add": []string{bob}}, 204)
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+bob, e.Owner, nil, 204)
	if m := items(e.Must("GET", groups+"/"+finance+"/members", e.Owner, nil, 200)); len(m) != 0 {
		t.Fatalf("members after org removal = %v", m)
	}
	e.Must("POST", groups+"/"+finance+"/members", e.Owner, fiber.Map{"add": []string{bob}}, 400)

	// Rename, unbind, delete; deleting the group cascades its bindings.
	e.Must("PATCH", groups+"/"+finance, e.Owner, fiber.Map{"name": "Finance Ops"}, 204)
	if g := e.Must("GET", groups+"/"+finance, e.Owner, nil, 200); g.JSON["name"] != "Finance Ops" || g.JSON["description"] != "Money people" {
		t.Fatalf("renamed group = %s", g.Body)
	}
	e.Must("DELETE", e.Base+"/group-role-assignments/"+reader+"/"+e.Org+"/"+finance, e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/group-role-assignments/"+reader+"/"+e.Org+"/"+finance, e.Owner, nil, 404)
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, bind, 204)
	e.Must("DELETE", groups+"/"+finance, e.Owner, nil, 204)
	e.Must("GET", groups+"/"+finance, e.Owner, nil, 404)
	if a := items(e.Must("GET", e.Base+"/group-role-assignments?organization_id="+e.Org, e.Owner, nil, 200)); len(a) != 0 {
		t.Fatalf("bindings after group delete = %v", a)
	}

	// Deleting a role removes its group bindings; deleting a user removes its group memberships.
	sales := e.ID("POST", groups, fiber.Map{"name": "Sales"})
	e.Must("POST", groups+"/"+sales+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 204)
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": writer, "organization_id": e.Org, "group_id": sales}, 204)
	e.Must("DELETE", e.Base+"/roles/"+writer, e.Owner, nil, 204)
	if a := items(e.Must("GET", e.Base+"/group-role-assignments?group_id="+sales, e.Owner, nil, 200)); len(a) != 0 {
		t.Fatalf("bindings after role delete = %v", a)
	}
	e.Must("DELETE", e.Base+"/users/"+e.Alice+"/permanent", e.Owner, nil, 204)
	if g := e.Must("GET", groups+"/"+sales, e.Owner, nil, 200); g.JSON["member_count"] != float64(0) {
		t.Fatalf("sales after user delete = %s", g.Body)
	}
}

// TestDirectoryGroupsAreReadOnly: operators cannot rename, delete or change
// members of a group owned by a provisioning connection, but can bind roles.
func TestDirectoryGroupsAreReadOnly(t *testing.T) {
	e := newEnv(t)
	conn := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Entra", "organization_id": e.Org}, 201).JSON["connection_id"].(string)
	group := "5f0c7e0a-6a53-4d4b-9b54-3c1b0f7d2a11"
	if _, err := e.DB.Exec(`INSERT INTO groups(id,environment_id,organization_id,name,connection_id,external_id) VALUES($1,$2,$3,'Engineering',$4,'ext-1')`, group, e.EnvID, e.Org, conn); err != nil {
		t.Fatal(err)
	}
	groups := e.Base + "/organizations/" + e.Org + "/groups"
	if g := e.Must("GET", groups+"/"+group, e.Owner, nil, 200); g.JSON["connection_id"] != conn {
		t.Fatalf("directory group = %s", g.Body)
	}
	e.Must("PATCH", groups+"/"+group, e.Owner, fiber.Map{"name": "x"}, 422)
	e.Must("POST", groups+"/"+group+"/members", e.Owner, fiber.Map{"add": []string{e.Alice}}, 422)
	e.Must("DELETE", groups+"/"+group, e.Owner, nil, 422)
	role := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": role, "organization_id": e.Org, "group_id": group}, 204)
	if l := items(e.Must("GET", groups+"?connection_id="+conn, e.Owner, nil, 200)); len(l) != 1 {
		t.Fatalf("filtered groups = %v", l)
	}
}
