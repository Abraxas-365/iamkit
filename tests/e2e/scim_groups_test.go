package e2e_test

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
)

const patchSchema = `"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`

func (s *scimClient) user(email, external string) string {
	s.e.t.Helper()
	return s.must("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+email+`","externalId":"`+external+`","active":true}`, 201).JSON["id"].(string)
}

func memberIDs(g map[string]any) []string {
	raw, _ := g["members"].([]any)
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		out = append(out, m.(map[string]any)["value"].(string))
	}
	return out
}

// TestSCIMGroupsJourney: a directory pushes a group like Entra does, the
// operator binds a role to it, and membership changes reach tokens.
func TestSCIMGroupsJourney(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	// Drop alice's direct grant: every permission below comes from the group.
	e.Grant(e.Org, e.Alice, e.Res)
	jdoe := s.user("jdoe@example.com", "obj-jdoe")
	ann := s.user("ann@example.com", "obj-ann")
	// Directory-created users have no password; give jdoe one to log in.
	if _, err := e.DB.Exec(`UPDATE users SET password_hash=(SELECT password_hash FROM users WHERE id=$1) WHERE id=$2`, e.Alice, jdoe); err != nil {
		t.Fatal(err)
	}

	// Entra: create with members, Location header, meta.
	created := s.must("POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"grp-eng","displayName":"Engineering","members":[{"value":"`+jdoe+`"}]}`, 201)
	group := created.JSON["id"].(string)
	if m := memberIDs(created.JSON); len(m) != 1 || m[0] != jdoe {
		t.Fatalf("created members: %s", created.Body)
	}
	if created.JSON["externalId"] != "grp-eng" || created.JSON["meta"].(map[string]any)["resourceType"] != "Group" {
		t.Fatalf("created: %s", created.Body)
	}
	dup := s.do("POST", "/Groups", `{"displayName":"engineering"}`)
	if dup.Status != 409 || scimType(dup) != "uniqueness" {
		t.Fatalf("duplicate: %d %s", dup.Status, dup.Body)
	}
	if bad := s.do("POST", "/Groups", `{"displayName":"X","members":[{"value":"`+e.Alice+`"}]}`); bad.Status != 400 || scimType(bad) != "invalidValue" {
		t.Fatalf("non-provisioned member: %d %s", bad.Status, bad.Body)
	}
	if bad := s.do("POST", "/Groups", `{"displayName":" "}`); bad.Status != 400 {
		t.Fatalf("blank name: %d %s", bad.Status, bad.Body)
	}

	// Filters and excludedAttributes (Entra probes by displayName first).
	q := "/Groups?excludedAttributes=members&filter=" + url.QueryEscape(`displayName eq "ENGINEERING"`)
	list := s.must("GET", q, "", 200).JSON
	if list["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %v", list)
	}
	if first := list["Resources"].([]any)[0].(map[string]any); first["members"] != nil {
		t.Fatalf("members not excluded: %v", first)
	}
	if n := s.must("GET", "/Groups?filter="+url.QueryEscape(`externalId eq "grp-eng"`), "", 200).JSON["totalResults"]; n.(float64) != 1 {
		t.Fatalf("externalId filter: %v", n)
	}
	if n := s.must("GET", "/Groups?filter="+url.QueryEscape(`id eq "not-a-uuid"`), "", 200).JSON["totalResults"]; n.(float64) != 0 {
		t.Fatalf("id filter: %v", n)
	}
	if r := s.do("GET", "/Groups?filter="+url.QueryEscape(`members eq "x"`), ""); r.Status != 400 || scimType(r) != "invalidFilter" {
		t.Fatalf("bad filter: %d %s", r.Status, r.Body)
	}

	// Operator sees the directory group read-only and binds a role to it.
	groups := e.Base + "/organizations/" + e.Org + "/groups"
	e.Must("PATCH", groups+"/"+group, e.Owner, fiber.Map{"name": "hijack"}, 422)
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	if got := e.permissions(e.Login("jdoe@example.com")); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("directory group role: %v", got)
	}

	// Entra PATCH forms: add, replace displayName, remove by filter.
	s.must("PATCH", "/Groups/"+group, `{`+patchSchema+`,"Operations":[{"op":"Add","path":"members","value":[{"value":"`+ann+`"}]},{"op":"Replace","path":"displayName","value":"Eng"}]}`, 204)
	got := s.must("GET", "/Groups/"+group, "", 200).JSON
	if got["displayName"] != "Eng" || len(memberIDs(got)) != 2 {
		t.Fatalf("after add: %v", got)
	}
	s.must("PATCH", "/Groups/"+group, `{`+patchSchema+`,"Operations":[{"op":"Remove","path":"members[value eq \"`+jdoe+`\"]"}]}`, 204)
	// jdoe's only access came from the group: login to the resource now fails.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("jdoe@example.com", e.Pass), 401)
	// Okta path-less replace sets the full member list.
	s.must("PATCH", "/Groups/"+group, `{`+patchSchema+`,"Operations":[{"op":"replace","value":{"id":"`+group+`","displayName":"Eng","members":[{"value":"`+jdoe+`","display":"jdoe"}]}}]}`, 204)
	if m := memberIDs(s.must("GET", "/Groups/"+group, "", 200).JSON); len(m) != 1 || m[0] != jdoe {
		t.Fatalf("after okta replace: %v", m)
	}
	// PUT replaces name and members.
	put := s.must("PUT", "/Groups/"+group, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"`+ann+`"}]}`, 200).JSON
	if put["displayName"] != "Engineering" || len(memberIDs(put)) != 1 || put["externalId"] != "grp-eng" {
		t.Fatalf("put: %v", put)
	}

	// Deprovisioning a user removes it from the directory's groups.
	s.must("DELETE", "/Users/"+ann, "", 204)
	if m := memberIDs(s.must("GET", "/Groups/"+group, "", 200).JSON); len(m) != 0 {
		t.Fatalf("after deprovision: %v", m)
	}

	// Isolation: another directory and operator groups are invisible.
	other, _ := newSCIM(t, e)
	other.must("GET", "/Groups/"+group, "", 404)
	other.must("PATCH", "/Groups/"+group, `{`+patchSchema+`,"Operations":[{"op":"remove","path":"members"}]}`, 404)
	manual := e.ID("POST", groups, fiber.Map{"name": "Manual"})
	s.must("GET", "/Groups/"+manual, "", 404)
	s.must("DELETE", "/Groups/"+manual, "", 404)
	if n := s.must("GET", "/Groups", "", 200).JSON["totalResults"]; n.(float64) != 1 {
		t.Fatalf("list isolation: %v", n)
	}
	// The console filters groups by source (invitations offer only manual ones).
	if l := items(e.Must("GET", groups+"?source=manual", e.Owner, nil, 200)); len(l) != 1 || l[0]["id"] != manual {
		t.Fatalf("manual groups = %v", l)
	}
	if l := items(e.Must("GET", groups+"?source=directory", e.Owner, nil, 200)); len(l) != 1 || l[0]["id"] != group {
		t.Fatalf("directory groups = %v", l)
	}
	e.Must("GET", groups+"?source=other", e.Owner, nil, 400)

	// DELETE cascades role bindings; the group answers 404 afterwards.
	s.must("DELETE", "/Groups/"+group, "", 204)
	s.must("GET", "/Groups/"+group, "", 404)
	if a := items(e.Must("GET", e.Base+"/group-role-assignments?organization_id="+e.Org, e.Owner, nil, 200)); len(a) != 0 {
		t.Fatalf("bindings after SCIM delete: %v", a)
	}
}
