package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// active introspects token for the billing audience.
func (e *Env) active(token string) bool {
	e.t.Helper()
	res := e.Must("POST", "/identity/v1/introspect", token, fiber.Map{"environment_id": e.EnvID, "audience": e.Audience}, 200)
	return res.JSON["active"] == true
}

// ids collects the field of each paginated item.
func ids(res Response, field string) []string {
	items, _ := res.JSON["items"].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]any)[field].(string))
	}
	return out
}

// TestResourceGrants: a vendor organization owns a resource and grants it
// (all or some roles) to customer organizations, whose administrators
// then assign only granted roles; require_grant limits token access to
// the owner and granted organizations, and narrowing or revoking a grant
// ends the affected sessions.
func TestResourceGrants(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	owner := e.systemRole("org_owner")
	e.systemRole("org_resource_manager")

	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	writer := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "writer", "resource_id": e.Res, "permissions": []string{"invoices:write"}})
	other := e.ID("POST", e.Base+"/resources", fiber.Map{"name": "CRM", "prefix": "crm", "audience": "https://crm.example", "permissions": []string{"crm:read"}})
	// A taken prefix or audience is named.
	for field, body := range map[string]fiber.Map{
		"prefix":   {"name": "CRM 2", "prefix": "crm", "audience": "https://crm2.example"},
		"audience": {"name": "CRM 2", "prefix": "crm2", "audience": "https://crm.example"},
	} {
		msg := e.Must("POST", e.Base+"/resources", e.Owner, body, 409).JSON["error"].(map[string]any)["message"].(string)
		if !strings.HasPrefix(msg, field+" is already used") {
			t.Fatalf("duplicate %s: %q", field, msg)
		}
	}
	otherRole := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "crm reader", "resource_id": other, "permissions": []string{"crm:read"}})

	// Vendor owns Billing; Vic administers Vendor, Alice administers Acme.
	vendor := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Vendor"})
	vic := e.User("Vic", "vic@example.com")
	e.Join(vendor, vic)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": vendor, "user_id": vic, "role_id": owner}, 204)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": owner}, 204)
	olga := e.User("Olga", "olga@example.com")
	e.Join(e.Org, olga)

	// Default: owning a resource changes nothing for other organizations.
	e.Must("PUT", e.Base+"/resources/"+e.Res+"/access", e.Owner, fiber.Map{"owner_organization_id": vendor}, 204)
	found := e.Must("GET", e.Base+"/resources/"+e.Res, e.Owner, nil, 200).JSON
	if found["owner_organization_id"] != vendor || found["require_grant"] != false {
		t.Fatalf("resource access = %v", found)
	}
	before := e.Login(e.AliceEmail)
	if got := e.permissions(before); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("permissions before require_grant = %v", got)
	}

	// Operator rules.
	e.Must("PUT", e.Base+"/resources/"+iam+"/access", e.Owner, fiber.Map{"require_grant": true}, 422)
	e.Must("PUT", e.Base+"/resource-grants", e.Owner, fiber.Map{"resource_id": iam, "organization_id": e.Org}, 422)
	e.Must("PUT", e.Base+"/resources/"+iam, e.Owner, fiber.Map{"name": "IAM", "permissions": []string{}}, 422)
	e.Must("PUT", e.Base+"/resource-grants", e.Owner, fiber.Map{"resource_id": e.Res, "organization_id": vendor}, 422)
	e.Must("PUT", e.Base+"/resource-grants", e.Owner, fiber.Map{"resource_id": e.Res, "organization_id": e.Org, "role_ids": []string{otherRole}}, 400)
	e.Must("PUT", e.Base+"/resources/"+e.Res+"/access", e.Owner, fiber.Map{"owner_organization_id": "00000000-0000-4000-8000-000000000001"}, 404)

	// Organization administrators see no grant before one exists.
	aliceAdmin := e.orgAdminToken(e.Org, e.AliceEmail)
	vicAdmin := e.orgAdminToken(vendor, "vic@example.com")
	acme := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	vend := "/api/v1/environments/" + e.EnvID + "/organizations/" + vendor + "/admin"
	if roles := ids(e.Must("GET", acme+"/roles", aliceAdmin, nil, 200), "id"); contains(roles, reader) || contains(roles, writer) {
		t.Fatalf("ungranted roles offered: %v", roles)
	}
	e.Must("POST", acme+"/role-assignments", aliceAdmin, fiber.Map{"user_id": olga, "role_id": reader}, 403)

	// require_grant: Acme loses access and its sessions end.
	e.Must("PUT", e.Base+"/resources/"+e.Res+"/access", e.Owner, fiber.Map{"owner_organization_id": vendor, "require_grant": true}, 204)
	if e.active(before) {
		t.Fatal("session of an ungranted organization survived require_grant")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 401)

	// The vendor grants Billing to Acme with the reader role only.
	if res := ids(e.Must("GET", vend+"/resources", vicAdmin, nil, 200), "id"); len(res) != 1 || res[0] != e.Res {
		t.Fatalf("vendor resources = %v", res)
	}
	e.Must("GET", acme+"/resources", aliceAdmin, nil, 200)
	grant := e.Must("PUT", vend+"/resource-grants", vicAdmin, fiber.Map{"resource_id": e.Res, "organization_id": e.Org, "role_ids": []string{reader}}, 200).JSON
	if grant["organization_name"] != "Acme" || len(grant["role_ids"].([]any)) != 1 {
		t.Fatalf("grant = %v", grant)
	}
	grantID := grant["id"].(string)
	// Only resources the organization owns.
	e.Must("PUT", vend+"/resource-grants", vicAdmin, fiber.Map{"resource_id": other, "organization_id": e.Org}, 404)
	e.Must("PUT", acme+"/resource-grants", aliceAdmin, fiber.Map{"resource_id": e.Res, "organization_id": e.Org}, 404)
	e.Must("DELETE", acme+"/resource-grants/"+grantID, aliceAdmin, nil, 404)
	if got := ids(e.Must("GET", acme+"/granted-resources", aliceAdmin, nil, 200), "id"); len(got) != 1 || got[0] != grantID {
		t.Fatalf("granted resources = %v", got)
	}
	if got := ids(e.Must("GET", vend+"/resource-grants", vicAdmin, nil, 200), "id"); len(got) != 1 || got[0] != grantID {
		t.Fatalf("vendor grants = %v", got)
	}
	if got := ids(e.Must("GET", acme+"/resource-grants", aliceAdmin, nil, 200), "id"); len(got) != 0 {
		t.Fatalf("customer sees grants of resources it does not own: %v", got)
	}

	// Direct grants count again; of roles, only granted ones.
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": writer}, 204)
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("permissions with an ungranted role = %v", got)
	}
	// effective-roles explains it: the writer role is held but not granted.
	granted := map[string]any{}
	for _, it := range e.Must("GET", e.Base+"/effective-roles?organization_id="+e.Org+"&user_id="+e.Alice, e.Owner, nil, 200).JSON["items"].([]any) {
		item := it.(map[string]any)
		granted[item["role_id"].(string)] = item["granted"]
	}
	if granted[writer] != false || granted[owner] != true {
		t.Fatalf("effective-roles granted = %v", granted)
	}
	// Acme's administrator assigns the granted role only.
	if roles := ids(e.Must("GET", acme+"/roles", aliceAdmin, nil, 200), "id"); !contains(roles, reader) || contains(roles, writer) || contains(roles, otherRole) {
		t.Fatalf("assignable roles = %v", roles)
	}
	e.Must("POST", acme+"/role-assignments", aliceAdmin, fiber.Map{"user_id": olga, "role_id": reader}, 204)
	e.Must("POST", acme+"/role-assignments", aliceAdmin, fiber.Map{"user_id": olga, "role_id": writer}, 403)
	olgaToken := e.Must("POST", "/identity/v1/login", "", e.LoginBody("olga@example.com", e.Pass), 200).JSON["access_token"].(string)
	if got := e.permissions(olgaToken); !equal(got, []string{"invoices:read"}) {
		t.Fatalf("olga permissions = %v", got)
	}

	// Widening to all roles keeps sessions and adds writer.
	e.Must("PUT", vend+"/resource-grants", vicAdmin, fiber.Map{"resource_id": e.Res, "organization_id": e.Org, "role_ids": nil}, 200)
	wide := e.Login(e.AliceEmail)
	if !e.active(olgaToken) {
		t.Fatal("widening a grant ended sessions")
	}
	if got := e.permissions(wide); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("permissions with every role granted = %v", got)
	}

	// Narrowing ends Acme's sessions for Billing.
	e.Must("PUT", vend+"/resource-grants", vicAdmin, fiber.Map{"resource_id": e.Res, "organization_id": e.Org, "role_ids": []string{reader}}, 200)
	if e.active(wide) || e.active(olgaToken) {
		t.Fatal("narrowing a grant left sessions alive")
	}

	// The operator API sees the same grant.
	scoped := e.scopedToken("iam:roles:read", "iam:roles:write")
	api := "/api/v1/environments/" + e.EnvID
	if got := ids(e.Must("GET", api+"/resource-grants?resource_id="+e.Res, scoped, nil, 200), "id"); len(got) != 1 || got[0] != grantID {
		t.Fatalf("api grants = %v", got)
	}
	e.Must("GET", api+"/resource-grants", e.scopedToken("iam:users:read"), nil, 403)
	e.Must("GET", api+"/resource-grants/"+grantID, scoped, nil, 200)

	// Revoking ends access; the vendor keeps it.
	last := e.Login(e.AliceEmail)
	e.Must("DELETE", vend+"/resource-grants/"+grantID, vicAdmin, nil, 204)
	if e.active(last) {
		t.Fatal("revoking a grant left the session alive")
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 401)
	e.Grant(vendor, vic, e.Res, "invoices:write")
	vicBody := e.LoginBody("vic@example.com", e.Pass)
	vicBody["organization_id"] = vendor
	e.Must("POST", "/identity/v1/login", "", vicBody, 200)
	if n := count(t, e.DB, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND actor_kind='user' AND organization_id=$2 AND target_id LIKE '%/resource-grants%'`, e.EnvID, vendor); n != 4 {
		t.Fatalf("vendor grant audit events = %d", n)
	}
	// The grant events name the grant, its resource, grantee and roles
	// (role_ids null = every role); the scope stays the owner organization.
	grantRes := e.Must("GET", e.Base+"/events?type=resource_grant.*&subject="+grantID, e.Owner, nil, 200)
	grantEvents := grantRes.JSON["items"].([]any)
	if got := eventTypes(grantRes); !equal(got, []string{"resource_grant.deleted", "resource_grant.updated", "resource_grant.updated", "resource_grant.updated"}) {
		t.Fatalf("grant events = %v", got)
	}
	for i, it := range grantEvents {
		ev := it.(map[string]any)
		data := ev["data"].(map[string]any)
		if data["resource_id"] != e.Res || data["granted_organization_id"] != e.Org || ev["organization_id"] != vendor || ev["actor"].(map[string]any)["id"] != vic {
			t.Fatalf("grant event %d = %v", i, ev)
		}
	}
	if roles := grantEvents[1].(map[string]any)["data"].(map[string]any)["role_ids"].([]any); len(roles) != 1 || roles[0] != reader {
		t.Fatalf("narrowed grant roles = %v", roles)
	}
	if roles, ok := grantEvents[2].(map[string]any)["data"].(map[string]any)["role_ids"]; !ok || roles != nil {
		t.Fatalf("widened grant roles = %v (%v)", roles, ok)
	}

	// Turning require_grant off restores every organization.
	e.Must("PUT", api+"/resources/"+e.Res+"/access", e.scopedToken("iam:resources:read", "iam:resources:write"), fiber.Map{"owner_organization_id": vendor, "require_grant": false}, 204)
	if got := e.permissions(e.Login(e.AliceEmail)); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("permissions without require_grant = %v", got)
	}
}
