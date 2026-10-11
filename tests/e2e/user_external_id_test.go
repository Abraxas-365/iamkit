package e2e_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestUserExternalID: users carry an optional external ID of the operator's
// own system — trimmed, at most 255 characters, unique per environment
// (409), set on create and update (null or "" clears, absent keeps), listed
// in every view, filtered with ?external_id=, recorded in the history, kept
// out of tokens and allowed on machine users; /api/v1 follows the users
// permissions.
func TestUserExternalID(t *testing.T) {
	e := newEnv(t)
	user := e.Base + "/users/" + e.Alice

	// Validation.
	e.Must("PATCH", user, e.Owner, fiber.Map{"external_id": strings.Repeat("x", 256)}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"external_id": "bad\nid"}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "o@example.com", "name": "O", "external_id": strings.Repeat("x", 256)}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"external_id": 42}, 400)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["external_id"]; got != "" {
		t.Fatalf("external_id before any change = %v", got)
	}

	// Set (trimmed), read, keep on unrelated updates.
	e.Must("PATCH", user, e.Owner, fiber.Map{"external_id": "  crm-42 "}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["external_id"]; got != "crm-42" {
		t.Fatalf("external_id = %v", got)
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"name": "Alice D"}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["external_id"]; got != "crm-42" {
		t.Fatal("an update without external_id keeps it")
	}

	// Unique per environment, on create and on update, case-sensitive.
	dup := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "o@example.com", "name": "O", "external_id": "crm-42"}, 409).Body
	if !strings.Contains(dup, "external_id") {
		t.Fatalf("duplicate on create = %s", dup)
	}
	other := e.ID("POST", e.Base+"/users", fiber.Map{"email": "o@example.com", "name": "O", "external_id": "CRM-42"})
	if !strings.Contains(e.Must("PATCH", e.Base+"/users/"+other, e.Owner, fiber.Map{"external_id": "crm-42"}, 409).Body, "external_id") {
		t.Fatal("duplicate on update does not name external_id")
	}
	third := e.ID("POST", e.Base+"/users", fiber.Map{"email": "p@example.com", "name": "P"})
	e.Must("PATCH", e.Base+"/users/"+third, e.Owner, fiber.Map{"external_id": ""}, 204) // clearing nothing is fine
	e.Must("PATCH", e.Base+"/users/"+other, e.Owner, fiber.Map{"external_id": nil}, 204)
	if got := e.Must("GET", e.Base+"/users/"+other, e.Owner, nil, 200).JSON["external_id"]; got != "" {
		t.Fatalf("external_id after null = %v", got)
	}
	// Several users without one never collide.
	e.Must("PATCH", e.Base+"/users/"+third, e.Owner, fiber.Map{"external_id": nil}, 204)

	// List: returned in rows, exact filter.
	listed := items(e.Must("GET", e.Base+"/users?external_id=crm-42", e.Owner, nil, 200))
	if len(listed) != 1 || listed[0]["id"] != e.Alice || listed[0]["external_id"] != "crm-42" {
		t.Fatalf("filter = %v", listed)
	}
	if got := items(e.Must("GET", e.Base+"/users?external_id=crm", e.Owner, nil, 200)); len(got) != 0 {
		t.Fatalf("the filter is exact, got %v", got)
	}
	if got := items(e.Must("GET", e.Base+"/users?external_id=nope", e.Owner, nil, 200)); len(got) != 0 {
		t.Fatalf("unknown external ID = %v", got)
	}
	if got := items(e.Must("GET", e.Base+"/users?search=crm-4", e.Owner, nil, 200)); len(got) != 1 {
		t.Fatalf("search by external ID = %v", got)
	}

	// History: the change is recorded as data.changes.external_id.
	history := e.Must("GET", user+"/history?type=user.updated", e.Owner, nil, 200)
	var found bool
	for _, it := range history.JSON["items"].([]any) {
		data, _ := it.(map[string]any)["data"].(map[string]any)
		changes, _ := data["changes"].(map[string]any)
		if fmt.Sprint(changes["external_id"]) == "[<nil> crm-42]" {
			found = true
		}
	}
	if !found {
		t.Fatalf("history lacks the external_id change: %s", history.Body)
	}
	cleared := e.Must("GET", e.Base+"/users/"+other+"/history?type=user.updated", e.Owner, nil, 200)
	if !strings.Contains(cleared.Body, "external_id") {
		t.Fatalf("clearing is not in the history: %s", cleared.Body)
	}

	// Machine users may have one; it is not released in tokens.
	bot := e.ID("POST", e.Base+"/users", fiber.Map{"kind": "machine", "name": "Sync", "external_id": "svc-1"})
	if got := e.Must("GET", e.Base+"/users/"+bot, e.Owner, nil, 200).JSON["external_id"]; got != "svc-1" {
		t.Fatalf("machine external_id = %v", got)
	}
	e.Must("PATCH", e.Base+"/users/"+bot, e.Owner, fiber.Map{"external_id": "svc-2"}, 204)
	if got := ids(e.Must("GET", e.Base+"/users?kind=machine&external_id=svc-2", e.Owner, nil, 200), "id"); len(got) != 1 || got[0] != bot {
		t.Fatalf("machine filter = %v", got)
	}
	token := e.Login(e.AliceEmail)
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil || strings.Contains(string(payload), "crm-42") || strings.Contains(string(payload), "external_id") {
		t.Fatalf("external_id in the token: %v %s", err, payload)
	}
	if me := e.Must("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+e.Audience, token, nil, 200).Body; strings.Contains(me, "crm-42") {
		t.Fatalf("external_id in /me: %s", me)
	}

	// /api/v1: reads need iam:users:read, writes iam:users:write.
	api := "/api/v1/environments/" + e.EnvID + "/users"
	reader, writer := e.scopedToken("iam:users:read"), e.scopedToken("iam:users:write")
	e.Must("GET", api+"?external_id=crm-42", "", nil, 401)
	e.Must("GET", api+"?external_id=crm-42", e.scopedToken("iam:orgs:read"), nil, 403)
	if got := items(e.Must("GET", api+"?external_id=crm-42", reader, nil, 200)); len(got) != 1 || got[0]["external_id"] != "crm-42" {
		t.Fatalf("api filter = %v", got)
	}
	if got := e.Must("GET", api+"/"+e.Alice, reader, nil, 200).JSON["external_id"]; got != "crm-42" {
		t.Fatalf("api user = %v", got)
	}
	e.Must("PATCH", api+"/"+e.Alice, reader, fiber.Map{"external_id": "x"}, 403)
	e.Must("PATCH", api+"/"+e.Alice, writer, fiber.Map{"external_id": "crm-43"}, 204)
	e.Must("PATCH", api+"/"+e.Alice, writer, fiber.Map{"external_id": nil}, 204)
	e.Must("POST", api, writer, fiber.Map{"email": "q@example.com", "name": "Q", "external_id": "crm-9"}, 201)
	e.Must("POST", api, writer, fiber.Map{"email": "r@example.com", "name": "R", "external_id": "crm-9"}, 409)
}

// TestUserExternalIDOrganizationAdmin: the external ID belongs to operators.
// Organization administrators read it and filter their users by it, but cannot
// set, change or clear it (the field is ignored); the home-organization rule
// still applies.
func TestUserExternalIDOrganizationAdmin(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	foreign := e.User("Gus", "gus@example.com")
	e.Join(e.Org, foreign) // a member whose record is not homed here
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	token := e.orgAdminToken(e.Org, e.AliceEmail)

	// Creating through the portal ignores external_id.
	id := e.Must("POST", admin+"/users", token, fiber.Map{"email": "nina@example.com", "name": "Nina", "external_id": "hr-7"}, 201).JSON["id"].(string)
	if got := e.Must("GET", admin+"/users/"+id, token, nil, 200).JSON["external_id"]; got != "" {
		t.Fatalf("external_id set by an organization administrator: %v", got)
	}

	// An operator sets it; administrators read and filter by it.
	e.Must("PATCH", e.Base+"/users/"+id, e.Owner, fiber.Map{"external_id": "hr-7"}, 204)
	if got := e.Must("GET", admin+"/users/"+id, token, nil, 200).JSON["external_id"]; got != "hr-7" {
		t.Fatalf("external_id = %v", got)
	}
	if got := items(e.Must("GET", admin+"/users?external_id=hr-7", token, nil, 200)); len(got) != 1 || got[0]["id"] != id {
		t.Fatalf("filter = %v", got)
	}

	// Updates, including null, leave it alone; a change with only the external
	// ID is an empty change.
	e.Must("PATCH", admin+"/users/"+id, token, fiber.Map{"name": "Nina R", "external_id": "hr-8"}, 204)
	e.Must("PATCH", admin+"/users/"+id, token, fiber.Map{"name": "Nina S", "external_id": nil}, 204)
	e.Must("PATCH", admin+"/users/"+id, token, fiber.Map{"external_id": "hr-8"}, 400)
	e.Must("PATCH", admin+"/users/"+foreign, token, fiber.Map{"name": "G", "external_id": "hr-9"}, 403)
	got := e.Must("GET", e.Base+"/users/"+id, e.Owner, nil, 200).JSON
	if got["external_id"] != "hr-7" || got["name"] != "Nina S" {
		t.Fatalf("after administrator updates: external_id=%v name=%v", got["external_id"], got["name"])
	}
}
