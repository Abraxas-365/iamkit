package e2e_test

import (
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/gofiber/fiber/v2"
)

// exchangeSetup trades a setup URL's fragment for the setup bearer.
func (e *Env) exchangeSetup(url string, want int) Response {
	e.t.Helper()
	_, secret, _ := strings.Cut(url, "#")
	return e.Must("POST", "/identity/v1/org-admin/setup", "", fiber.Map{"token": secret}, want)
}

// TestSetupLinks: an operator (or an organization owner) gives the customer's
// IT administrator an expiring link; its bearer configures only what the
// link's intents allow, and dies with the link.
func TestSetupLinks(t *testing.T) {
	e := newEnv(t)
	idp := samltest.New("https://idp.example.com")
	links := e.Base + "/organizations/" + e.Org + "/setup-links"
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"

	// Validation.
	e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{}}, 400)
	e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"nope"}}, 400)
	e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}, "expires_in": "1s"}, 400)
	e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}, "expires_in": "721h"}, 400)
	e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}, "expires_in": "soon"}, 400)
	e.Must("POST", e.Base+"/organizations/00000000-0000-4000-8000-00000000dead/setup-links", e.Owner, fiber.Map{"intents": []string{"sso"}}, 404)

	// A full link: operator creates, URL carries the secret in its fragment.
	issued := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso", "directory", "domains"}, "expires_in": "48h"}, 201).JSON
	url := issued["url"].(string)
	if !strings.HasPrefix(url, "https://iam.example/org-admin/"+e.EnvID+"/setup#ik_setup_") || issued["id"] == "" {
		t.Fatalf("issued = %v", issued)
	}
	linkID := issued["id"].(string)

	// Listing never shows secrets.
	list := e.Must("GET", links, e.Owner, nil, 200)
	if strings.Contains(list.Body, "ik_setup_") || strings.Contains(list.Body, "secret") || list.JSON["page"].(map[string]any)["total"].(float64) != 1 {
		t.Fatalf("list = %s", list.Body)
	}

	// Unknown, malformed and empty tokens are one 401 (or 400 when absent).
	e.Must("POST", "/identity/v1/org-admin/setup", "", fiber.Map{"token": "ik_setup_unknown"}, 401)
	e.Must("POST", "/identity/v1/org-admin/setup", "", fiber.Map{"token": "garbage"}, 401)
	e.Must("POST", "/identity/v1/org-admin/setup", "", fiber.Map{}, 400)

	session := e.exchangeSetup(url, 200).JSON
	bearer := session["access_token"].(string)
	if !strings.HasPrefix(bearer, "ik_setupsess_") || session["token_type"] != "Bearer" || session["organization_id"] != e.Org || session["environment_id"] != e.EnvID || session["organization_name"] == "" || session["expires_in"].(float64) <= 0 {
		t.Fatalf("session = %v", session)
	}
	var used *string
	if err := e.DB.Get(&used, `SELECT last_used_at::text FROM org_setup_links WHERE id=$1`, linkID); err != nil || used == nil {
		t.Fatalf("last_used_at = %v %v", used, err)
	}

	// The bearer configures SSO, SCIM and domains…
	conn := e.Must("POST", admin+"/connections", bearer, fiber.Map{"name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata()}}, 201).JSON
	e.Must("GET", admin+"/connections/"+conn["id"].(string), bearer, nil, 200)
	dir := e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta SCIM"}, 201).JSON
	if !strings.HasPrefix(dir["secret"].(string), "ik_scim_") {
		t.Fatalf("directory = %v", dir)
	}
	e.Must("POST", admin+"/domains", bearer, fiber.Map{"domain": "customer.example"}, 201)
	e.Must("GET", admin+"/domains", bearer, nil, 200)
	e.Must("GET", admin, bearer, nil, 200)

	// …and nothing else.
	for _, p := range []string{"/members", "/roles", "/users", "/invitations", "/events", "/resources", "/resource-grants", "/branding", "/password-policy", "/setup-links"} {
		e.Must("GET", admin+p, bearer, nil, 403)
	}
	e.Must("POST", admin+"/setup-links", bearer, fiber.Map{"intents": []string{"sso"}}, 403)
	e.Must("POST", admin+"/invitations", bearer, fiber.Map{"email": "x@example.com"}, 403)
	e.Must("PATCH", admin, bearer, fiber.Map{"name": "Hacked"}, 403)

	// Only that organization's /admin routes, in that environment.
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+globex+"/admin/domains", bearer, nil, 403)
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/users", bearer, nil, 403)
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+e.Org+"/setup-links", bearer, nil, 403)
	e.Must("GET", e.Base+"/users", bearer, nil, 401)

	// A domains-only link cannot create connections or directories.
	domainsOnly := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"domains"}}, 201).JSON
	domainsBearer := e.exchangeSetup(domainsOnly["url"].(string), 200).JSON["access_token"].(string)
	e.Must("POST", admin+"/domains", domainsBearer, fiber.Map{"domain": "other.example"}, 201)
	e.Must("POST", admin+"/connections", domainsBearer, fiber.Map{"name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata()}}, 403)
	e.Must("POST", admin+"/directories", domainsBearer, fiber.Map{"name": "Okta"}, 403)
	// An sso-only link cannot touch domains.
	ssoOnly := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}}, 201).JSON
	ssoBearer := e.exchangeSetup(ssoOnly["url"].(string), 200).JSON["access_token"].(string)
	e.Must("POST", admin+"/domains", ssoBearer, fiber.Map{"domain": "third.example"}, 403)
	e.Must("GET", admin+"/connections", ssoBearer, nil, 200)

	// Events carry the link as the actor.
	events := e.Must("GET", e.Base+"/events?limit=200&subject="+linkID, e.Owner, nil, 200)
	types := eventTypes(events)
	if !contains(types, "org_setup_link.used") || !contains(types, "org_setup_link.created") {
		t.Fatalf("link events = %v", types)
	}
	var kind string
	if err := e.DB.Get(&kind, `SELECT actor_kind FROM events WHERE type='org_setup_link.used' AND subject_id=$1 AND environment_id=$2`, linkID, e.EnvID); err != nil || kind != "setup_link" {
		t.Fatalf("used actor kind = %q %v", kind, err)
	}
	var changeKind string
	if err := e.DB.Get(&changeKind, `SELECT actor_kind FROM events WHERE type='connection.created' AND actor_id=$1`, linkID); err != nil || changeKind != "setup_link" {
		t.Fatalf("connection actor kind = %q %v", changeKind, err)
	}
	var auditKind string
	if err := e.DB.Get(&auditKind, `SELECT actor_kind FROM audit_events WHERE actor_id=$1 ORDER BY created_at DESC LIMIT 1`, linkID); err != nil || auditKind != "setup_link" {
		t.Fatalf("audit actor kind = %q %v", auditKind, err)
	}

	// Revoking ends the link and the bearers already exchanged from it.
	e.Must("DELETE", links+"/"+linkID, e.Owner, nil, 204)
	e.Must("DELETE", links+"/"+linkID, e.Owner, nil, 404)
	e.Must("DELETE", links+"/not-a-uuid", e.Owner, nil, 404)
	e.exchangeSetup(url, 401)
	e.Must("GET", admin+"/domains", bearer, nil, 401)
	e.Must("GET", admin+"/domains", domainsBearer, nil, 200)
	if got := eventTypes(e.Must("GET", e.Base+"/events?type=org_setup_link.*&limit=200", e.Owner, nil, 200)); !contains(got, "org_setup_link.revoked") {
		t.Fatalf("events = %v", got)
	}

	// Expiry (backdated): exchange and existing bearers are refused.
	if _, err := e.DB.Exec(`UPDATE org_setup_links SET expires_at=now() - interval '1 minute' WHERE id=$1`, domainsOnly["id"]); err != nil {
		t.Fatal(err)
	}
	e.Must("GET", admin+"/domains", domainsBearer, nil, 401)
	e.exchangeSetup(domainsOnly["url"].(string), 401)

	// A bearer past its own short life is refused too.
	if _, err := e.DB.Exec(`UPDATE org_setup_sessions SET expires_at=now() - interval '1 second' WHERE link_id=$1`, ssoOnly["id"]); err != nil {
		t.Fatal(err)
	}
	e.Must("GET", admin+"/connections", ssoBearer, nil, 401)
}

// TestSetupLinksOperatorAPI: /api/v1 needs iam:orgs:read / iam:orgs:write.
func TestSetupLinksOperatorAPI(t *testing.T) {
	e := newEnv(t)
	api := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/setup-links"
	reader := e.scopedToken("iam:orgs:read")
	writer := e.scopedToken("iam:orgs:read", "iam:orgs:write")
	none := e.scopedToken("iam:users:read")
	body := fiber.Map{"intents": []string{"domains"}}
	e.Must("POST", api, reader, body, 403)
	e.Must("POST", api, none, body, 403)
	e.Must("GET", api, none, nil, 403)
	issued := e.Must("POST", api, writer, body, 201).JSON
	e.Must("GET", api, reader, nil, 200)
	e.Must("DELETE", api+"/"+issued["id"].(string), reader, nil, 403)
	e.Must("DELETE", api+"/"+issued["id"].(string), writer, nil, 204)
	e.exchangeSetup(issued["url"].(string), 401)
	var kind string
	if err := e.DB.Get(&kind, `SELECT actor_kind FROM events WHERE type='org_setup_link.created' AND subject_id=$1`, issued["id"]); err != nil || kind != "service_account" {
		t.Fatalf("created actor kind = %q %v", kind, err)
	}
}

// TestSetupLinksPortalOwners: only principals holding every organization
// permission manage links from the portal.
func TestSetupLinksPortalOwners(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"home_organization_id": e.Org}, 204)
	mallory := e.User("Mallory", "mallory@example.com")
	e.Join(e.Org, mallory)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": mallory, "role_id": e.systemRole("org_user_manager")}, 204)
	alice := e.orgAdminToken(e.Org, e.AliceEmail)
	malloryToken := e.orgAdminToken(e.Org, "mallory@example.com")
	links := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin/setup-links"

	e.Must("GET", links, malloryToken, nil, 403)
	e.Must("POST", links, malloryToken, fiber.Map{"intents": []string{"sso"}}, 403)
	e.Must("POST", links, alice, fiber.Map{"intents": []string{}}, 400)
	issued := e.Must("POST", links, alice, fiber.Map{"intents": []string{"sso", "domains"}}, 201).JSON
	if !strings.Contains(issued["url"].(string), "/org-admin/"+e.EnvID+"/setup#ik_setup_") {
		t.Fatalf("issued = %v", issued)
	}
	list := e.Must("GET", links, alice, nil, 200)
	if strings.Contains(list.Body, "ik_setup_") || list.JSON["page"].(map[string]any)["total"].(float64) != 1 {
		t.Fatalf("list = %s", list.Body)
	}
	e.Must("DELETE", links+"/"+issued["id"].(string), malloryToken, nil, 403)
	e.Must("DELETE", links+"/"+issued["id"].(string), alice, nil, 204)
	e.exchangeSetup(issued["url"].(string), 401)
	var kind string
	if err := e.DB.Get(&kind, `SELECT actor_kind FROM events WHERE type='org_setup_link.created' AND subject_id=$1`, issued["id"]); err != nil || kind != "user" {
		t.Fatalf("created actor kind = %q %v", kind, err)
	}
}

// TestSetupLinkConnectionGroups: the groups a connection signs people into
// carry roles, so a setup link's bearer may only name groups whose roles it
// could assign itself (none, with sso-only permissions).
func TestSetupLinkConnectionGroups(t *testing.T) {
	e := newEnv(t)
	idp := samltest.New("https://idp.example.com")
	links := e.Base + "/organizations/" + e.Org + "/setup-links"
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	issued := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"sso"}}, 201).JSON
	bearer := e.exchangeSetup(issued["url"].(string), 200).JSON["access_token"].(string)

	owners := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Owners"})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": e.systemRole("org_owner"), "organization_id": e.Org, "group_id": owners}, 204)
	readers := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Readers"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": readers}, 204)
	plain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Plain"})

	create := func(extra fiber.Map, want int) Response {
		body := fiber.Map{"name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata()}}
		for k, v := range extra {
			body[k] = v
		}
		return e.Must("POST", admin+"/connections", bearer, body, want)
	}
	for _, group := range []string{owners, readers} {
		create(fiber.Map{"jit_group_id": group}, 403)
		create(fiber.Map{"signup_group_id": group}, 403)
		create(fiber.Map{"group_mappings": []fiber.Map{{"value": "staff", "group_id": plain}, {"value": "root", "group_id": group}}}, 403)
	}
	conn := create(fiber.Map{"jit_group_id": plain, "group_mappings": []fiber.Map{{"value": "staff", "group_id": plain}}}, 201).JSON["id"].(string)
	var count int
	if err := e.DB.Get(&count, `SELECT count(*) FROM federation_connections WHERE environment_id=$1 AND organization_id=$2`, e.EnvID, e.Org); err != nil || count != 1 {
		t.Fatalf("connections = %d %v", count, err)
	}

	// Updates are checked on the fields being set only.
	path := admin + "/connections/" + conn
	e.Must("PATCH", path, bearer, fiber.Map{"jit_group_id": owners}, 403)
	e.Must("PATCH", path, bearer, fiber.Map{"signup_group_id": readers}, 403)
	e.Must("PATCH", path, bearer, fiber.Map{"group_mappings": []fiber.Map{{"value": "root", "group_id": owners}}}, 403)
	e.Must("PATCH", path, bearer, fiber.Map{"enforcement": "optional"}, 204)
	e.Must("PATCH", path, bearer, fiber.Map{"jit_group_id": plain}, 204)
}

// TestSetupLinkDirectoryLimits: a setup link's bearer cannot adopt existing
// members into a directory nor issue a SCIM token that never expires.
func TestSetupLinkDirectoryLimits(t *testing.T) {
	e := newEnv(t)
	links := e.Base + "/organizations/" + e.Org + "/setup-links"
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	issued := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"directory"}}, 201).JSON
	bearer := e.exchangeSetup(issued["url"].(string), 200).JSON["access_token"].(string)

	if r := e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta", "adopt_existing_members": true}, 400); !strings.Contains(r.Body, "adopt_existing_members") {
		t.Fatalf("adopt: %s", r.Body)
	}
	if r := e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta", "expires_in": "never"}, 400); !strings.Contains(r.Body, "expires_in") {
		t.Fatalf("never: %s", r.Body)
	}
	e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta", "expires_in": "8761h"}, 400)
	e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta", "expires_in": "8760h", "adopt_existing_members": false}, 201)
	e.Must("POST", admin+"/directories", bearer, fiber.Map{"name": "Okta"}, 201)
}

// TestSetupLinkInactiveOrganization: deactivating the organization stops
// its links and the bearers already exchanged from them.
func TestSetupLinkInactiveOrganization(t *testing.T) {
	e := newEnv(t)
	links := e.Base + "/organizations/" + e.Org + "/setup-links"
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	live := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"domains"}}, 201).JSON
	fresh := e.Must("POST", links, e.Owner, fiber.Map{"intents": []string{"domains"}}, 201).JSON
	bearer := e.exchangeSetup(live["url"].(string), 200).JSON["access_token"].(string)
	e.Must("GET", admin+"/domains", bearer, nil, 200)

	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"active": false}, 204)
	e.Must("GET", admin+"/domains", bearer, nil, 401)
	e.exchangeSetup(fresh["url"].(string), 401)

	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"active": true}, 204)
	e.Must("GET", admin+"/domains", bearer, nil, 200)
	e.exchangeSetup(fresh["url"].(string), 200)
}
