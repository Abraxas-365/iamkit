package e2e_test

import (
	"context"
	"testing"

	"github.com/gofiber/fiber/v2"
)

type capturedMail struct{ Code string }

func (m *capturedMail) Send(_ context.Context, _, _, code string) error { m.Code = code; return nil }

func migrationJourney(t *testing.T, call func(string, string, string, any, int) map[string]any, mail *capturedMail, owner, base, devbase, env, org, user, member, client, resource string) {
	t.Helper()
	create := func(path string, body any) string { return call("POST", path, owner, body, 201)["id"].(string) }
	orgbase := base + "/organizations/" + org
	root := create(orgbase+"/org-units", fiber.Map{"name": "Europe", "kind": "region"})
	child := create(orgbase+"/org-units", fiber.Map{"name": "Spain", "kind": "country", "parent_id": root})
	call("PUT", orgbase+"/org-units/"+root, owner, fiber.Map{"name": "Europe", "kind": "region", "parent_id": child}, 400)
	call("DELETE", orgbase+"/org-units/"+root, owner, nil, 409)
	call("PUT", orgbase+"/members/"+member+"/profile", owner, fiber.Map{"org_unit_id": child, "manager_id": user}, 204)
	call("PUT", orgbase+"/members/"+user+"/profile", owner, fiber.Map{"manager_id": member}, 400)
	call("GET", orgbase+"/org-units/"+child, owner, nil, 200)
	call("GET", orgbase+"/org-units/"+root+"/delete-impact", owner, nil, 200)
	position := create(orgbase+"/positions", fiber.Map{"name": "Engineering lead", "code": "engineering_lead"})
	call("PUT", orgbase+"/positions/"+position, owner, fiber.Map{"name": "Lead", "code": "lead"}, 204)
	for _, path := range []string{"users/" + user, "organizations/" + org, "applications/" + client, "resources/" + resource} {
		call("GET", base+"/"+path, owner, nil, 200)
	}
	create(orgbase+"/position-assignments", fiber.Map{"position_id": position, "user_id": member, "org_unit_id": child})
	role := create(base+"/roles", fiber.Map{"name": "reader", "resource_id": resource, "permissions": []string{"invoices:read"}})
	call("POST", base+"/role-assignments", owner, fiber.Map{"role_id": role, "organization_id": org, "user_id": member}, 204)
	call("POST", devbase+"/role-assignments", owner, fiber.Map{"role_id": role, "organization_id": org, "user_id": member}, 404)
	login := fiber.Map{"environment_id": env, "organization_id": org, "application_id": client, "resource_id": resource, "email": "bob@example.com", "password": "correct horse battery"}
	pair := call("POST", "/identity/v1/login", "", login, 200)
	check := fiber.Map{"environment_id": env, "audience": "https://billing.example"}
	call("GET", "/identity/v1/me?environment_id="+env+"&audience=https://billing.example", pair["access_token"].(string), nil, 200)
	call("PATCH", "/identity/v1/me", pair["access_token"].(string), fiber.Map{"environment_id": env, "audience": "https://billing.example", "name": "Bob self profile"}, 204)
	imp := fiber.Map{"organization_id": org, "application_id": client, "resource_id": resource, "user_id": member, "reason": "Support ticket regression"}
	impersonated := call("POST", base+"/impersonations", owner, imp, 200)
	if _, ok := impersonated["refresh_token"]; ok {
		t.Fatal("impersonation has refresh")
	}
	if call("POST", "/identity/v1/introspect", impersonated["access_token"].(string), check, 200)["active"] != true {
		t.Fatal("impersonation inactive")
	}
	call("PATCH", "/identity/v1/me", impersonated["access_token"].(string), fiber.Map{"environment_id": env, "audience": "https://billing.example", "name": "Impersonated"}, 403)
	call("PATCH", base+"/users/"+member, owner, fiber.Map{"name": "Bob renamed"}, 204)
	call("PATCH", base+"/applications/"+client, owner, fiber.Map{"name": "Client renamed"}, 204)
	call("PATCH", base+"/organizations/"+org, owner, fiber.Map{"name": "Organization renamed"}, 204)
	if call("POST", "/identity/v1/introspect", pair["access_token"].(string), check, 200)["active"] != true {
		t.Fatal("profile edit revoked session")
	}
	refresh := fiber.Map{"environment_id": env, "organization_id": org, "application_id": client, "resource_id": resource, "refresh_token": pair["refresh_token"]}
	rotated := call("POST", "/identity/v1/refresh", "", refresh, 200)
	if rotated["refresh_token"] == pair["refresh_token"] {
		t.Fatal("refresh token did not rotate")
	}
	call("POST", "/identity/v1/refresh", "", refresh, 401)
	if call("POST", "/identity/v1/introspect", rotated["access_token"].(string), check, 200)["active"] != false {
		t.Fatal("refresh replay did not revoke family")
	}
	pair = call("POST", "/identity/v1/login", "", login, 200)
	call("DELETE", base+"/role-assignments/"+role+"/"+org+"/"+member, owner, nil, 204)
	call("POST", base+"/role-assignments", owner, fiber.Map{"role_id": role, "organization_id": org, "user_id": member}, 204)
	if call("POST", "/identity/v1/introspect", pair["access_token"].(string), check, 200)["active"] != false {
		t.Fatal("restored role revived session")
	}
	call("PATCH", base+"/users/"+member, owner, fiber.Map{"otp_enabled": true}, 204)
	challenge := call("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": env, "email": "bob@example.com", "purpose": "login"}, 202)
	verification := fiber.Map{"environment_id": env, "organization_id": org, "application_id": client, "resource_id": resource, "challenge_id": challenge["challenge_id"], "purpose": "login", "code": mail.Code}
	call("POST", "/identity/v1/challenges/verify", "", verification, 200)
	call("POST", "/identity/v1/challenges/verify", "", verification, 401)
	pending := call("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": env, "email": "bob@example.com", "purpose": "login"}, 202)
	verification["challenge_id"] = pending["challenge_id"]
	verification["code"] = mail.Code
	reset := call("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": env, "email": "bob@example.com", "purpose": "password_reset"}, 202)
	call("POST", "/identity/v1/challenges/verify", "", fiber.Map{"environment_id": env, "challenge_id": reset["challenge_id"], "purpose": "password_reset", "code": mail.Code, "password": "new secure password"}, 204)
	call("POST", "/identity/v1/challenges/verify", "", verification, 401)
	call("POST", "/identity/v1/login", "", login, 401)
	login["password"] = "new secure password"
	call("POST", "/identity/v1/login", "", login, 200)
	scim := call("POST", base+"/provisioning-credentials", owner, fiber.Map{"name": "HR", "organization_id": org}, 201)
	secret := scim["secret"].(string)
	call("GET", "/scim/v2/ResourceTypes/User", secret, nil, 200)
	call("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", secret, nil, 200)
	call("GET", "/management/v1/me", secret, nil, 401)
	provisioned := call("POST", "/scim/v2/Users", secret, fiber.Map{"userName": "provisioned@example.com", "displayName": "Provisioned", "externalId": "external-1"}, 201)
	id := provisioned["id"].(string)
	manager := call("POST", "/scim/v2/Users", secret, fiber.Map{"userName": "manager@example.com", "displayName": "Manager", "externalId": "manager-1"}, 201)["id"].(string)
	managerPatch := func(target string) fiber.Map {
		return fiber.Map{"Operations": []fiber.Map{{"op": "replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value", "value": target}}}
	}
	call("PATCH", "/scim/v2/Users/"+id, secret, managerPatch(manager), 200)
	call("PATCH", "/scim/v2/Users/"+manager, secret, managerPatch(id), 400)
	call("PATCH", "/scim/v2/Users/"+id, secret, managerPatch(user), 400)
	call("GET", "/scim/v2/Users/"+id, secret, nil, 200)
	call("GET", "/scim/v2/Users/"+user, secret, nil, 404)
	call("PATCH", "/scim/v2/Users/"+id, secret, fiber.Map{"Operations": []fiber.Map{{"op": "replace", "path": "active", "value": false}}}, 200)
	call("GET", "/scim/v2/Users?filter=externalId%20eq%20%22external-1%22", secret, nil, 200)
	replacement := call("POST", base+"/provisioning-credentials", owner, fiber.Map{"name": "Rotated HR", "organization_id": org, "connection_id": scim["connection_id"]}, 201)
	call("GET", "/scim/v2/Users/"+id, replacement["secret"].(string), nil, 200)
	call("PATCH", "/scim/v2/Users/"+id, replacement["secret"].(string), fiber.Map{"Operations": []fiber.Map{{"op": "replace", "path": "displayName", "value": "Local HR profile"}}}, 200)
	call("DELETE", base+"/provisioning-credentials/"+scim["id"].(string), owner, nil, 204)
	call("GET", "/scim/v2/Users/"+id, secret, nil, 401)
	call("PUT", base+"/resources/"+resource, owner, fiber.Map{"name": "Billing API", "permissions": []string{}}, 204)
	stored := call("GET", base+"/roles/"+role, owner, nil, 200)
	if len(stored["permissions"].([]any)) != 0 {
		t.Fatal("catalog shrink did not strip role permissions")
	}
	fresh := call("POST", "/identity/v1/login", "", login, 200)
	verified := call("POST", "/identity/v1/introspect", fresh["access_token"].(string), check, 200)
	if len(verified["claims"].(map[string]any)["permissions"].([]any)) != 0 {
		t.Fatal("removed catalog permission reissued")
	}
	call("PUT", base+"/resources/"+resource, owner, fiber.Map{"name": "Billing API", "permissions": []string{"invoices:read"}}, 204)
	call("PUT", base+"/grants", owner, fiber.Map{"organization_id": org, "user_id": user, "resource_id": resource, "permissions": []string{"invoices:read"}}, 200)
}
