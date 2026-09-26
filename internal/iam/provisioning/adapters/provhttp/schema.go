package provhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/gofiber/fiber/v2"
)

const scimSchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"

// scimDefinitions describes exactly what IAMKit stores and returns. userName
// is renamable; externalId is immutable once the directory has set it.
func scimDefinitions() []fiber.Map {
	attr := func(name, kind, mutability string, required bool) fiber.Map {
		return fiber.Map{"name": name, "type": kind, "multiValued": false, "required": required, "caseExact": false, "mutability": mutability, "returned": "default", "uniqueness": "none"}
	}
	userName := attr("userName", "string", "readWrite", true)
	userName["uniqueness"] = "server"
	externalID := attr("externalId", "string", "immutable", false)
	externalID["caseExact"] = true
	name := attr("name", "complex", "readWrite", false)
	name["subAttributes"] = []fiber.Map{attr("formatted", "string", "readWrite", false), attr("givenName", "string", "writeOnly", false), attr("familyName", "string", "writeOnly", false)}
	emails := attr("emails", "complex", "readWrite", false)
	emails["multiValued"] = true
	emails["subAttributes"] = []fiber.Map{attr("value", "string", "readWrite", false), attr("type", "string", "readWrite", false), attr("primary", "boolean", "readWrite", false)}
	managerValue := attr("value", "string", "readWrite", false)
	managerValue["caseExact"] = true
	manager := attr("manager", "complex", "readWrite", false)
	manager["subAttributes"] = []fiber.Map{managerValue}
	meta := func(id string) fiber.Map {
		return fiber.Map{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + id}
	}
	return []fiber.Map{
		{"schemas": []string{scimSchemaSchema}, "id": scimUserSchema, "name": "User", "description": "User account", "meta": meta(scimUserSchema), "attributes": []fiber.Map{
			userName, attr("displayName", "string", "readWrite", false), name, attr("active", "boolean", "readWrite", false), externalID, emails,
		}},
		{"schemas": []string{scimSchemaSchema}, "id": scimEnterpriseSchema, "name": "EnterpriseUser", "description": "Enterprise user extension", "meta": meta(scimEnterpriseSchema), "attributes": []fiber.Map{manager}},
		groupSchemaDefinition(attr),
	}
}
func userResourceType() fiber.Map {
	return fiber.Map{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema,
		"schemaExtensions": []fiber.Map{{"schema": scimEnterpriseSchema, "required": false}},
		"meta":             fiber.Map{"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"},
	}
}
func scimSchemas(c *fiber.Ctx) error {
	defs := scimDefinitions()
	return send(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": len(defs), "itemsPerPage": len(defs), "startIndex": 1, "Resources": defs})
}
func scimSchema(c *fiber.Ctx) error {
	for _, definition := range scimDefinitions() {
		if definition["id"] == c.Params("id") {
			return send(c, 200, definition)
		}
	}
	return errx.NotFound("schema not found")
}
func scimResourceType(c *fiber.Ctx) error {
	switch c.Params("id") {
	case "User":
		return send(c, 200, userResourceType())
	case "Group":
		return send(c, 200, groupResourceType())
	}
	return errx.NotFound("resource type not found")
}
