package provhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/gofiber/fiber/v2"
)

func scimDefinitions() []fiber.Map {
	attr := func(name, kind string, required bool) fiber.Map {
		return fiber.Map{"name": name, "type": kind, "multiValued": false, "required": required, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
	}
	manager := attr("manager", "complex", false)
	manager["subAttributes"] = []fiber.Map{attr("value", "string", false)}
	return []fiber.Map{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scimUserSchema, "name": "User", "attributes": []fiber.Map{attr("userName", "string", true), attr("displayName", "string", false), attr("active", "boolean", false), attr("externalId", "string", false)}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scimEnterpriseSchema, "name": "EnterpriseUser", "attributes": []fiber.Map{manager}},
	}
}
func scimSchemas(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": 2, "Resources": scimDefinitions()})
}
func scimSchema(c *fiber.Ctx) error {
	for _, definition := range scimDefinitions() {
		if definition["id"] == c.Params("id") {
			return c.JSON(definition)
		}
	}
	return errx.NotFound("schema not found")
}
func scimResourceType(c *fiber.Ctx) error {
	if c.Params("id") != "User" {
		return errx.NotFound("resource type not found")
	}
	return c.JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "schemaExtensions": []fiber.Map{{"schema": scimEnterpriseSchema, "required": false}}})
}
