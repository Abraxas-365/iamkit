// Package fiberauth integrates resource-bound access validation with Fiber v2.
package fiberauth

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/gofiber/fiber/v2"
)

type Validator func(context.Context, string) (*authclient.Claims, error)
type claimsKey struct{}

// Authenticate accepts a trusted, configured validator. Use Client.Introspect
// for live revocation, or authclient.Validate for explicitly offline validation.
func Authenticate(validate Validator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		value := strings.Fields(c.Get("Authorization"))
		if validate == nil || len(value) != 2 || !strings.EqualFold(value[0], "Bearer") {
			return fiber.ErrUnauthorized
		}
		claims, err := validate(c.UserContext(), value[1])
		if err != nil || claims == nil {
			return fiber.ErrUnauthorized
		}
		c.Locals(claimsKey{}, claims)
		return c.Next()
	}
}
func Claims(c *fiber.Ctx) *authclient.Claims {
	claims, _ := c.Locals(claimsKey{}).(*authclient.Claims)
	return claims
}
func RequirePermissions(required ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := Claims(c)
		if claims == nil {
			return fiber.ErrUnauthorized
		}
		for _, permission := range required {
			if permission == "" || !claims.HasPermission(permission) {
				return fiber.ErrForbidden
			}
		}
		return c.Next()
	}
}
func RequireOrganization(id string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := Claims(c)
		if claims == nil {
			return fiber.ErrUnauthorized
		}
		if id == "" || claims.Purpose != "application" || claims.OrganizationID != id {
			return fiber.ErrForbidden
		}
		return c.Next()
	}
}
