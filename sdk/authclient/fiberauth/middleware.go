// Package fiberauth integrates resource-bound access validation with Fiber v2.
package fiberauth

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/gofiber/fiber/v2"
)

// errJSON returns a structured JSON error matching the IAMKit error format.
// This ensures SDK consumers get consistent error responses.
func errJSON(c *fiber.Ctx, status int, code, message string) error {
	c.Set("Cache-Control", "no-store")
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    code,
			"message": message,
		},
	})
}

// Validator resolves a bearer token to trusted claims.
type Validator func(context.Context, string) (*authclient.Claims, error)

type (
	claimsKey    struct{}
	principalKey struct{}
)

// APIKeyValidator resolves an API key value (ik_key_…) to the validated key;
// pass Client.ValidateAPIKey of a client built with authclient.WithAudience.
type APIKeyValidator func(context.Context, string) (authclient.APIKey, error)

type config struct{ keys APIKeyValidator }

// Option configures Authenticate.
type Option func(*config)

// AllowAPIKeys lets bearers starting with ik_key_ authenticate as API keys,
// validated by validate on every request (use Client.ValidateAPIKey). Off by
// default: without it an API key is a 401. The key becomes the request's
// Principal; Claims is nil for it.
func AllowAPIKeys(validate APIKeyValidator) Option {
	return func(c *config) { c.keys = validate }
}

// Authenticate accepts a trusted, configured validator. Use Client.Introspect
// for live revocation, or authclient.Validate for explicitly offline validation.
// With AllowAPIKeys an ik_key_ bearer is validated as an API key instead.
func Authenticate(validate Validator, options ...Option) fiber.Handler {
	var cfg config
	for _, option := range options {
		option(&cfg)
	}
	return func(c *fiber.Ctx) error {
		value := strings.Fields(c.Get("Authorization"))
		if len(value) != 2 || !strings.EqualFold(value[0], "Bearer") {
			return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
		}
		if authclient.IsAPIKey(value[1]) {
			if cfg.keys == nil {
				return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
			}
			key, err := cfg.keys(c.UserContext(), value[1])
			if err != nil || key.ID == "" {
				return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
			}
			c.Locals(principalKey{}, &authclient.Principal{APIKey: &key})
			return c.Next()
		}
		if validate == nil {
			return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
		}
		claims, err := validate(c.UserContext(), value[1])
		if err != nil || claims == nil {
			return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
		}
		c.Locals(claimsKey{}, claims)
		c.Locals(principalKey{}, &authclient.Principal{Claims: claims})
		return c.Next()
	}
}

// Claims returns the token claims stored by Authenticate, or nil (no
// Authenticate, or the request authenticated with an API key: see Principal).
func Claims(c *fiber.Ctx) *authclient.Claims {
	claims, _ := c.Locals(claimsKey{}).(*authclient.Claims)
	return claims
}

// Principal returns who Authenticate admitted — token claims or an API key,
// with the organization, permissions and (for keys) owner — or nil.
func Principal(c *fiber.Ctx) *authclient.Principal {
	principal, _ := c.Locals(principalKey{}).(*authclient.Principal)
	return principal
}

// APIKey returns the validated API key of the request, or nil when it
// authenticated with a token (or not at all).
func APIKey(c *fiber.Ctx) *authclient.APIKey {
	if p := Principal(c); p != nil {
		return p.APIKey
	}
	return nil
}

// RequirePermissions requires every listed permission to be held by the
// principal (token or API key); 401 without one, 403 when one is missing.
func RequirePermissions(required ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := Principal(c)
		if principal == nil {
			return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
		}
		for _, permission := range required {
			if permission == "" || !principal.HasPermission(permission) {
				return errJSON(c, fiber.StatusForbidden, "FORBIDDEN", "insufficient permissions")
			}
		}
		return c.Next()
	}
}

// RequireOrganization requires the principal to act in organization id: an
// "application" token bound to it or an API key of it. Compare it to a
// trusted organization, never to a route parameter alone.
func RequireOrganization(id string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := Principal(c)
		if principal == nil {
			return errJSON(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
		}
		if !principal.OrganizationBound(id) {
			return errJSON(c, fiber.StatusForbidden, "FORBIDDEN", "organization mismatch")
		}
		return c.Next()
	}
}
