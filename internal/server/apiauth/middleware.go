// Package apiauth provides JWT-based authentication and permission enforcement
// for the /api/v1/* route group. Service account and user JWTs authenticate
// through this middleware; raw API keys (ik_mgmt_, ik_svc_, ik_scim_) are rejected.
package apiauth

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
)

type tokenKey struct{}

// Middleware validates a JWT Bearer token and stores the parsed token in context.
type Middleware struct {
	validator authentication.TokenValidator
}

// New creates the API auth middleware backed by the given token validator.
func New(v authentication.TokenValidator) *Middleware { return &Middleware{validator: v} }

// Authenticate extracts and validates the JWT from the Authorization header.
// On success it stores the parsed token in context. The downstream router must
// include an :environment param; this middleware verifies it matches the JWT.
func (m *Middleware) Authenticate(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")

	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return errx.Unauthorized("bearer token required")
	}
	raw := parts[1]
	// Reject raw API keys — this route group accepts JWTs only.
	if strings.HasPrefix(raw, "ik_") {
		return errx.Unauthorized("JWT access token required, not an API key")
	}
	token, err := m.validator.ValidateSelf(c.Context(), raw)
	if err != nil {
		return errx.Unauthorized("invalid or expired token")
	}
	// If the route includes :environment, verify it matches the JWT.
	if env := c.Params("environment"); env != "" && env != token.EnvironmentID {
		return errx.Forbidden("token not scoped to this environment")
	}
	c.Locals(tokenKey{}, token)
	return c.Next()
}

// Token returns the validated JWT claims from the request context.
func Token(c *fiber.Ctx) authentication.Token {
	t, _ := c.Locals(tokenKey{}).(authentication.Token)
	return t
}

// ActorID returns the JWT subject — used as the actor for audit mutations.
func ActorID(c *fiber.Ctx) string {
	return Token(c).Subject
}

// Environment returns the environment ID from the JWT claims.
func Environment(c *fiber.Ctx) string {
	return Token(c).EnvironmentID
}

// RequirePermission checks that the JWT carries the given permission.
func RequirePermission(perm string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		for _, p := range Token(c).Permissions {
			if p == perm {
				return c.Next()
			}
		}
		return errx.Forbidden("missing permission: " + perm)
	}
}

// ReadWrite requires the read permission for GET/HEAD, the write permission otherwise.
func ReadWrite(read, write string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		required := write
		if c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead {
			required = read
		}
		for _, p := range Token(c).Permissions {
			if p == required {
				return c.Next()
			}
		}
		return errx.Forbidden("missing permission: " + required)
	}
}
