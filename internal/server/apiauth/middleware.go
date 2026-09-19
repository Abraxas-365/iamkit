// Package apiauth provides JWT-based authentication and permission enforcement
// for the /api/v1/* route group.
package apiauth

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type tokenKey struct{}

type Middleware struct {
	validator authentication.TokenValidator
}

func New(v authentication.TokenValidator) *Middleware { return &Middleware{validator: v} }

func (m *Middleware) Authenticate(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")

	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return errx.Unauthorized("bearer token required")
	}
	raw := parts[1]
	if strings.HasPrefix(raw, "ik_") {
		return errx.Unauthorized("JWT access token required, not an API key")
	}
	token, err := m.validator.ValidateSelf(c.Context(), raw)
	if err != nil {
		return errx.Unauthorized("invalid or expired token")
	}
	if env := c.Params("environment"); env != "" {
		envID, parseErr := identity.ParseEnvironmentID(env)
		if parseErr != nil || envID != token.EnvironmentID {
			return errx.Forbidden("token not scoped to this environment")
		}
	}
	c.Locals(tokenKey{}, token)
	return c.Next()
}

func Token(c *fiber.Ctx) authentication.Token {
	t, _ := c.Locals(tokenKey{}).(authentication.Token)
	return t
}

func ActorID(c *fiber.Ctx) string {
	return Token(c).Subject.String()
}

func Environment(c *fiber.Ctx) identity.EnvironmentID {
	return Token(c).EnvironmentID
}

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
