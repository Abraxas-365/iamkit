// Package apiauth provides JWT-based authentication and permission enforcement
// for the /api/v1/* route group.
package apiauth

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type tokenKey struct{}
type setupKey struct{}

// SetupSessions resolves the opaque bearer of an organization setup link
// (orgadmin.SetupLinkQueries).
type SetupSessions interface {
	Session(ctx context.Context, bearer string) (orgadmin.SetupGrant, error)
}

type Middleware struct {
	validator authentication.TokenValidator
	setup     SetupSessions
}

func New(v authentication.TokenValidator) *Middleware { return &Middleware{validator: v} }

// WithSetup also accepts setup-link bearers (ik_setupsess_…). They reach
// only their organization's /admin routes: see Scope.
func (m *Middleware) WithSetup(s SetupSessions) *Middleware { m.setup = s; return m }

// Setup returns the setup grant of the request's bearer (false for every
// other caller).
func Setup(c *fiber.Ctx) (orgadmin.SetupGrant, bool) {
	g, ok := c.Locals(setupKey{}).(orgadmin.SetupGrant)
	return g, ok
}

// adminRoutes reports whether path is the grant's organization
// administration: /api/v1/environments/:env/organizations/:org/admin[/…].
func adminRoutes(g orgadmin.SetupGrant, path string) bool {
	base := "/api/v1/environments/" + g.Environment.String() + "/organizations/" + g.Organization.String() + "/admin"
	path = strings.ToLower(path)
	return path == base || strings.HasPrefix(path, base+"/")
}

func (m *Middleware) Authenticate(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")

	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return errx.Unauthorized("bearer token required")
	}
	raw := parts[1]
	if m.setup != nil && strings.HasPrefix(raw, orgadmin.SetupSessionPrefix) {
		grant, err := m.setup.Session(c.UserContext(), raw)
		if errx.IsServerError(err) {
			return err
		}
		if err != nil {
			return errx.Unauthorized("invalid or expired token")
		}
		c.Locals(setupKey{}, grant)
		c.SetUserContext(event.WithActor(c.UserContext(), grant.Link.String()))
		return c.Next()
	}
	// Personal access tokens of machine users are the one opaque bearer
	// accepted here; every other ik_ secret is an API key.
	if strings.HasPrefix(raw, "ik_") && !strings.HasPrefix(raw, authentication.AccessTokenPrefix) {
		return errx.Unauthorized("JWT access token required, not an API key")
	}
	token, err := m.validator.ValidateSelf(c.UserContext(), raw)
	if errx.IsServerError(err) {
		return err
	}
	if err != nil {
		return errx.Unauthorized("invalid or expired token")
	}
	c.Locals(tokenKey{}, token)
	c.SetUserContext(event.WithActor(c.UserContext(), token.Subject.String()))
	return c.Next()
}

// Scope refuses a token on another environment's routes. It must be mounted
// on the group that declares the :environment parameter — Authenticate runs
// on /api/v1, where that parameter is not yet bound.
func Scope(c *fiber.Ctx) error {
	if grant, ok := Setup(c); ok {
		// A setup bearer is for one organization's administration only.
		if !adminRoutes(grant, c.Path()) {
			return errx.Forbidden("setup links reach only their organization's admin routes")
		}
		return c.Next()
	}
	env, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil || env != Token(c).EnvironmentID {
		return errx.Forbidden("token not scoped to this environment")
	}
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
