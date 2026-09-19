package server

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/adapters/imphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/adapters/provhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

type Server struct {
	Activity            *mgmthttp.Activity
	ServiceAccounts     *saccthttp.Handler
	ProvisioningControl *provhttp.Control
	Applications        *apphttp.Handler
	Tokens              *authhttp.Tokens
	Grants              *authzhttp.Grants
	Structure           *orghttp.Structure
	Provisioning        *provhttp.Handler
	Federation          *fedhttp.Handler
	Authorization       *authzhttp.Handler
	Organizations       *orghttp.Handler
	Control             *mgmthttp.Handler
	Health              func(context.Context) error
	Impersonation       *imphttp.Handler
	Auth                *authhttp.Handler
	OAuth               *oauthhttp.Handler
	Users               *userhttp.Handler
}

func (s *Server) App() *fiber.App {
	app := fiber.New(fiber.Config{AppName: "IAMKit", DisableStartupMessage: true, BodyLimit: 64 * 1024, ErrorHandler: errorHandler})
	app.Use(recover.New())
	app.Get("/health", func(c *fiber.Ctx) error {
		if err := s.Health(c.Context()); err != nil {
			unavailable := errx.Wrap(err, "database unavailable", errx.TypeInternal)
			unavailable.HTTPStatus = fiber.StatusServiceUnavailable
			return unavailable
		}
		return c.JSON(fiber.Map{"status": "healthy", "service": "iamkit"})
	})
	app.Get("/.well-known/jwks.json", s.Tokens.JWKS)
	// Operator login is unauthenticated — registered outside the auth middleware.
	mgmt := app.Group("/management/v1")
	mgmt.Post("/login", limiter.New(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Control.Login)
	control := mgmt.Group("", s.Control.Authenticate)
	s.managementRoutes(control)
	auth := app.Group("/identity/v1")
	auth.Post("/login", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Auth.Login)
	auth.Post("/machine-token", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Tokens.Machine)
	auth.Post("/refresh", limiter.New(limiter.Config{Max: 30}), s.Auth.Refresh)
	auth.Post("/challenges", limiter.New(limiter.Config{Max: 20}), s.Auth.InitiateChallenge)
	auth.Post("/challenges/verify", limiter.New(limiter.Config{Max: 30}), s.Auth.VerifyChallenge)
	auth.Post("/federation/start", limiter.New(limiter.Config{Max: 20}), s.Federation.Start)
	auth.Get("/federation/callback", limiter.New(limiter.Config{Max: 30}), s.Federation.Callback)
	auth.Get("/me", s.Tokens.Profile)
	auth.Patch("/me", s.Tokens.UpdateProfile)
	auth.Get("/organizations", s.Tokens.Organizations)
	auth.Post("/introspect", s.Tokens.Introspect)
	auth.Post("/logout", s.Tokens.Logout)
	auth.Post("/memberships", s.Tokens.AddMember)
	s.Provisioning.Register(app)
	s.OAuth.Register(app)
	return app
}
