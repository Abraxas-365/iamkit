package server

import (
	"context"
	"io/fs"
	"log/slog"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/adapters/hostedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/adapters/imphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfahttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/adapters/provhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/adapters/signinghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// APIHandlerSet groups the handler instances used by the /api/v1/* route group.
// These are separate instances wired with JWT-based actor extraction.
type APIHandlerSet struct {
	Users           *userhttp.Handler
	Organizations   *orghttp.Handler
	Structure       *orghttp.Structure
	Groups          *orghttp.Groups
	Domains         *orghttp.Domains
	Invitations     *invhttp.Handler
	Applications    *apphttp.Handler
	Authorization   *authzhttp.Handler
	Grants          *authzhttp.Grants
	ServiceAccounts *saccthttp.Handler
	Factors         *mfahttp.Handler
	Delivery        *authhttp.DeliveryHandler
	SMS             *authhttp.SMSHandler
}

type Server struct {
	Factors             *mfahttp.Handler
	Activity            *mgmthttp.Activity
	ServiceAccounts     *saccthttp.Handler
	ProvisioningControl *provhttp.Control
	Applications        *apphttp.Handler
	Tokens              *authhttp.Tokens
	Grants              *authzhttp.Grants
	Structure           *orghttp.Structure
	Groups              *orghttp.Groups
	Domains             *orghttp.Domains
	Invitations         *invhttp.Handler
	Provisioning        *provhttp.Handler
	Federation          *fedhttp.Handler
	Authorization       *authzhttp.Handler
	Organizations       *orghttp.Handler
	Control             *mgmthttp.Handler
	OperatorSSO         *mgmthttp.SSO // console login options, operator SSO, linked identities
	Health              func(context.Context) error
	Impersonation       *imphttp.Handler
	Auth                *authhttp.Handler
	OAuth               *oauthhttp.Handler
	Hosted              *hostedhttp.Handler
	Users               *userhttp.Handler
	Delivery            *authhttp.DeliveryHandler
	SMS                 *authhttp.SMSHandler
	PasswordPolicy      *authhttp.PasswordPolicyHandler
	SignInPolicy        *authhttp.SignInPolicyHandler
	Signup              *authhttp.SignupHandler
	SigningKeys         *signinghttp.Handler
	// SAML is the SAML identity provider (/saml/:environment/*) and its
	// service provider management.
	SAML *samlhttp.Handler
	// LogoutDeliveries is the back-channel logout delivery log.
	LogoutDeliveries *oauthhttp.Logouts
	// LogoutDispatcher sends due back-channel logout notifications once
	// (Start runs it periodically; tests call it directly).
	LogoutDispatcher oauth.Dispatcher
	// Background workers Start runs until its context ends.
	Background []func(ctx context.Context)
	// API routes (/api/v1/*) — JWT-based, permission-scoped.
	API         *apiauth.Middleware
	APIHandlers APIHandlerSet

	// AllowedOrigins is a comma-separated list of origins for CORS.
	// If empty, CORS middleware is not applied (same-origin only).
	// Env: CORS_ALLOWED_ORIGINS
	AllowedOrigins string

	// RateLimitPerMinute is the max requests per IP per minute for authenticated
	// management and API routes. Defaults to 120 if zero.
	// Env: RATE_LIMIT_PER_MINUTE
	RateLimitPerMinute int

	// Console is the embedded frontend filesystem (from internal/console).
	// If nil, no SPA is served and clients must provide their own UI.
	Console fs.FS
}

// Start runs the background workers (back-channel logout delivery) until
// ctx ends. Every replica runs them; they coordinate through the database.
func (s *Server) Start(ctx context.Context) {
	for _, run := range s.Background {
		go run(ctx)
	}
}

// requestLogger logs every request with method, path, status, and latency.
func requestLogger(c *fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	slog.Info("request",
		"method", c.Method(),
		"path", c.Path(),
		"status", c.Response().StatusCode(),
		"latency", time.Since(start).String(),
		"ip", c.IP(),
	)
	return err
}

// rateLimiter returns a shared rate limiter for authenticated routes.
func rateLimiter(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:          max,
		Expiration:   1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests },
	})
}

func (s *Server) App() *fiber.App {
	app := fiber.New(fiber.Config{AppName: "IAMKit", DisableStartupMessage: true, BodyLimit: 64 * 1024, ErrorHandler: errorHandler})
	app.Use(recover.New())
	app.Use(requestLogger)

	rateLimit := s.RateLimitPerMinute
	if rateLimit <= 0 {
		rateLimit = 120
	}

	// CORS — only enabled when AllowedOrigins is set.
	if s.AllowedOrigins != "" {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     s.AllowedOrigins,
			AllowMethods:     "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
			AllowHeaders:     "Content-Type,Authorization,X-API-Key,X-IAMKit-Console",
			AllowCredentials: true,
			MaxAge:           config.CORSMaxAge,
		}))
	}
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
	if s.OperatorSSO != nil {
		// Single sign-on is browser navigation: plain limiter responses.
		mgmt.Get("/login-options", limiter.New(limiter.Config{Max: 60}), s.OperatorSSO.Options)
		mgmt.Get("/sso/callback", limiter.New(limiter.Config{Max: 30}), s.OperatorSSO.Callback)
		mgmt.Get("/sso/:provider/start", limiter.New(limiter.Config{Max: 20}), s.OperatorSSO.Start)
	}
	control := mgmt.Group("", s.Control.Authenticate, rateLimiter(rateLimit))
	s.managementRoutes(control)
	auth := app.Group("/identity/v1")
	auth.Post("/login", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Auth.Login)
	auth.Post("/machine-token", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Tokens.Machine)
	auth.Post("/refresh", limiter.New(limiter.Config{Max: 30}), s.Auth.Refresh)
	auth.Post("/challenges", limiter.New(limiter.Config{Max: 20}), s.Auth.InitiateChallenge)
	auth.Post("/challenges/verify", limiter.New(limiter.Config{Max: 30}), s.Auth.VerifyChallenge)
	if s.Signup != nil {
		auth.Post("/signup", limiter.New(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Signup.Signup)
		auth.Post("/signup/verify", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Signup.Verify)
	}
	auth.Post("/federation/start", limiter.New(limiter.Config{Max: 20}), s.Federation.Start)
	auth.Get("/federation/callback", limiter.New(limiter.Config{Max: 30}), s.Federation.Callback)
	auth.Post("/federation/callback", limiter.New(limiter.Config{Max: 30}), s.Federation.CallbackForm)
	auth.Post("/federation/saml/acs", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.ACS)
	auth.Get("/federation/saml/:environment/:connection/metadata", limiter.New(limiter.Config{Max: 60, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.SAMLMetadata)
	auth.Post("/federation/ldap/login", limiter.New(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.DirectoryLogin)
	auth.Post("/discover", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.Discover)
	if s.Invitations != nil {
		auth.Post("/invitations/preview", limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Invitations.Preview)
		auth.Post("/invitations/accept", limiter.New(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Invitations.Accept)
	}
	auth.Get("/me", s.Tokens.Profile)
	auth.Patch("/me", s.Tokens.UpdateProfile)
	auth.Get("/organizations", s.Tokens.Organizations)
	auth.Post("/introspect", s.Tokens.Introspect)
	auth.Post("/logout", s.Tokens.Logout)
	auth.Post("/memberships", s.Tokens.AddMember)
	if s.Factors != nil {
		mfaLimit := limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
		auth.Post("/mfa/verify", mfaLimit, s.Auth.VerifyMFA)
		auth.Post("/mfa/enroll", mfaLimit, s.Auth.EnrollMFA)
		// Each challenge emails or texts a code: a tighter per-address limit.
		auth.Post("/mfa/challenge", limiter.New(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Auth.ChallengeMFA)
		auth.Post("/mfa/webauthn", mfaLimit, s.Auth.AssertMFA)
		s.Factors.RegisterSelf(auth, mfaLimit)
		passkeyLimit := limiter.New(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
		auth.Post("/passkeys/login/begin", passkeyLimit, s.Auth.BeginPasskey)
		auth.Post("/passkeys/login/finish", passkeyLimit, s.Auth.FinishPasskey)
	}
	s.Provisioning.Register(app)
	// Unauthenticated OIDC endpoints get per-IP limits; resource servers
	// call introspection and userinfo often, so theirs are wider.
	app.Use("/oauth/token", rateLimiter(rateLimit*5))
	app.Use("/oauth/device_authorization", rateLimiter(rateLimit))
	app.Use("/oauth/introspect", rateLimiter(rateLimit*5))
	app.Use("/oauth/userinfo", rateLimiter(rateLimit*5))
	app.Use("/oauth/end_session", rateLimiter(30))
	s.OAuth.Register(app)
	s.hostedRoutes(app)
	s.samlRoutes(app)
	s.apiRoutes(app, rateLimit)
	s.spaRoutes(app, s.Console)
	return app
}
