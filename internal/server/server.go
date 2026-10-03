package server

import (
	"context"
	"io/fs"
	"log/slog"
	"strconv"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action/adapters/actionhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/adapters/featurehttp"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/adapters/hostedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/adapters/imphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfahttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/adapters/orgadminhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/adapters/provhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/adapters/signinghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagehttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// APIHandlerSet groups the handler instances used by the /api/v1/* route group.
// These are separate instances wired with JWT-based actor extraction.
type APIHandlerSet struct {
	Users *userhttp.Handler
	// AccessTokens serves machine users' personal access tokens.
	AccessTokens *userhttp.AccessTokens
	// UserKeys serves machine users' keys (JWT-bearer login).
	UserKeys        *userhttp.Keys
	Organizations   *orghttp.Handler
	Structure       *orghttp.Structure
	Groups          *orghttp.Groups
	Domains         *orghttp.Domains
	Invitations     *invhttp.Handler
	Applications    *apphttp.Handler
	Authorization   *authzhttp.Handler
	Grants          *authzhttp.Grants
	ResourceGrants  *authzhttp.ResourceGrants
	ServiceAccounts *saccthttp.Handler
	Factors         *mfahttp.Handler
	Delivery        *authhttp.DeliveryHandler
	SMS             *authhttp.SMSHandler
	// OrgAdmin serves organization administrators (.../organizations/:organization/admin).
	OrgAdmin *orgadminhttp.Handler
	// Events serves the event log (iam:events:read).
	Events *eventhttp.Handler
	// Webhooks serves event webhook subscriptions (iam:webhooks:*).
	Webhooks *eventhttp.Subscriptions
	// Usage serves daily usage (iam:usage:read).
	Usage *usagehttp.Handler
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
	ResourceGrants      *authzhttp.ResourceGrants
	Organizations       *orghttp.Handler
	Control             *mgmthttp.Handler
	OperatorSSO         *mgmthttp.SSO // console login options, operator SSO, linked identities
	Health              func(context.Context) error
	Impersonation       *imphttp.Handler
	Auth                *authhttp.Handler
	OAuth               *oauthhttp.Handler
	Hosted              *hostedhttp.Handler
	Users               *userhttp.Handler
	AccessTokens        *userhttp.AccessTokens
	UserKeys            *userhttp.Keys
	Delivery            *authhttp.DeliveryHandler
	SMS                 *authhttp.SMSHandler
	PasswordPolicy      *authhttp.PasswordPolicyHandler
	SignInPolicy        *authhttp.SignInPolicyHandler
	Signup              *authhttp.SignupHandler
	SigningKeys         *signinghttp.Handler
	// Features serves IAMKit's feature flags and environment overrides.
	Features *featurehttp.Handler
	// Actions serves action targets, executions and the calls log.
	Actions *actionhttp.Handler
	// SAML is the SAML identity provider (/saml/:environment/*) and its
	// service provider management.
	SAML *samlhttp.Handler
	// OrgAdminPortal turns the hosted organization admin portal (/org-admin)
	// on and off and tells the portal its client.
	OrgAdminPortal *orgadminhttp.Portal
	// Events serves the environment's event log.
	Events *eventhttp.Handler
	// Webhooks serves event webhook subscriptions; WebhookDispatcher sends
	// one round of due deliveries (the worker runs it; tests call it).
	Webhooks          *eventhttp.Subscriptions
	WebhookDispatcher event.Dispatcher
	// LogoutDeliveries is the back-channel logout delivery log.
	LogoutDeliveries *oauthhttp.Logouts
	// LogoutDispatcher sends due back-channel logout notifications once
	// (the worker runs it periodically; tests call it directly).
	LogoutDispatcher oauth.Dispatcher
	// Workers runs the background jobs (Start) and reports their state on
	// /health.
	Workers *worker.Runner
	// Limits serves environment limits and usage (management).
	Limits *usagehttp.Handler
	// Meter enforces requests_per_minute and counts API requests on routes
	// binding :environment (nil: none).
	Meter fiber.Handler
	// FlushUsage writes in-memory usage counters (tokens, emails, SMS,
	// action calls, requests); Start runs it every config.UsageFlushInterval
	// on every replica and once more when ctx ends (nil: none).
	FlushUsage func(context.Context) error
	// flushed closes after the final usage flush.
	flushed chan struct{}
	// API routes (/api/v1/*) — JWT-based, permission-scoped.
	API         *apiauth.Middleware
	APIHandlers APIHandlerSet

	// AllowedOrigins is a comma-separated list of origins for CORS.
	// If empty, CORS middleware is not applied (same-origin only).
	// Env: CORS_ALLOWED_ORIGINS
	AllowedOrigins string
	// ClientOrigins allows the origins OAuth clients list on the
	// browser-facing routes (nil: only AllowedOrigins).
	ClientOrigins ClientOrigins

	// RateLimitPerMinute is the max requests per IP per minute for authenticated
	// management and API routes. Defaults to 120 if zero.
	// Env: RATE_LIMIT_PER_MINUTE
	RateLimitPerMinute int
	// LimitStorage, when set (REDIS_URL), holds the per-IP rate limiters'
	// counters so replicas share them; nil keeps them in each process.
	LimitStorage fiber.Storage
	limiters     int
	// TrustedProxies are the reverse proxies (IPs or CIDRs) whose
	// X-Forwarded-For names the client; X-Forwarded-Proto/-Host are then
	// believed from them only. Empty: the socket address is the client (and
	// Fiber's default reads X-Forwarded-Proto/-Host from anyone).
	// Env: IAMKIT_TRUSTED_PROXIES
	TrustedProxies []string
	// Cache pings the shared cache (REDIS_URL) for /health's cache field;
	// nil reports "none".
	Cache func(context.Context) error
	// CloseCache closes the shared cache's connections after shutdown (nil:
	// none).
	CloseCache func() error
	// WaitDeliveries waits up to timeout for code emails still being sent
	// after their response (nil: none); true when none are left.
	WaitDeliveries func(timeout time.Duration) bool

	// Console is the embedded frontend filesystem (from internal/console).
	// If nil, no SPA is served and clients must provide their own UI.
	Console fs.FS
}

// Start runs the background jobs until ctx ends (unless IAMKIT_WORKERS
// turned them off). Every replica may run them; they coordinate through the
// database.
func (s *Server) Start(ctx context.Context) {
	if s.Workers != nil {
		s.Workers.Start(ctx)
	}
	if s.FlushUsage != nil && s.flushed == nil {
		s.flushed = make(chan struct{})
		go s.flushLoop(ctx)
	}
}

// flushLoop flushes usage counters periodically and once more at
// shutdown (with a fresh deadline: ctx is already done then).
func (s *Server) flushLoop(ctx context.Context) {
	defer close(s.flushed)
	tick := time.NewTicker(config.UsageFlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if err := s.FlushUsage(ctx); err != nil {
				slog.WarnContext(ctx, "usage flush failed", "err", err)
			}
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := s.FlushUsage(final); err != nil {
				slog.Warn("final usage flush failed", "err", err)
			}
			cancel()
			return
		}
	}
}

// WaitFlushed waits up to timeout for the final usage flush after Start's
// context ended; true when it finished (or never started).
func (s *Server) WaitFlushed(timeout time.Duration) bool {
	if s.flushed == nil {
		return true
	}
	select {
	case <-s.flushed:
		return true
	case <-time.After(timeout):
		return false
	}
}

// cacheState is the /health cache field: "none" without REDIS_URL, else
// "up" or "down" (down stays healthy: IAMKit falls back to the database
// and per-replica counters).
func (s *Server) cacheState(ctx context.Context) string {
	if s.Cache == nil {
		return "none"
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if s.Cache(ctx) != nil {
		return "down"
	}
	return "up"
}

// workerState is the /health workers field.
func (s *Server) workerState() string {
	if s.Workers == nil {
		return worker.StateDisabled
	}
	return s.Workers.State()
}

// countTokens records token endpoint outcomes by grant type.
func countTokens(c *fiber.Ctx) error {
	err := c.Next()
	status := c.Response().StatusCode()
	if err != nil {
		status = fiber.StatusInternalServerError
		var custom *errx.Error
		if errx.As(err, &custom) {
			status = custom.HTTPStatus
		}
	}
	telemetry.TokenRequest(c.UserContext(), c.FormValue("grant_type"), status)
	return err
}

// rateLimiter returns a per-IP limit of max requests a minute.
func (s *Server) rateLimiter(max int) fiber.Handler {
	return s.limit(limiter.Config{
		Max:          max,
		Expiration:   1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests },
	})
}

// scimTooMany answers a rate-limited SCIM request as a SCIM error (RFC 7644
// §3.12), which directories parse.
func scimTooMany(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  "429", "detail": "too many requests",
	}, "application/scim+json")
}

// limit is limiter.New on the shared LimitStorage (REDIS_URL) when set
// (keys: the config's KeyGenerator, default the client IP).
// Each limiter gets its own key space, numbered in registration order —
// the same on every replica, as routes are registered identically.
func (s *Server) limit(cfg limiter.Config) fiber.Handler {
	if s.LimitStorage != nil {
		s.limiters++
		scope := strconv.Itoa(s.limiters) + ":"
		cfg.Storage = s.LimitStorage
		key := cfg.KeyGenerator
		if key == nil {
			key = func(c *fiber.Ctx) string { return c.IP() }
		}
		cfg.KeyGenerator = func(c *fiber.Ctx) string { return scope + key(c) }
	}
	return limiter.New(cfg)
}

// config is the Fiber configuration. With TrustedProxies, c.IP() is the
// first valid address of X-Forwarded-For (the edge proxy must replace, not
// append to, what clients send) and only those proxies' forwarded headers
// are read; without them the default stays: the socket address.
func (s *Server) config() fiber.Config {
	cfg := fiber.Config{AppName: "IAMKit", DisableStartupMessage: true, BodyLimit: 64 * 1024, ErrorHandler: errorHandler}
	if len(s.TrustedProxies) > 0 {
		cfg.ProxyHeader = fiber.HeaderXForwardedFor
		cfg.EnableTrustedProxyCheck = true
		cfg.TrustedProxies = s.TrustedProxies
		cfg.EnableIPValidation = true
	}
	return cfg
}

func (s *Server) App() *fiber.App {
	app := fiber.New(s.config())
	app.Use(observe)
	app.Use(recover.New())
	s.limiters = 0

	rateLimit := s.RateLimitPerMinute
	if rateLimit <= 0 {
		rateLimit = 120
	}

	// CORS — the deployment's origins everywhere, client origins on the
	// browser-facing routes (cors.go); none when neither is configured.
	if handler := s.corsMiddleware(); handler != nil {
		app.Use(handler)
	}
	app.Get("/health", func(c *fiber.Ctx) error {
		if err := s.Health(c.UserContext()); err != nil {
			unavailable := errx.Wrap(err, "database unavailable", errx.TypeInternal)
			unavailable.HTTPStatus = fiber.StatusServiceUnavailable
			return unavailable
		}
		return c.JSON(fiber.Map{"status": "healthy", "service": "iamkit", "workers": s.workerState(), "cache": s.cacheState(c.UserContext())})
	})
	app.Get("/.well-known/jwks.json", s.Tokens.JWKS)
	app.Get("/openapi.json", openAPI)
	// Operator login is unauthenticated — registered outside the auth middleware.
	mgmt := app.Group("/management/v1")
	mgmt.Post("/login", s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Control.Login)
	if s.OperatorSSO != nil {
		// Single sign-on is browser navigation: plain limiter responses.
		mgmt.Get("/login-options", s.limit(limiter.Config{Max: 60}), s.OperatorSSO.Options)
		mgmt.Get("/sso/callback", s.limit(limiter.Config{Max: 30}), s.OperatorSSO.Callback)
		mgmt.Get("/sso/:provider/start", s.limit(limiter.Config{Max: 20}), s.OperatorSSO.Start)
	}
	control := mgmt.Group("", s.Control.Authenticate, s.rateLimiter(rateLimit))
	s.managementRoutes(control)
	auth := app.Group("/identity/v1")
	if s.OrgAdminPortal != nil {
		auth.Get("/org-admin/:environment", s.limit(limiter.Config{Max: 60}), s.OrgAdminPortal.Discover)
	}
	auth.Post("/login", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Auth.Login)
	auth.Post("/machine-token", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Tokens.Machine)
	auth.Post("/token-exchange", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Tokens.ExchangeAccessToken)
	auth.Post("/refresh", s.limit(limiter.Config{Max: 30}), s.Auth.Refresh)
	auth.Post("/challenges", s.limit(limiter.Config{Max: 20}), s.Auth.InitiateChallenge)
	auth.Post("/challenges/verify", s.limit(limiter.Config{Max: 30}), s.Auth.VerifyChallenge)
	if s.Signup != nil {
		auth.Post("/signup", s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Signup.Signup)
		auth.Post("/signup/verify", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Signup.Verify)
	}
	auth.Post("/federation/start", s.limit(limiter.Config{Max: 20}), s.Federation.Start)
	auth.Get("/federation/callback", s.limit(limiter.Config{Max: 30}), s.Federation.Callback)
	auth.Post("/federation/result", s.limit(limiter.Config{Max: 30}), s.Federation.Result)
	auth.Post("/federation/callback", s.limit(limiter.Config{Max: 30}), s.Federation.CallbackForm)
	auth.Post("/federation/saml/acs", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.ACS)
	auth.Get("/federation/saml/:environment/:connection/metadata", s.limit(limiter.Config{Max: 60, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.SAMLMetadata)
	auth.Post("/federation/ldap/login", s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.DirectoryLogin)
	auth.Post("/discover", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Federation.Discover)
	if s.Hosted != nil {
		auth.Get("/authorize/:ticket", s.limit(limiter.Config{Max: 60, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Hosted.Authorization)
	}
	if s.Invitations != nil {
		auth.Post("/invitations/preview", s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Invitations.Preview)
		auth.Post("/invitations/accept", s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Invitations.Accept)
	}
	auth.Get("/me", s.Tokens.Profile)
	auth.Patch("/me", s.Tokens.UpdateProfile)
	auth.Get("/organizations", s.Tokens.Organizations)
	s.Users.RegisterSelf(auth, s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}),
		s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}))
	auth.Post("/introspect", s.Tokens.Introspect)
	auth.Post("/logout", s.Tokens.Logout)
	auth.Post("/memberships", s.Tokens.AddMember)
	if s.Factors != nil {
		mfaLimit := s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
		auth.Post("/mfa/verify", mfaLimit, s.Auth.VerifyMFA)
		auth.Post("/mfa/enroll", mfaLimit, s.Auth.EnrollMFA)
		// Each challenge emails or texts a code: a tighter per-address limit.
		auth.Post("/mfa/challenge", s.limit(limiter.Config{Max: 10, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }}), s.Auth.ChallengeMFA)
		auth.Post("/mfa/webauthn", mfaLimit, s.Auth.AssertMFA)
		s.Factors.RegisterSelf(auth, mfaLimit)
		passkeyLimit := s.limit(limiter.Config{Max: 30, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
		auth.Post("/passkeys/login/begin", passkeyLimit, s.Auth.BeginPasskey)
		auth.Post("/passkeys/login/finish", passkeyLimit, s.Auth.FinishPasskey)
	}
	// SCIM: directories sync in bursts, so the budget is the token
	// endpoint's; every request (a wrong credential too) counts, before the
	// credential lookup.
	app.Use("/scim/v2", s.limit(limiter.Config{Max: rateLimit * 5, Expiration: time.Minute, LimitReached: scimTooMany}))
	s.Provisioning.Register(app)
	// Unauthenticated OIDC endpoints get per-IP limits; resource servers
	// call introspection and userinfo often, so theirs are wider.
	app.Use("/oauth/token", countTokens, s.rateLimiter(rateLimit*5))
	app.Use("/oauth/device_authorization", s.rateLimiter(rateLimit))
	app.Use("/oauth/introspect", s.rateLimiter(rateLimit*5))
	app.Use("/oauth/userinfo", s.rateLimiter(rateLimit*5))
	app.Use("/oauth/end_session", s.rateLimiter(30))
	s.OAuth.Register(app)
	s.hostedRoutes(app)
	s.samlRoutes(app)
	s.apiRoutes(app, rateLimit)
	s.spaRoutes(app, s.Console)
	return app
}
