package server

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// ClientOrigins answers whether some live OAuth client lists an origin in
// its allowed_origins (oauth.Queries.OriginAllowed).
type ClientOrigins interface {
	OriginAllowed(ctx context.Context, origin string) (bool, error)
}

// browserFacing are the routes a custom sign-in UI or a single-page
// application calls from another origin: the identity API, the OAuth
// endpoints browsers use and the public discovery documents (OIDC
// libraries read the configuration and JWKS first). Client allowed origins
// apply only there; the deployment-wide CORS_ALLOWED_ORIGINS applies
// everywhere.
func browserFacing(path string) bool {
	for _, prefix := range []string{"/identity/v1/", "/oauth/", "/.well-known/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func corsConfig(origins string) cors.Config {
	return cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization,X-API-Key,X-IAMKit-Console,X-Request-Id,traceparent,tracestate",
		ExposeHeaders:    "X-Request-Id",
		AllowCredentials: true,
		MaxAge:           config.CORSMaxAge,
	}
}

// corsMiddleware is CORS for the deployment's origins on every route and,
// on browser-facing routes, also for the origins clients allow (looked up
// through a short cache); the public discovery documents and the token and
// revocation endpoints are also open to any origin without credentials
// (MCP clients running in a browser).
func (s *Server) corsMiddleware() fiber.Handler {
	credentialed := s.credentialedCORS()
	return func(c *fiber.Ctx) error {
		path := c.Path()
		if publicDocument(path) {
			return openCORS(c)
		}
		if publicEndpoint(path) {
			return endpointCORS(c, credentialed)
		}
		if credentialed != nil {
			return credentialed(c)
		}
		return c.Next()
	}
}

// publicDocument are the discovery documents any origin may read (an MCP
// client in a browser, such as MCP Inspector, reads them before it has a
// client): Access-Control-Allow-Origin *, never credentials.
func publicDocument(path string) bool {
	switch path {
	case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/jwks.json":
		return true
	}
	return false
}

// publicEndpoint are the OAuth endpoints public clients call from a
// browser of any origin: the preflight is open, the answer readable only
// when the client is public (oauthhttp.PublicClientLocal). Dynamic
// registration (/oauth/register) is always public: its answer holds no
// secret, so it sets the local itself.
func publicEndpoint(path string) bool {
	return path == "/oauth/token" || path == "/oauth/revoke" || path == "/oauth/register"
}

// publicHeaders are the request headers an open preflight admits.
const publicHeaders = "Content-Type,Authorization,MCP-Protocol-Version,X-Request-Id,traceparent,tracestate"

func preflight(c *fiber.Ctx) bool {
	return c.Method() == fiber.MethodOptions && c.Get(fiber.HeaderAccessControlRequestMethod) != ""
}

func openPreflight(c *fiber.Ctx, methods string) {
	c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
	c.Set(fiber.HeaderAccessControlAllowMethods, methods)
	c.Set(fiber.HeaderAccessControlAllowHeaders, publicHeaders)
	c.Set(fiber.HeaderAccessControlMaxAge, strconv.Itoa(config.CORSMaxAge))
}

// openCORS answers any origin without credentials.
func openCORS(c *fiber.Ctx) error {
	if c.Get(fiber.HeaderOrigin) == "" {
		return c.Next()
	}
	if preflight(c) {
		openPreflight(c, "GET,HEAD,OPTIONS")
		return c.SendStatus(fiber.StatusNoContent)
	}
	c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
	c.Set(fiber.HeaderAccessControlExposeHeaders, "X-Request-Id")
	return c.Next()
}

// endpointCORS keeps the configured origins' credentialed CORS on the
// token and revocation endpoints and, for every other origin, opens the
// preflight and exposes the answer only to public clients.
func endpointCORS(c *fiber.Ctx, credentialed fiber.Handler) error {
	if c.Get(fiber.HeaderOrigin) == "" {
		return c.Next()
	}
	if preflight(c) {
		if credentialed != nil {
			err := credentialed(c)
			if len(c.Response().Header.Peek(fiber.HeaderAccessControlAllowOrigin)) > 0 {
				return err
			}
		}
		openPreflight(c, "POST,OPTIONS")
		return c.SendStatus(fiber.StatusNoContent)
	}
	var err error
	if credentialed != nil {
		err = credentialed(c)
	} else {
		err = c.Next()
	}
	c.Vary(fiber.HeaderOrigin)
	if len(c.Response().Header.Peek(fiber.HeaderAccessControlAllowOrigin)) == 0 {
		if public, _ := c.Locals(oauthhttp.PublicClientLocal).(bool); public {
			c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
			c.Set(fiber.HeaderAccessControlExposeHeaders, "X-Request-Id")
		}
	}
	return err
}

// credentialedCORS is CORS for the deployment's origins on every route
// and, on browser-facing routes, also for the origins clients allow (nil
// when neither is configured).
func (s *Server) credentialedCORS() fiber.Handler {
	var global fiber.Handler
	if s.AllowedOrigins != "" {
		global = cors.New(corsConfig(s.AllowedOrigins))
	}
	if s.ClientOrigins == nil {
		return global
	}
	cache := newOriginCache(s.ClientOrigins, config.ClientOriginCacheTTL)
	// The deployment list is checked first, then the clients' (Fiber logs
	// once at startup that both are set; that is intended).
	cfg := corsConfig(s.AllowedOrigins)
	cfg.AllowOriginsFunc = cache.allowed
	clients := cors.New(cfg)
	return func(c *fiber.Ctx) error {
		if browserFacing(c.Path()) {
			return clients(c)
		}
		if global != nil {
			return global(c)
		}
		return c.Next()
	}
}

// originCache remembers client origin answers for ttl (both ways), so a
// cross-origin request costs one query per origin and interval.
type originCache struct {
	lookup ClientOrigins
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	items  map[string]originEntry
}

type originEntry struct {
	allowed bool
	until   time.Time
}

// maxCachedOrigins bounds the cache; past it, it starts over.
const maxCachedOrigins = 1024

func newOriginCache(lookup ClientOrigins, ttl time.Duration) *originCache {
	return &originCache{lookup: lookup, ttl: ttl, now: time.Now, items: map[string]originEntry{}}
}

func (o *originCache) allowed(origin string) bool {
	now := o.now()
	o.mu.Lock()
	entry, ok := o.items[origin]
	o.mu.Unlock()
	if ok && now.Before(entry.until) {
		return entry.allowed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	allowed, err := o.lookup.OriginAllowed(ctx, origin)
	if err != nil {
		// Fail closed, uncached: the browser retries on the next request.
		slog.Warn("cors: client origin lookup failed", "err", err)
		return false
	}
	o.mu.Lock()
	if len(o.items) >= maxCachedOrigins {
		o.items = map[string]originEntry{}
	}
	o.items[origin] = originEntry{allowed: allowed, until: now.Add(o.ttl)}
	o.mu.Unlock()
	return allowed
}
