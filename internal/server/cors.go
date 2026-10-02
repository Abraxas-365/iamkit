package server

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// ClientOrigins answers whether some live OAuth client lists an origin in
// its allowed_origins (oauth.Queries.OriginAllowed).
type ClientOrigins interface {
	OriginAllowed(ctx context.Context, origin string) (bool, error)
}

// browserFacing are the routes a custom sign-in UI or a single-page
// application calls from another origin: the identity API and the OAuth
// endpoints browsers use. Client allowed origins apply only there; the
// deployment-wide CORS_ALLOWED_ORIGINS applies everywhere.
func browserFacing(path string) bool {
	for _, prefix := range []string{"/identity/v1/", "/oauth/"} {
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
// through a short cache). Nil when neither is configured.
func (s *Server) corsMiddleware() fiber.Handler {
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
