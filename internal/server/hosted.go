package server

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// hostedRoutes mounts the hosted sign-in pages under /hosted with browser
// security headers. Each page handler sets its own content security policy
// (it carries a per-response style nonce). Like the identity API, every
// route has its own per-IP limit; POSTs verify credentials or send mail and
// get a tighter one.
func (s *Server) hostedRoutes(app *fiber.App) {
	if s.Hosted == nil {
		return
	}
	group := app.Group("/hosted", hostedHeaders)
	pages := s.Hosted.Pages()
	// Sorted: limiters are numbered in registration order (Server.limit),
	// which must be the same on every replica.
	for _, route := range slices.Sorted(maps.Keys(pages)) {
		handler := pages[route]
		method, path, _ := strings.Cut(route, " ")
		max := 60
		if method == fiber.MethodPost {
			max = 30
		}
		if method == fiber.MethodPost && strings.HasPrefix(path, "/hosted/device") {
			// User codes are short: guessing them is throttled harder.
			max = 10
		}
		if strings.HasPrefix(path, "/hosted/fonts/") {
			// Static, cached files: a page loads up to four.
			max = 600
		}
		limit := s.limit(limiter.Config{Max: max, Expiration: time.Minute, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
		group.Add(method, strings.TrimPrefix(path, "/hosted"), limit, handler)
	}
}

func hostedHeaders(c *fiber.Ctx) error {
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("Cross-Origin-Opener-Policy", "same-origin")
	c.Set("Strict-Transport-Security", "max-age=31536000")
	c.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	return c.Next()
}

// oauthHeaders keeps /oauth/* out of frames and sniffing. Pages rendered
// there (signed out, device approved, errors) set their own CSP over this
// default; no COOP here, so popup sign-ins keep their opener.
func oauthHeaders(c *fiber.Ctx) error {
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	return c.Next()
}

// samlRoutes mounts the SAML identity provider's public endpoints:
// metadata and single sign-on (HTTP-Redirect and HTTP-POST bindings). SSO
// only parks the request and redirects to the hosted sign-in, which has
// its own limits.
func (s *Server) samlRoutes(app *fiber.App) {
	if s.SAML == nil {
		return
	}
	group := app.Group("/saml/:environment", hostedHeaders)
	tooMany := func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }
	group.Get("/metadata", s.limit(limiter.Config{Max: 60, Expiration: time.Minute, LimitReached: tooMany}), s.SAML.Metadata)
	sso := s.limit(limiter.Config{Max: 30, Expiration: time.Minute, LimitReached: tooMany})
	group.Get("/sso", sso, s.SAML.SSO)
	group.Post("/sso", sso, s.SAML.SSO)
}
