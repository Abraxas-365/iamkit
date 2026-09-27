package server

import (
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
	for route, handler := range s.Hosted.Pages() {
		method, path, _ := strings.Cut(route, " ")
		max := 60
		if method == fiber.MethodPost {
			max = 30
		}
		limit := limiter.New(limiter.Config{Max: max, Expiration: time.Minute, LimitReached: func(c *fiber.Ctx) error { return fiber.ErrTooManyRequests }})
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
