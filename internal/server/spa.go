package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
)

// spaRoutes serves the embedded operator console as a single-page application.
// Static assets (JS, CSS, fonts) are served directly; all other non-API GET
// requests receive index.html for client-side routing.
//
// If assets is nil (no frontend embedded), this is a no-op.
func (s *Server) spaRoutes(app *fiber.App, assets fs.FS) {
	if assets == nil {
		return
	}
	// The organization admin portal handles end-user tokens in the
	// browser: a strict CSP (bundled scripts only, API calls same-origin)
	// and no referrer, since its callback URL carries an authorization code.
	app.Use(PortalPath, portalHeaders)

	app.Use(filesystem.New(filesystem.Config{
		Root: http.FS(assets),
		// SPA fallback: unknown paths serve index.html so React Router
		// resolves the client-side route.
		NotFoundFile: "index.html",
		Next: func(c *fiber.Ctx) bool {
			// Skip non-GET/HEAD (API mutations should 404, not get HTML).
			if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead {
				return true
			}
			// Skip API paths — let them 404 normally.
			path := c.Path()
			for _, prefix := range []string{"/management/", "/identity/", "/api/", "/scim/", "/hosted/", "/oauth/", "/health", "/.well-known/"} {
				if strings.HasPrefix(path, prefix) {
					return true
				}
			}
			return false
		},
	}))
}

// PortalPath is where the hosted organization admin portal is served
// (orgadmin.PortalPath; the console bundle routes it client-side).
const PortalPath = "/org-admin"

// portalCSP allows the bundle's own scripts, styles and fonts, inline
// style attributes (React), https images (logos, avatars) and same-origin
// requests only.
const portalCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' https: data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func portalHeaders(c *fiber.Ctx) error {
	c.Set("Content-Security-Policy", portalCSP)
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Cache-Control", "no-store")
	return c.Next()
}
