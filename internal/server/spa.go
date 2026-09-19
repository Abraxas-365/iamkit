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
			for _, prefix := range []string{"/management/", "/identity/", "/api/", "/scim/", "/health", "/.well-known/"} {
				if strings.HasPrefix(path, prefix) {
					return true
				}
			}
			return false
		},
	}))
}
