package server

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gofiber/fiber/v2"
)

func TestConsoleAndPortalServedWithStrictHeaders(t *testing.T) {
	app := fiber.New()
	(&Server{}).spaRoutes(app, fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}})
	for _, tc := range []struct {
		path   string
		portal bool
	}{{"/org-admin/0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01", true}, {"/org-admin/env/callback?code=x", true}, {"/projects", false}} {
		res, err := app.Test(httptest.NewRequest("GET", tc.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 || !strings.Contains(string(body), "console") {
			t.Fatalf("%s: %d %s", tc.path, res.StatusCode, body)
		}
		csp := res.Header.Get("Content-Security-Policy")
		if csp != portalCSP || tc.portal != (res.Header.Get("Referrer-Policy") == "no-referrer") || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", tc.path, res.Header)
		}
	}
}

// Paths owned by the server never fall back to the console: with the
// saml_idp feature off the SAML IdP routes are absent and must 404, not
// answer an SP's metadata fetch with index.html.
func TestSPASkipsServerPaths(t *testing.T) {
	app := fiber.New()
	(&Server{}).spaRoutes(app, fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}})
	for _, path := range []string{"/saml/0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01/metadata", "/saml/x/sso", "/oauth/nope", "/identity/v1/nope", "/hosted/nope"} {
		res, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 404 || strings.Contains(string(body), "console") {
			t.Fatalf("%s: %d %s", path, res.StatusCode, body)
		}
	}
}
