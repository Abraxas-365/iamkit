package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/gofiber/fiber/v2"
)

type fakeOrigins struct {
	allowed map[string]bool
	calls   int
	err     error
}

func (f *fakeOrigins) OriginAllowed(_ context.Context, origin string) (bool, error) {
	f.calls++
	return f.allowed[origin], f.err
}

func TestOriginCache(t *testing.T) {
	lookup := &fakeOrigins{allowed: map[string]bool{"https://a.example": true}}
	cache := newOriginCache(lookup, time.Minute)
	now := time.Now()
	cache.now = func() time.Time { return now }
	if !cache.allowed("https://a.example") || !cache.allowed("https://a.example") || cache.allowed("https://b.example") || cache.allowed("https://b.example") {
		t.Fatal("wrong answers")
	}
	if lookup.calls != 2 {
		t.Fatalf("lookups = %d, want 2 (cached both ways)", lookup.calls)
	}
	now = now.Add(2 * time.Minute)
	lookup.allowed["https://b.example"] = true
	if !cache.allowed("https://b.example") || lookup.calls != 3 {
		t.Fatalf("expired entry not refreshed: calls %d", lookup.calls)
	}
	// Failures deny and are not cached.
	lookup.err = errors.New("down")
	if cache.allowed("https://c.example") || cache.allowed("https://c.example") || lookup.calls != 5 {
		t.Fatalf("failure handling: calls %d", lookup.calls)
	}
}

func TestCORSScopes(t *testing.T) {
	s := &Server{AllowedOrigins: "https://console.example", ClientOrigins: &fakeOrigins{allowed: map[string]bool{"https://login.example": true}}}
	app := fiber.New()
	app.Use(s.corsMiddleware())
	app.All("/*", func(c *fiber.Ctx) error { return c.SendStatus(204) })
	allow := func(path, origin string) string {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Origin", origin)
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return res.Header.Get("Access-Control-Allow-Origin")
	}
	cases := []struct{ path, origin, want string }{
		{"/identity/v1/login", "https://login.example", "https://login.example"},
		{"/oauth/authorize/complete", "https://login.example", "https://login.example"},
		{"/.well-known/openid-configuration", "https://login.example", "*"},
		{"/.well-known/oauth-authorization-server", "https://evil.example", "*"},
		{"/.well-known/jwks.json", "https://evil.example", "*"},
		{"/oauth/token", "https://login.example", "https://login.example"},
		{"/oauth/token", "https://evil.example", ""},
		{"/management/v1/projects", "https://login.example", ""},
		{"/api/v1/environments/x/users", "https://login.example", ""},
		{"/identity/v1/login", "https://console.example", "https://console.example"},
		{"/management/v1/projects", "https://console.example", "https://console.example"},
		{"/identity/v1/login", "https://evil.example", ""},
	}
	for _, c := range cases {
		if got := allow(c.path, c.origin); got != c.want {
			t.Errorf("%s from %s: %q, want %q", c.path, c.origin, got, c.want)
		}
	}
}

// TestPublicCORS: the discovery documents are open to every origin and the
// token endpoint's answer only to public clients, never with credentials,
// even with no configured origin.
func TestPublicCORS(t *testing.T) {
	app := fiber.New()
	app.Use((&Server{}).corsMiddleware())
	app.Post("/oauth/token", func(c *fiber.Ctx) error {
		if c.FormValue("client_id") == "public" {
			c.Locals(oauthhttp.PublicClientLocal, true)
		}
		return c.SendStatus(200)
	})
	app.All("/*", func(c *fiber.Ctx) error { return c.SendStatus(200) })
	send := func(method, path, body string, headers map[string]string) *http.Response {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Origin", "https://inspector.example")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	pre := map[string]string{"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,mcp-protocol-version"}
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/oauth/token", "/oauth/revoke"} {
		res := send("OPTIONS", path, "", pre)
		if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), "MCP-Protocol-Version") || res.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("preflight %s: %d %v", path, res.StatusCode, res.Header)
		}
	}
	if res := send("GET", "/.well-known/jwks.json", "", nil); res.Header.Get("Access-Control-Allow-Origin") != "*" || res.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("jwks: %v", res.Header)
	}
	if res := send("POST", "/oauth/token", "client_id=public", nil); res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("public client answer: %v", res.Header)
	}
	if res := send("POST", "/oauth/token", "client_id=confidential", nil); res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("confidential client answer readable: %v", res.Header)
	}
	if res := send("GET", "/management/v1/projects", "", nil); res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("management open: %v", res.Header)
	}
}
