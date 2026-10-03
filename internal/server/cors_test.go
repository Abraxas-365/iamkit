package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

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
		{"/.well-known/openid-configuration", "https://login.example", "https://login.example"},
		{"/.well-known/jwks.json", "https://evil.example", ""},
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
	if (&Server{}).corsMiddleware() != nil {
		t.Fatal("CORS without any origin source")
	}
}
