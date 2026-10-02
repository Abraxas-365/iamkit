package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestTrustedProxies: the client address comes from X-Forwarded-For only
// when the peer is a trusted proxy (fiber's test connection is 0.0.0.0).
func TestTrustedProxies(t *testing.T) {
	ip := func(s *Server, forwarded string) string {
		t.Helper()
		app := fiber.New(s.config())
		app.Get("/", func(c *fiber.Ctx) error { return c.SendString(c.IP() + " " + c.Protocol()) })
		r := httptest.NewRequest("GET", "/", nil)
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		res, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body [64]byte
		n, _ := res.Body.Read(body[:])
		return string(body[:n])
	}
	if got := ip(&Server{}, "203.0.113.7"); got != "0.0.0.0 https" {
		t.Fatalf("no trusted proxies = %q, want the socket address", got)
	}
	trusted := &Server{TrustedProxies: []string{"0.0.0.0/8"}}
	if got := ip(trusted, "203.0.113.7, 10.0.0.2"); got != "203.0.113.7 https" {
		t.Fatalf("trusted = %q", got)
	}
	if got := ip(trusted, "not-an-ip, 203.0.113.9"); got != "203.0.113.9 https" {
		t.Fatalf("invalid entries skipped = %q", got)
	}
	if got := ip(trusted, ""); got != "0.0.0.0 http" {
		t.Fatalf("no header = %q", got)
	}
	other := &Server{TrustedProxies: []string{"10.0.0.0/8"}}
	if got := ip(other, "203.0.113.7"); got != "0.0.0.0 http" {
		t.Fatalf("untrusted peer = %q, want socket address and no forwarded proto", got)
	}
}
