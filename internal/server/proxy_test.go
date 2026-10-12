package server

import (
	"bufio"
	"fmt"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttputil"
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

// TestClientInfoMiddleware: the request context carries the address Fiber
// resolved (trusted proxies honoured) and the truncated User-Agent.
func TestClientInfoMiddleware(t *testing.T) {
	get := func(s *Server, forwarded string) identity.ClientInfo {
		t.Helper()
		app := fiber.New(s.config())
		var got identity.ClientInfo
		app.Use(s.clientInfo)
		app.Get("/", func(c *fiber.Ctx) error { got = identity.ClientInfoFrom(c.UserContext()); return nil })
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", strings.Repeat("a", 600))
		r.Header.Set("CF-IPCountry", "pe")
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		res, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return got
	}
	if got := get(&Server{}, "203.0.113.7"); got.IP != "0.0.0.0" || len(got.UserAgent) != identity.MaxUserAgent {
		t.Fatalf("untrusted = %+v", got)
	}
	if got := get(&Server{TrustedProxies: []string{"0.0.0.0/8"}}, "203.0.113.7"); got.IP != "203.0.113.7" || got.Country != "" {
		t.Fatalf("trusted = %+v", got)
	}
	// The country header is believed from trusted proxies only.
	if got := get(&Server{GeoIPHeader: "CF-IPCountry"}, ""); got.Country != "" {
		t.Fatalf("untrusted country = %+v", got)
	}
	if got := get(&Server{GeoIPHeader: "CF-IPCountry", TrustedProxies: []string{"0.0.0.0/8"}}, "203.0.113.7"); got.Country != "PE" {
		t.Fatalf("trusted country = %+v", got)
	}
}

// TestRequestHeaderLimit: requests carrying several kilobytes of an
// application's own cookies (shared host) are still read.
func TestRequestHeaderLimit(t *testing.T) {
	app := fiber.New((&Server{}).config())
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(204) })
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()
	go func() { _ = app.Listener(ln) }()
	defer func() { _ = app.Shutdown() }()
	status := func(cookie int) int {
		conn, err := ln.Dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\nCookie: a=%s\r\nConnection: close\r\n\r\n", strings.Repeat("a", cookie))
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if got := status(8 * 1024); got != 204 {
		t.Fatalf("8 KiB of cookies: %d", got)
	}
	if got := status(20 * 1024); got != 431 {
		t.Fatalf("20 KiB of cookies: %d, want 431", got)
	}
}
