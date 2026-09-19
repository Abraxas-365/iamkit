package mgmthttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
)

type consoleAuth struct {
	management.ManagementAuthenticator
}

func (consoleAuth) Authenticate(context.Context, string) (management.Principal, error) {
	return management.Principal{Role: "owner"}, nil
}
func (consoleAuth) AuthenticateSession(context.Context, string) (management.Principal, error) {
	return management.Principal{Role: "owner"}, nil
}

type consoleSessions struct {
	management.SessionCommands
	logoutErr error
	loggedOut string
}

func (*consoleSessions) Login(context.Context, string, string) (string, management.Principal, error) {
	return "ik_sess_test", management.Principal{Role: "owner"}, nil
}
func (s *consoleSessions) Logout(_ context.Context, raw string) error {
	s.loggedOut = raw
	return s.logoutErr
}

func consoleApp(s *consoleSessions) *fiber.App {
	h := New(consoleAuth{}, s, nil, nil)
	app := fiber.New()
	app.Post("/login", h.Login)
	app.Post("/mutate", h.Authenticate, func(c *fiber.Ctx) error { return c.SendStatus(204) })
	app.Delete("/logout", h.Authenticate, h.logout)
	return app
}
func TestConsoleCookieAndCSRF(t *testing.T) {
	s := &consoleSessions{}
	app := consoleApp(s)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"email":"owner@example.com","password":"password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IAMKit-Console", "1")
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("login status: %d", res.StatusCode)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookie || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("invalid Host cookie: %+v", cookie)
	}
	for _, tc := range []struct {
		name, path, header, site, apiKey string
		allowed                         bool
	}{
		{"login no header", "/login", "", "", "", false},
		{"login cross site", "/login", "1", "cross-site", "", false},
		{"cookie no header", "/mutate", "", "", "", false},
		{"cookie cross site", "/mutate", "1", "cross-site", "", false},
		{"cookie same origin", "/mutate", "1", "same-origin", "", true},
		{"api key automation", "/mutate", "", "", "ik_mgmt_test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, nil)
			r.AddCookie(cookie)
			r.Header.Set("X-IAMKit-Console", tc.header)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.apiKey != "" {
				r.Header.Set("X-API-Key", tc.apiKey)
			}
			out, err := app.Test(r)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Body.Close()
			if (out.StatusCode < 300) != tc.allowed {
				t.Fatalf("unexpected status %d", out.StatusCode)
			}
		})
	}
}
func TestLogoutPropagatesRevocationFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		s := &consoleSessions{}
		if fail {
			s.logoutErr = errors.New("database unavailable")
		}
		r := httptest.NewRequest("DELETE", "/logout", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "ik_sess_test"})
		r.Header.Set("X-IAMKit-Console", "1")
		res, err := consoleApp(s).Test(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if s.loggedOut != "ik_sess_test" {
			t.Fatal("session was not revoked")
		}
		if fail && res.StatusCode < 500 {
			t.Fatal("revocation failure hidden")
		}
		if !fail && (res.StatusCode != 204 || len(res.Cookies()) != 1 || res.Cookies()[0].Path != "/" || res.Cookies()[0].MaxAge >= 0) {
			t.Fatal("logout did not clear Host cookie")
		}
	}
}
