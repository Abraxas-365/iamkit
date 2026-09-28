package mgmthttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
)

type fakeFlows struct {
	startErr, callbackErr error
	code, state, binding  string
}

func (fakeFlows) Options(context.Context) management.LoginOptions {
	return management.LoginOptions{Password: true, Providers: []management.SSOProviderView{{ID: "acme", Name: "Acme", Type: "oidc"}}}
}
func (f *fakeFlows) Start(context.Context, string) (management.SSOStart, error) {
	return management.SSOStart{URL: "https://idp.example/authorize?state=s", Binding: "ik_binding_b"}, f.startErr
}
func (f *fakeFlows) Callback(_ context.Context, code, state, binding string) (string, management.Principal, error) {
	f.code, f.state, f.binding = code, state, binding
	if f.callbackErr != nil {
		return "", management.Principal{}, f.callbackErr
	}
	return "ik_sess_new", management.Principal{Role: "admin"}, nil
}

func ssoApp(f *fakeFlows) *fiber.App {
	h := NewSSO(f, nil, nil)
	app := fiber.New()
	app.Get("/login-options", h.Options)
	app.Get("/sso/callback", h.Callback)
	app.Get("/sso/:provider/start", h.Start)
	return app
}

func cookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSSOStart(t *testing.T) {
	f := &fakeFlows{}
	res, err := ssoApp(f).Test(httptest.NewRequest("GET", "/sso/acme/start", nil))
	if err != nil {
		t.Fatal(err)
	}
	c := cookie(res, ssoCookie)
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://idp.example/authorize?state=s" || c == nil || c.Value != "ik_binding_b" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("start: %d %s %+v", res.StatusCode, res.Header.Get("Location"), c)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", res.Header)
	}
	f.startErr = errx.NotFound("operator SSO provider not found")
	res, _ = ssoApp(f).Test(httptest.NewRequest("GET", "/sso/nope/start", nil))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/login?sso_error=not_authorized" {
		t.Fatalf("unknown provider: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestSSOCallback(t *testing.T) {
	f := &fakeFlows{}
	req := httptest.NewRequest("GET", "/sso/callback?code=c&state=s", nil)
	req.AddCookie(&http.Cookie{Name: ssoCookie, Value: "ik_binding_b"})
	res, err := ssoApp(f).Test(req)
	if err != nil {
		t.Fatal(err)
	}
	session := cookie(res, sessionCookie)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" || session == nil || session.Value != "ik_sess_new" || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("callback: %d %s %+v", res.StatusCode, res.Header.Get("Location"), session)
	}
	if f.code != "c" || f.state != "s" || f.binding != "ik_binding_b" {
		t.Fatalf("flow got %+v", f)
	}
	if c := cookie(res, ssoCookie); c == nil || c.MaxAge >= 0 && c.Value != "" {
		t.Fatalf("binding cookie not cleared: %+v", c)
	}

	cases := []struct {
		err  error
		want string
	}{
		{management.ErrSSOExpired(), "expired"},
		{management.ErrSSONotAuthorized("no operator"), "not_authorized"},
		{errx.Unauthorized("token exchange failed"), "not_authorized"},
		{func() error { e := errx.External("down"); e.Code = "PROVIDER_UNAVAILABLE"; return e }(), "provider_unavailable"},
		{errors.New("boom"), "failed"},
	}
	for _, tc := range cases {
		f.callbackErr = tc.err
		res, _ = ssoApp(f).Test(httptest.NewRequest("GET", "/sso/callback?code=c&state=s", nil))
		if res.StatusCode != 303 || res.Header.Get("Location") != "/login?sso_error="+tc.want || cookie(res, sessionCookie) != nil {
			t.Fatalf("%v: %d %s", tc.err, res.StatusCode, res.Header.Get("Location"))
		}
	}

	f.callbackErr, f.code = nil, ""
	res, _ = ssoApp(f).Test(httptest.NewRequest("GET", "/sso/callback?error=access_denied&state=s", nil))
	if res.Header.Get("Location") != "/login?sso_error=cancelled" || f.code != "" {
		t.Fatalf("cancelled: %s", res.Header.Get("Location"))
	}
	// An error response with a code is still an error: no exchange.
	res, _ = ssoApp(f).Test(httptest.NewRequest("GET", "/sso/callback?error=server_error&code=c&state=s", nil))
	if res.Header.Get("Location") != "/login?sso_error=cancelled" || f.code != "" || cookie(res, sessionCookie) != nil {
		t.Fatalf("error with code: %s %q", res.Header.Get("Location"), f.code)
	}
}

func TestSSOOptions(t *testing.T) {
	res, _ := ssoApp(&fakeFlows{}).Test(httptest.NewRequest("GET", "/login-options", nil))
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("options: %d", res.StatusCode)
	}
}
