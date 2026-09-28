package e2e_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// mockIdPImage is a real OIDC provider (discovery, JWKS, signed ID tokens,
// PKCE and nonce enforcement) whose sign-in form takes the subject and
// claims to issue.
const mockIdPImage = "ghcr.io/navikt/mock-oauth2-server:2.1.10"

// forwardedHTTPS lets the plain-HTTP container stand in for an HTTPS
// issuer: requests to https://host go to http://host with
// X-Forwarded-Proto, so the IdP names itself https:// in discovery and in
// the tokens it signs.
type forwardedHTTPS struct{ base http.RoundTripper }

func (f forwardedHTTPS) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if r.URL.Scheme == "https" {
		r.URL.Scheme = "http"
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	return f.base.RoundTrip(r)
}

// startMockIdP runs the provider container and returns its HTTPS-form
// issuer for tenant "acme".
func startMockIdP(t *testing.T) (issuer string, transport http.RoundTripper) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, mockIdPImage,
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithWaitStrategyAndDeadline(90*time.Second,
			wait.ForHTTP("/acme/.well-known/openid-configuration").WithPort("8080/tcp")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := c.PortEndpoint(ctx, "8080/tcp", "https")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint + "/acme", forwardedHTTPS{base: http.DefaultTransport}
}

// containerSignIn runs one browser sign-in: IAMKit start → the real IdP's
// login form (subject + claims) → IAMKit callback with the code it issued.
func containerSignIn(t *testing.T, h *Harness, transport http.RoundTripper, subject, claims string) *http.Response {
	t.Helper()
	start, err := h.App.Test(httptest.NewRequest("GET", "/management/v1/sso/acme/start", nil), 10000)
	if err != nil {
		t.Fatal(err)
	}
	start.Body.Close()
	if start.StatusCode != fiber.StatusFound {
		t.Fatalf("start: %d", start.StatusCode)
	}
	authorize := start.Header.Get("Location")
	q := mustURL(t, authorize).Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://iam.example/management/v1/sso/callback" {
		t.Fatalf("authorize request: %s", authorize)
	}
	// The operator submits the IdP's sign-in form.
	browser := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"username": {subject}, "claims": {claims}}
	res, err := browser.Post(authorize, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	back := mustURL(t, res.Header.Get("Location"))
	if res.StatusCode != http.StatusFound || back.Host != "iam.example" || back.Query().Get("code") == "" || back.Query().Get("state") != q.Get("state") {
		t.Fatalf("idp redirect: %d %s", res.StatusCode, back)
	}
	callback := httptest.NewRequest("GET", back.RequestURI(), nil)
	for _, c := range start.Cookies() {
		callback.AddCookie(c)
	}
	out, err := h.App.Test(callback, 30000)
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	return out
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestOperatorSSOAgainstRealIdP signs operators in against a real OIDC
// provider container: discovery, the code exchange with PKCE and the client
// secret, ID token signature/issuer/audience/nonce checks, then IAMKit's
// linking rules.
func TestOperatorSSOAgainstRealIdP(t *testing.T) {
	requireE2E(t)
	issuer, transport := startMockIdP(t)
	sso := bootstrap.OperatorSSO{
		Settings: management.SSOSettings{Password: management.PasswordEnabled, Providers: []management.SSOProvider{
			{ID: "acme", Name: "Acme IdP", Type: management.SSOTypeOIDC, Issuer: issuer, Client: "console", AllowedDomains: []string{"acme.com"}},
		}},
		Secrets:   map[string]string{"acme": "console-secret"},
		Transport: transport,
	}
	h := newHarness(t, bootstrap.WithOperatorSSO(sso))
	invited := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "admin"}, 201)
	annID := invited.JSON["operator_id"].(string)

	refused := func(name string, res *http.Response) {
		t.Helper()
		if res.StatusCode != 303 || res.Header.Get("Location") != "/login?sso_error=not_authorized" || sessionCookie(res) != nil {
			t.Fatalf("%s: %d %s", name, res.StatusCode, res.Header.Get("Location"))
		}
	}
	refused("unverified email", containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com","email_verified":false}`))
	refused("outside allowed domains", containerSignIn(t, h, transport, "u-eve", `{"email":"ann@evil.com","email_verified":true}`))
	refused("not an operator", containerSignIn(t, h, transport, "u-bob", `{"email":"bob@acme.com","email_verified":true}`))

	res := containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com","email_verified":true}`)
	cookie := sessionCookie(res)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/" || cookie == nil {
		t.Fatalf("invited operator: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	me := httptest.NewRequest("GET", "/management/v1/me", nil)
	me.AddCookie(cookie)
	if out, _ := h.App.Test(me, 10000); out.StatusCode != 200 {
		t.Fatalf("me: %d", out.StatusCode)
	}
	if n := count(t, h.DB, `SELECT count(*) FROM operator_identities WHERE issuer=$1 AND subject='u-ann' AND operator_id=$2`, issuer, annID); n != 1 {
		t.Fatalf("identity not linked under the https issuer %s", issuer)
	}
	// Later sign-ins match the subject even without email_verified; another
	// subject with Ann's email cannot take over her operator.
	if res = containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com"}`); sessionCookie(res) == nil {
		t.Fatalf("linked sign-in: %s", res.Header.Get("Location"))
	}
	refused("second subject for the same operator", containerSignIn(t, h, transport, "u-ann-impostor", `{"email":"ann@acme.com","email_verified":true}`))

	// An ID token for another client (aud) fails verification.
	if res = containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com","email_verified":true,"aud":"someone-else"}`); sessionCookie(res) != nil || res.Header.Get("Location") != "/login?sso_error=not_authorized" {
		t.Fatalf("foreign audience: %s", res.Header.Get("Location"))
	}
}

// TestOperatorPasswordChangeAgainstRealIdP: in break-glass mode, the
// bootstrap owner's temporary password must be replaced at the first
// sign-in; an operator signed in through the real IdP sets an emergency
// password only right after signing in, and changing it keeps that session
// while ending the password ones.
func TestOperatorPasswordChangeAgainstRealIdP(t *testing.T) {
	requireE2E(t)
	issuer, transport := startMockIdP(t)
	h := newHarness(t, bootstrap.WithOperatorSSO(bootstrap.OperatorSSO{
		Settings: management.SSOSettings{Password: management.PasswordBreakGlass, Providers: []management.SSOProvider{
			{ID: "acme", Name: "Acme IdP", Type: management.SSOTypeOIDC, Issuer: issuer, Client: "console", AllowedDomains: []string{"acme.com"}},
		}},
		Secrets:   map[string]string{"acme": "console-secret"},
		Transport: transport,
	}))

	// The bootstrap owner (emergency access) with a temporary password.
	mgmt := bootstrap.ManagementWithPasswords(h.DB)
	owner, err := mgmt.Authenticate(t.Context(), h.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = mgmt.SetTemporaryPassword(t.Context(), owner, "bootstrap password"); err != nil {
		t.Fatal(err)
	}
	if status, code, c := consolePassword(t, h, "owner@example.com", "bootstrap password"); status != 403 || code != management.CodePasswordChangeRequired || c != nil {
		t.Fatalf("must change: %d %s", status, code)
	}
	if status, _, c := consoleLogin(t, h, map[string]string{"email": "owner@example.com", "password": "bootstrap password", "new_password": "owner chosen password"}); status != 200 || c == nil {
		t.Fatalf("change at login: %d", status)
	}

	// Ann signs in through the IdP; the owner grants her emergency access.
	invited := h.Must("POST", "/management/v1/operators", h.Owner, map[string]any{"email": "ann@acme.com", "role": "admin"}, 201)
	annID := invited.JSON["operator_id"].(string)
	h.Must("PUT", "/management/v1/operators/"+annID+"/password-access", h.Owner, map[string]any{"allowed": true}, 204)
	sso := sessionCookie(containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com","email_verified":true}`))
	if sso == nil {
		t.Fatal("ann sso sign-in")
	}
	// Right after signing in she may set a password without one.
	if status, code := consoleRequest(t, h, sso, "POST", "/management/v1/password", map[string]any{"password": "ann emergency pw"}); status != 204 {
		t.Fatalf("fresh sso set password: %d %s", status, code)
	}
	status, _, pw := consolePassword(t, h, "ann@acme.com", "ann emergency pw")
	if status != 200 || pw == nil {
		t.Fatalf("ann emergency login: %d", status)
	}
	// Once the sign-in is old she must sign in again.
	if _, err = h.DB.Exec(`UPDATE operator_sessions SET authenticated_at=now()-interval '1 hour' WHERE operator_id=$1 AND method='sso'`, annID); err != nil {
		t.Fatal(err)
	}
	if status, code := consoleRequest(t, h, sso, "POST", "/management/v1/password", map[string]any{"password": "another ann password"}); status != 403 || code != management.CodeReauthenticationRequired {
		t.Fatalf("stale sso: %d %s", status, code)
	}
	// With the current password the change works; her SSO session stays
	// and her password session ends.
	if status, code := consoleRequest(t, h, sso, "POST", "/management/v1/password", map[string]any{"current_password": "ann emergency pw", "password": "another ann password"}); status != 204 {
		t.Fatalf("change with current: %d %s", status, code)
	}
	if status, _ := consoleRequest(t, h, sso, "GET", "/management/v1/me", nil); status != 200 {
		t.Fatalf("sso session after change: %d", status)
	}
	if status, _ := consoleRequest(t, h, pw, "GET", "/management/v1/me", nil); status != 401 {
		t.Fatalf("password session after change: %d", status)
	}
	// A new sign-in through the IdP is fresh again.
	fresh := sessionCookie(containerSignIn(t, h, transport, "u-ann", `{"email":"ann@acme.com"}`))
	if status, code := consoleRequest(t, h, fresh, "POST", "/management/v1/password", map[string]any{"password": "third ann password"}); status != 204 {
		t.Fatalf("fresh again: %d %s", status, code)
	}
	if n := count(t, h.DB, `SELECT count(*) FROM operator_sessions WHERE operator_id=$1 AND revoked_at IS NULL`, annID); n != 1 {
		t.Fatalf("live sessions after the last change: %d", n)
	}
}
