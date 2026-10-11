package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/gofiber/fiber/v2"
)

// fakeSiteverify stands in for Turnstile and hCaptcha. The answer follows
// the response token (good, bad, wronghost, wrongaction, timeout) and, for
// tokens it does not know, the secret (the config test endpoint).
type fakeSiteverify struct {
	mu    sync.Mutex
	calls []url.Values
	hosts []string
}

func (f *fakeSiteverify) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	f.mu.Lock()
	f.calls = append(f.calls, form)
	f.hosts = append(f.hosts, r.URL.Host)
	f.mu.Unlock()
	reply := func(status int, body string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
	switch form.Get("response") {
	case "good":
		return reply(200, `{"success":true,"hostname":"iam.example","action":"`+form.Get("action")+`"}`)
	case "good-anywhere":
		return reply(200, `{"success":true,"hostname":"app.example.com"}`)
	case "bad":
		return reply(200, `{"success":false,"error-codes":["invalid-input-response"]}`)
	case "wronghost":
		return reply(200, `{"success":true,"hostname":"evil.example"}`)
	case "wrongaction":
		return reply(200, `{"success":true,"hostname":"iam.example","action":"signup"}`)
	case "timeout":
		return nil, io.ErrUnexpectedEOF
	}
	switch form.Get("secret") {
	case "secret-invalid":
		return reply(200, `{"success":false,"error-codes":["invalid-input-secret"]}`)
	case "secret-down":
		return reply(502, `bad gateway`)
	}
	return reply(200, `{"success":false,"error-codes":["invalid-input-response"]}`)
}

func (f *fakeSiteverify) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeSiteverify) Last() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

// TestCaptcha covers the CAPTCHA backend: configuration, the test
// endpoint, headless gating, fail-open, the kill switch and the hosted
// pages (widget, CSP, one pass for the whole journey).
func TestCaptcha(t *testing.T) {
	fake := &fakeSiteverify{}
	e := newEnv(t, bootstrap.WithCaptchaTransport(fake))
	cfg := e.Base + "/captcha"
	login := func(token string) Response {
		body := e.LoginBody(e.AliceEmail, e.Pass)
		if token != "" {
			body["captcha_token"] = token
		}
		return e.Do("POST", "/identity/v1/login", "", body)
	}
	codeOf := func(r Response) any { return errorOf(r)["code"] }

	// No configuration: nothing changes anywhere.
	if r := login(""); r.Status != 200 {
		t.Fatalf("no config: %d %s", r.Status, r.Body)
	}
	if r := e.Do("GET", "/identity/v1/captcha/"+e.EnvID, "", nil); r.Status != 200 || r.JSON["enabled"] != false {
		t.Fatalf("public without config: %d %s", r.Status, r.Body)
	}
	e.Must("GET", cfg, e.Owner, nil, 404)
	hb := e.browser()
	client := e.hostedClient()
	plain := hb.authorize(client)
	noConfigCSP := plain.Header.Get("Content-Security-Policy")
	if noConfigCSP == "" || strings.Contains(noConfigCSP, "cloudflare") || strings.Contains(noConfigCSP, "hcaptcha") || strings.Contains(plain.Body, "cf-turnstile") {
		t.Fatalf("no config: CSP %q", noConfigCSP)
	}
	if c, ok := hb.cookies["__Host-iamkit-device"]; !ok || !c.Secure || !c.HttpOnly || c.Path != "/" || c.MaxAge <= 0 {
		t.Fatalf("device cookie = %+v", c)
	}
	e.Must("POST", cfg+"/test", e.Owner, nil, 404)

	// The secret is stored sealed and never returned.
	saved := e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "0xSITEKEY", "secret": "secret-ok"}, 200)
	if strings.Contains(saved.Body, "secret-ok") || saved.JSON["secret"] != nil || saved.JSON["hosted"] != true || saved.JSON["headless"] != true {
		t.Fatalf("saved: %s", saved.Body)
	}
	if got := e.Must("GET", cfg, e.Owner, nil, 200); strings.Contains(got.Body, "secret-ok") || got.JSON["site_key"] != "0xSITEKEY" {
		t.Fatalf("read back: %s", got.Body)
	}
	var sealed string
	if err := e.DB.Get(&sealed, `SELECT secret_sealed FROM captcha_configs WHERE environment_id=$1`, e.EnvID); err != nil || sealed == "" || strings.Contains(sealed, "secret-ok") {
		t.Fatalf("sealed = %q, %v", sealed, err)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM audit_events WHERE action='captcha.update'`); n != 1 {
		t.Fatalf("captcha.update audits = %d", n)
	}
	if r := e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "0xSITEKEY2"}, 200); r.JSON["site_key"] != "0xSITEKEY2" {
		t.Fatalf("update keeping the secret: %s", r.Body)
	}
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "recaptcha", "site_key": "k", "secret": "s"}, 400)

	// Public: what a custom UI renders, never the secret.
	pub := e.Do("GET", "/identity/v1/captcha/"+e.EnvID, "", nil)
	if pub.Status != 200 || pub.JSON["enabled"] != true || pub.JSON["provider"] != "turnstile" || pub.JSON["site_key"] != "0xSITEKEY2" || strings.Contains(pub.Body, "secret") {
		t.Fatalf("public: %d %s", pub.Status, pub.Body)
	}

	// Test endpoint: 204 (secret accepted), 422 (rejected), 502 (provider down).
	e.Must("POST", cfg+"/test", e.Owner, nil, 204)
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "0xSITEKEY2", "secret": "secret-invalid"}, 200)
	if r := e.Do("POST", cfg+"/test", e.Owner, nil); r.Status != 422 || codeOf(r) != "CAPTCHA_SECRET_INVALID" {
		t.Fatalf("invalid secret: %d %s", r.Status, r.Body)
	}
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "0xSITEKEY2", "secret": "secret-down"}, 200)
	e.Must("POST", cfg+"/test", e.Owner, nil, 502)
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "0xSITEKEY2", "secret": "secret-ok"}, 200)

	// Headless gating on login, challenges, signup.
	before := fake.Calls()
	if r := login(""); r.Status != 403 || codeOf(r) != "CAPTCHA_REQUIRED" || fake.Calls() != before {
		t.Fatalf("no token: %d %s (provider calls %d→%d)", r.Status, r.Body, before, fake.Calls())
	} else if d, _ := errorOf(r)["details"].(map[string]any); d["provider"] != "turnstile" {
		t.Fatalf("CAPTCHA_REQUIRED names no provider: %s", r.Body)
	}
	if r := login("bad"); r.Status != 403 || codeOf(r) != "CAPTCHA_REQUIRED" {
		t.Fatalf("bad token: %d %s", r.Status, r.Body)
	}
	if r := login("wrongaction"); r.Status != 403 || codeOf(r) != "CAPTCHA_REQUIRED" {
		t.Fatalf("action mismatch: %d %s", r.Status, r.Body)
	}
	if r := login("good"); r.Status != 200 {
		t.Fatalf("good token: %d %s", r.Status, r.Body)
	}
	if v := fake.Last(); v.Get("secret") != "secret-ok" || v.Get("response") != "good" {
		t.Fatalf("siteverify form = %v", v)
	}
	// A wrong password with a good token is the ordinary failure, not the CAPTCHA's.
	if r := e.Do("POST", "/identity/v1/login", "", func() fiber.Map {
		b := e.LoginBody(e.AliceEmail, "wrong password here")
		b["captcha_token"] = "good"
		return b
	}()); r.Status != 401 {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
	for _, purpose := range []string{"login", "password_reset", "email_verification"} {
		body := fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": purpose}
		if r := e.Do("POST", "/identity/v1/challenges", "", body); r.Status != 403 || codeOf(r) != "CAPTCHA_REQUIRED" {
			t.Fatalf("challenge %s without token: %d %s", purpose, r.Status, r.Body)
		}
		body["captcha_token"] = "good"
		e.Must("POST", "/identity/v1/challenges", "", body, 202)
	}
	su := fiber.Map{"environment_id": e.EnvID, "email": "new@example.com", "name": "New", "password": "a long enough password"}
	if r := e.Do("POST", "/identity/v1/signup", "", su); r.Status == 202 || (r.Status != 403 && codeOf(r) != "SIGNUP_DISABLED") {
		t.Fatalf("signup without token: %d %s", r.Status, r.Body)
	}

	// Hostname mismatch: configured hostnames must match the solved one.
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "k", "hostnames": []string{"app.example.com"}}, 200)
	if r := login("wronghost"); r.Status != 403 || codeOf(r) != "CAPTCHA_REQUIRED" {
		t.Fatalf("hostname mismatch: %d %s", r.Status, r.Body)
	}
	if r := login("good-anywhere"); r.Status != 200 {
		t.Fatalf("hostname match: %d %s", r.Status, r.Body)
	}
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "k", "hostnames": []string{}}, 200)

	// Provider down: fail open.
	if r := login("timeout"); r.Status != 200 {
		t.Fatalf("provider unreachable must fail open: %d %s", r.Status, r.Body)
	}

	// Headless off: no token needed, nothing announced.
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "k", "headless": false}, 200)
	if r := login(""); r.Status != 200 {
		t.Fatalf("headless off: %d %s", r.Status, r.Body)
	}
	if r := e.Do("GET", "/identity/v1/captcha/"+e.EnvID, "", nil); r.JSON["enabled"] != false {
		t.Fatalf("public with headless off: %s", r.Body)
	}
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "turnstile", "site_key": "k", "headless": true}, 200)

	// The authorize ticket description tells a custom UI which widget to render.
	ui := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{"https://login.example.com"}}, 201).JSON["client_id"].(string)
	described := func() map[string]any {
		b := e.browser()
		sum := sha256.Sum256([]byte(hostedVerifier))
		q := url.Values{"client_id": {ui}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
		start := b.get("/oauth/authorize?" + q.Encode())
		var begin map[string]any
		json.Unmarshal([]byte(start.Body), &begin)
		ticket, _ := begin["authorization_ticket"].(string)
		info := b.get("/identity/v1/authorize/" + url.PathEscape(ticket))
		var out map[string]any
		if info.Status != 200 || json.Unmarshal([]byte(info.Body), &out) != nil {
			t.Fatalf("ticket description: %d %s", info.Status, info.Body)
		}
		return out
	}
	if c, _ := described()["captcha"].(map[string]any); c["provider"] != "turnstile" || c["site_key"] != "k" || len(c) != 2 {
		t.Fatalf("description captcha = %v", c)
	}

	// Feature flag off: the CAPTCHA is skipped everywhere.
	e.Must("PUT", e.Base+"/features/captcha", e.Owner, fiber.Map{"enabled": false}, 200)
	calls := fake.Calls()
	if r := login(""); r.Status != 200 || fake.Calls() != calls {
		t.Fatalf("feature off: %d %s", r.Status, r.Body)
	}
	if r := e.Do("GET", "/identity/v1/captcha/"+e.EnvID, "", nil); r.JSON["enabled"] != false {
		t.Fatalf("public with the feature off: %s", r.Body)
	}
	hb = e.browser()
	if p := hb.authorize(client); strings.Contains(p.Body, "cf-turnstile") || strings.Contains(p.Header.Get("Content-Security-Policy"), "cloudflare") {
		t.Fatal("widget with the feature off")
	}
	if _, ok := described()["captcha"]; ok {
		t.Fatal("ticket description announces a CAPTCHA with the feature off")
	}
	e.Must("PUT", e.Base+"/features/captcha", e.Owner, fiber.Map{"enabled": true}, 200)

	// Hosted: the identify page renders the widget and its CSP admits the provider.
	hb = e.browser()
	idPage := hb.authorize(client)
	csp := idPage.Header.Get("Content-Security-Policy")
	if !strings.Contains(idPage.Body, `class="cf-turnstile"`) || !strings.Contains(idPage.Body, `data-sitekey="k"`) || !strings.Contains(idPage.Body, "https://challenges.cloudflare.com/turnstile/v0/api.js") {
		t.Fatalf("no widget: %s", idPage.Body)
	}
	if !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "https://challenges.cloudflare.com") || strings.Contains(csp, "hcaptcha") {
		t.Fatalf("CSP = %q", csp)
	}
	tk := idPage.field("ticket")
	// Without an answer: the page comes back with the widget and the error.
	again := hb.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if again.Status != 403 || !strings.Contains(again.Body, "cf-turnstile") {
		t.Fatalf("identify without token: %d %s", again.Status, again.Body)
	}
	// A credential step cannot skip the identify page.
	if p := hb.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 {
		t.Fatalf("password before the CAPTCHA: %d", p.Status)
	}
	// One answer covers the journey: the password page needs none.
	next := hb.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "cf-turnstile-response": {"good"}})
	if next.Status != 200 || strings.Contains(next.Body, "cf-turnstile") {
		t.Fatalf("identify with token: %d %s", next.Status, next.Body)
	}
	if strings.Contains(next.Header.Get("Content-Security-Policy"), "cloudflare") {
		t.Fatal("CSP admits the provider on a page without the widget")
	}
	if n := count(t, e.DB, `SELECT count(*) FROM hosted_captcha_passes`); n != 1 {
		t.Fatalf("passes = %d", n)
	}
	done := hb.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	hb.exchange(client, done)

	// A pass covers config.CaptchaPassUses credential posts, then the
	// widget comes back: one solve never covers a guessing run.
	hb = e.browser()
	tk = hb.authorize(client).field("ticket")
	hb.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "cf-turnstile-response": {"good"}})
	for i := 0; i < config.CaptchaPassUses; i++ {
		if p := hb.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"wrong password " + strconv.Itoa(i)}}); p.Status == 403 && strings.Contains(p.Body, "cf-turnstile") {
			t.Fatalf("pass spent after %d posts", i)
		}
	}
	if p := hb.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 403 || !strings.Contains(p.Body, "cf-turnstile") {
		t.Fatalf("spent pass still accepted: %d", p.Status)
	}

	// Provider failure on a hosted page fails open too.
	hb = e.browser()
	tk = hb.authorize(client).field("ticket")
	if p := hb.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "cf-turnstile-response": {"timeout"}}); p.Status != 200 {
		t.Fatalf("hosted fail open: %d %s", p.Status, p.Body)
	}
	// A token solved on another host is refused.
	hb = e.browser()
	tk = hb.authorize(client).field("ticket")
	if p := hb.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "cf-turnstile-response": {"wronghost"}}); p.Status != 403 {
		t.Fatalf("hosted hostname mismatch: %d", p.Status)
	}

	// hCaptcha: its own field and hosts.
	e.Must("PUT", cfg, e.Owner, fiber.Map{"provider": "hcaptcha", "site_key": "hk", "secret": "secret-ok"}, 200)
	hb = e.browser()
	hp := hb.authorize(client)
	hcsp := hp.Header.Get("Content-Security-Policy")
	if !strings.Contains(hp.Body, `class="h-captcha"`) || !strings.Contains(hcsp, "https://hcaptcha.com") || !strings.Contains(hcsp, "https://*.hcaptcha.com") || strings.Contains(hcsp, "cloudflare") {
		t.Fatalf("hcaptcha page: CSP %q", hcsp)
	}
	hb.post("/hosted/login/identify", url.Values{"ticket": {hp.field("ticket")}, "email": {e.AliceEmail}, "h-captcha-response": {"good"}})
	if v := fake.Last(); v.Get("response") != "good" {
		t.Fatalf("hcaptcha form = %v", v)
	}

	// Sign-up page widget; deleting the configuration restores the original pages.
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}, 200)
	hb = e.browser()
	stk := hb.authorize(client).field("ticket")
	if p := hb.get("/hosted/signup?ticket=" + url.QueryEscape(stk)); p.Status != 200 || !strings.Contains(p.Body, "h-captcha") {
		t.Fatalf("signup page: %d %s", p.Status, p.Body)
	}
	e.Must("DELETE", cfg, e.Owner, nil, 204)
	if n := count(t, e.DB, `SELECT count(*) FROM audit_events WHERE action='captcha.delete'`); n != 1 {
		t.Fatalf("captcha.delete audits = %d", n)
	}
	if r := login(""); r.Status != 200 {
		t.Fatalf("after delete: %d %s", r.Status, r.Body)
	}
	hb = e.browser()
	after := hb.authorize(client)
	// The nonce differs per page: compare with it masked.
	nonce := regexp.MustCompile(`nonce-[A-Za-z0-9+/=_-]+`)
	if got := nonce.ReplaceAllString(after.Header.Get("Content-Security-Policy"), "nonce-N"); got != nonce.ReplaceAllString(noConfigCSP, "nonce-N") {
		t.Fatalf("CSP after delete = %q, want %q", got, noConfigCSP)
	}
	if strings.Contains(after.Body, "h-captcha") || strings.Contains(after.Header.Get("Content-Security-Policy"), "hcaptcha") {
		t.Fatal("widget after the configuration was deleted")
	}
}

// TestCaptchaLDAPAndDevice covers the remaining gated entry points: the
// headless LDAP login, and the hosted device page whose pass follows the
// approved device into the sign-in (identify and password need no second
// widget).
func TestCaptchaLDAPAndDevice(t *testing.T) {
	fake := &fakeSiteverify{}
	e := newEnv(t, loopbackLDAP(), bootstrap.WithCaptchaTransport(fake))
	e.Must("PUT", e.Base+"/captcha", e.Owner, fiber.Map{"provider": "turnstile", "site_key": "k", "secret": "secret-ok"}, 200)

	dir := directory(t, true)
	connections := e.Base + "/federation-connections"
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "AD", "provider": "ldap", "client_secret": "service-pass",
		"options": fiber.Map{"url": dir.URL, "bind_dn": "cn=iam,dc=example,dc=com", "user_base_dn": ldapBase, "ca_pem": dir.CA}})
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	ldap := func(token string) Response {
		body := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "connection_id": conn, "email": "dora@example.com", "password": "dora-pass"}
		if token != "" {
			body["captcha_token"] = token
		}
		return e.Do("POST", "/identity/v1/federation/ldap/login", "", body)
	}
	if r := ldap(""); r.Status != 403 || errorOf(r)["code"] != "CAPTCHA_REQUIRED" {
		t.Fatalf("ldap without token: %d %s", r.Status, r.Body)
	}
	if r := ldap("bad"); r.Status != 403 {
		t.Fatalf("ldap bad token: %d %s", r.Status, r.Body)
	}
	// Past the CAPTCHA the directory signs the user in; a fresh JIT user
	// has no role yet, which is the ordinary "no access" answer.
	if r := ldap("good"); r.Status != 403 || errorOf(r)["code"] != "FORBIDDEN" {
		t.Fatalf("ldap good token: %d %s", r.Status, r.Body)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='dora@example.com'`); n != 1 {
		t.Fatalf("the directory user was not signed in past the CAPTCHA: %d", n)
	}

	// Device: the user code page asks for the widget before the sign-in starts.
	grants := []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true, "hosted_login": true, "grant_types": grants}, 201).JSON["client_id"].(string)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	start := e.deviceRequest(url.Values{"client_id": {client}, "scope": {"openid"}})
	userCode := start.JSON["user_code"].(string)

	b := e.browser()
	confirm := b.post("/hosted/device", url.Values{"user_code": {userCode}})
	if confirm.Status != 200 || !strings.Contains(confirm.Body, "cf-turnstile") || !strings.Contains(confirm.Header.Get("Content-Security-Policy"), "challenges.cloudflare.com") {
		t.Fatalf("device confirm: %d %s", confirm.Status, confirm.Body)
	}
	if p := b.post("/hosted/device/approve", url.Values{"user_code": {userCode}}); p.Status != 403 || !strings.Contains(p.Body, "cf-turnstile") {
		t.Fatalf("approve without the CAPTCHA: %d %s", p.Status, p.Body)
	}
	approve := b.post("/hosted/device/approve", url.Values{"user_code": {userCode}, "cf-turnstile-response": {"good"}})
	if approve.Status != 303 || !strings.HasPrefix(approve.Location, "/hosted/login?ticket=ik_authorize_") {
		t.Fatalf("approve: %d %s", approve.Status, approve.Body)
	}
	login := b.get(approve.Location)
	if strings.Contains(login.Body, "cf-turnstile") {
		t.Fatal("the sign-in page of an approved device asks for a second widget")
	}
	tk := login.field("ticket")
	if p := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}}); p.Status != 200 {
		t.Fatalf("identify after the device pass: %d %s", p.Status, p.Body)
	}
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if done.Status != 200 || !strings.Contains(done.Body, "Device connected") {
		t.Fatalf("device sign-in: %d %s", done.Status, done.Body)
	}
}
