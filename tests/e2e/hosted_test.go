package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// browser drives the hosted pages like a browser without JavaScript: it
// keeps cookies and submits forms.
type browser struct {
	t       *testing.T
	e       *Env
	cookies map[string]*http.Cookie
}

type page struct {
	Status   int
	Body     string
	Location string
	Header   http.Header
}

func (e *Env) browser() *browser {
	return &browser{t: e.t, e: e, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, path string, form url.Values) page {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	res, err := b.e.App.Test(req, 10000)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return page{Status: res.StatusCode, Body: string(raw), Location: res.Header.Get("Location"), Header: res.Header}
}

func (b *browser) get(path string) page { return b.do("GET", path, nil) }
func (b *browser) post(path string, form url.Values) page {
	return b.do("POST", path, form)
}

var hiddenField = regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)

// field returns the first hidden or prefilled form value named name.
func (p page) field(name string) string {
	for _, m := range hiddenField.FindAllStringSubmatch(p.Body, -1) {
		if m[1] == name {
			return html.UnescapeString(m[2])
		}
	}
	return ""
}

func (p page) fields(name string) []string {
	var out []string
	for _, m := range hiddenField.FindAllStringSubmatch(p.Body, -1) {
		if m[1] == name {
			out = append(out, html.UnescapeString(m[2]))
		}
	}
	return out
}

// hostedClient registers a public OAuth client for the env's application
// with hosted login enabled.
func (e *Env) hostedClient() string {
	e.t.Helper()
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "hosted_login": true}, 201).JSON["client_id"].(string)
	return client
}

const hostedVerifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

// authorize starts an authorization in the browser and follows the
// redirect to the hosted sign-in page.
func (b *browser) authorize(client string) page {
	b.t.Helper()
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	start := b.get("/oauth/authorize?" + q.Encode())
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=ik_authorize_") {
		b.t.Fatalf("authorize: %d %q %s", start.Status, start.Location, start.Body)
	}
	if _, ok := b.cookies["__Host-iamkit-authorization"]; !ok {
		b.t.Fatal("missing authorization binding cookie")
	}
	login := b.get(start.Location)
	if login.Status != 200 || login.field("ticket") == "" {
		b.t.Fatalf("login page: %d %s", login.Status, login.Body)
	}
	return login
}

// exchange redeems the code a finished hosted login redirected with.
func (b *browser) exchange(client string, done page) map[string]any {
	b.t.Helper()
	location, err := url.Parse(done.Location)
	if done.Status != 303 || err != nil || !strings.HasPrefix(done.Location, "https://app.example/callback") || location.Query().Get("code") == "" || location.Query().Get("state") != "unpredictable-state-123456" {
		b.t.Fatalf("finish: %d %q %s", done.Status, done.Location, done.Body)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "code": {location.Query().Get("code")}, "code_verifier": {hostedVerifier}}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := b.e.App.Test(req, 10000)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != 200 || out["access_token"] == nil || out["id_token"] == nil {
		b.t.Fatalf("token: %d %v", res.StatusCode, out)
	}
	return out
}

// claims decodes a JWT payload without verifying it (the server issued it).
func claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

// TestHostedLoginJourney covers the hosted pages end to end: opt-in per
// client, password with one and several organizations, email codes,
// password reset, SSO routing and enforcement, branding and the invitation
// accept page.
func TestHostedLoginJourney(t *testing.T) {
	e := newEnv(t)
	client := e.hostedClient()

	// Headless clients keep the JSON contract; the hosted pages refuse them.
	headless := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true}, 201).JSON["client_id"].(string)
	list := items(e.Must("GET", e.Base+"/oauth-clients", e.Owner, nil, 200))
	for _, c := range list {
		if (c["id"] == client) != (c["hosted_login"] == true) {
			t.Fatalf("client list = %v", list)
		}
	}
	hb := e.browser()
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {headless}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	start := hb.get("/oauth/authorize?" + q.Encode())
	var ticket map[string]any
	json.Unmarshal([]byte(start.Body), &ticket)
	if start.Status != 200 || ticket["authorization_ticket"] == nil {
		t.Fatalf("headless authorize: %d %s", start.Status, start.Body)
	}
	if p := hb.get("/hosted/login?ticket=" + url.QueryEscape(ticket["authorization_ticket"].(string))); p.Status != 403 {
		t.Fatalf("hosted page for headless client: %d", p.Status)
	}

	// Page security: strict CSP with a nonce, no framing, no caching.
	b := e.browser()
	login := b.authorize(client)
	csp := login.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "style-src 'nonce-") || !strings.Contains(csp, "frame-ancestors 'none'") ||
		login.Header.Get("X-Frame-Options") != "DENY" || login.Header.Get("Cache-Control") != "no-store" || strings.Contains(login.Body, "<script") {
		t.Fatalf("headers = %v", login.Header)
	}
	// A ticket without its browser binding is useless.
	stranger := e.browser()
	if p := stranger.get("/hosted/login?ticket=" + url.QueryEscape(login.field("ticket"))); p.Status != 401 {
		t.Fatalf("unbound ticket: %d", p.Status)
	}

	// Password, one organization: straight back to the client.
	tk := login.field("ticket")
	pw := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if pw.Status != 200 || !strings.Contains(pw.Body, `name="password"`) || pw.field("email") != e.AliceEmail {
		t.Fatalf("identify: %d %s", pw.Status, pw.Body)
	}
	if r := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"wrong password!!"}}); r.Status != 401 || !strings.Contains(r.Body, "invalid credentials") {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
	tokens := b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	access := claims(t, tokens["access_token"].(string))
	if access["organization_id"] != e.Org || access["sub"] != e.Alice || access["application_id"] != e.Client {
		t.Fatalf("access claims = %v", access)
	}
	if !equal(e.permissions(tokens["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatal("hosted token lacks permissions")
	}
	// The ticket is spent.
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status != 401 {
		t.Fatalf("reused ticket: %d", p.Status)
	}

	// Several organizations: choose one; no session exists before.
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(other, e.Alice)
	e.Grant(other, e.Alice, e.Res, "invoices:write")
	noAccess := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Gamma"})
	e.Join(noAccess, e.Alice)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	var before int
	e.DB.Get(&before, `SELECT count(*) FROM sessions WHERE user_id=$1`, e.Alice)
	choose := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	orgs := choose.fields("organization_id")
	if choose.Status != 200 || len(orgs) != 2 || !contains(orgs, e.Org) || !contains(orgs, other) || strings.Contains(choose.Body, "Gamma") {
		t.Fatalf("choose page: %d %v %s", choose.Status, orgs, choose.Body)
	}
	var after int
	e.DB.Get(&after, `SELECT count(*) FROM sessions WHERE user_id=$1`, e.Alice)
	if after != before {
		t.Fatal("session issued before choosing the organization")
	}
	if p := b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {noAccess}}); p.Status != 403 {
		t.Fatalf("organization without access: %d %s", p.Status, p.Body)
	}
	tokens = b.exchange(client, b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {other}}))
	if claims(t, tokens["access_token"].(string))["organization_id"] != other {
		t.Fatal("wrong organization")
	}
	// Choosing needs a verified login bound to this ticket.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	if p := b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {e.Org}}); p.Status != 401 {
		t.Fatalf("choose without login: %d", p.Status)
	}

	// Email code.
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	sent := b.post("/hosted/login/code", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	mail, ok := e.Mail.Last("login")
	if sent.Status != 200 || !ok || sent.field("challenge_id") == "" {
		t.Fatalf("code: %d %v %s", sent.Status, ok, sent.Body)
	}
	if p := b.post("/hosted/login/code/verify", url.Values{"ticket": {tk}, "challenge_id": {sent.field("challenge_id")}, "code": {"00000000"}}); p.Status != 401 {
		t.Fatalf("wrong code: %d", p.Status)
	}
	choose = b.post("/hosted/login/code/verify", url.Values{"ticket": {tk}, "challenge_id": {sent.field("challenge_id")}, "code": {mail.Code}})
	if len(choose.fields("organization_id")) != 2 {
		t.Fatalf("code login: %d %s", choose.Status, choose.Body)
	}
	b.exchange(client, b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {e.Org}}))

	// Password reset, then sign in with the new password.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	reset := b.post("/hosted/login/reset", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	mail, _ = e.Mail.Last("password_reset")
	done := b.post("/hosted/login/reset/verify", url.Values{"ticket": {tk}, "challenge_id": {reset.field("challenge_id")}, "email": {e.AliceEmail}, "code": {mail.Code}, "password": {"a brand new password"}})
	if done.Status != 200 || !strings.Contains(done.Body, "password was changed") {
		t.Fatalf("reset: %d %s", done.Status, done.Body)
	}
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"a brand new password"}}); p.Status != 200 || len(p.fields("organization_id")) != 2 {
		t.Fatalf("new password: %d %s", p.Status, p.Body)
	}

	// Branding: validated, rendered, audited.
	settings := e.Base + "/login-settings"
	e.Must("PUT", settings, e.Owner, fiber.Map{"logo_url": "http://insecure.example/logo.png"}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"accent_color": "red"}, 400)
	saved := e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme <Billing>", "logo_url": "https://cdn.example/logo.png", "accent_color": "#FF6600"}, 200).JSON
	if saved["accent_color"] != "#ff6600" {
		t.Fatalf("settings = %v", saved)
	}
	branded := e.browser().authorize(client)
	if !strings.Contains(branded.Body, "Acme &lt;Billing&gt;") || !strings.Contains(branded.Body, `src="https://cdn.example/logo.png"`) || !strings.Contains(branded.Body, "--accent:#ff6600") {
		t.Fatalf("branding not rendered: %s", branded.Body)
	}
	if e.Must("GET", settings, e.Owner, nil, 200).JSON["display_name"] != "Acme <Billing>" {
		t.Fatal("settings not stored")
	}

	// Organization SSO: optional offers both, enforced redirects; the
	// callback resumes the hosted login in the SSO organization only.
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	optional := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if optional.field("connection_id") != conn || !strings.Contains(optional.Body, `name="password"`) {
		t.Fatalf("optional SSO: %s", optional.Body)
	}
	e.Must("PATCH", e.Base+"/federation-connections/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	// Enforced: the password step refuses before comparing.
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"a brand new password"}}); p.Status != 403 || !strings.Contains(p.Body, "single sign-on") {
		t.Fatalf("password under enforcement: %d %s", p.Status, p.Body)
	}
	redirect := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	if redirect.Status != 303 || !strings.HasPrefix(redirect.Location, idp.URL+"/authorize") {
		t.Fatalf("enforced identify: %d %q", redirect.Status, redirect.Location)
	}
	e.Must("POST", e.Base+"/external-identities", e.Owner, fiber.Map{"connection_id": conn, "user_id": e.Alice, "subject": "alice-sub"}, 204)
	callback := b.federate(idp, redirect.Location, map[string]any{"sub": "alice-sub"})
	tokens = b.exchange(client, callback)
	if claims(t, tokens["access_token"].(string))["organization_id"] != e.Org {
		t.Fatal("SSO must sign in to its organization")
	}
	// A federation callback without the authorization cookie cannot resume.
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	redirect = b.post("/hosted/login/sso", url.Values{"ticket": {tk}, "connection_id": {conn}})
	delete(b.cookies, "__Host-iamkit-authorization")
	if p := b.federate(idp, redirect.Location, map[string]any{"sub": "alice-sub"}); p.Status != 401 {
		t.Fatalf("callback without binding: %d %s", p.Status, p.Body)
	}
	e.Must("PATCH", e.Base+"/federation-connections/"+conn, e.Owner, fiber.Map{"enforcement": "optional"}, 204)

	// Invitation accept page.
	inv := e.Must("POST", e.Base+"/organizations/"+other+"/invitations", e.Owner, fiber.Map{"email": "newbie@elsewhere.example"}, 201).JSON
	token := inv["token"].(string)
	ib := e.browser()
	if p := ib.get("/hosted/invite?token=ik_inv_unknown"); p.Status != 400 {
		t.Fatalf("unknown invite: %d", p.Status)
	}
	accept := ib.get("/hosted/invite?token=" + url.QueryEscape(token))
	if accept.Status != 200 || !strings.Contains(accept.Body, "Join Beta") || !strings.Contains(accept.Body, `name="password"`) || !strings.Contains(accept.Body, "--accent:#ff6600") {
		t.Fatalf("invite page: %d %s", accept.Status, accept.Body)
	}
	if p := ib.post("/hosted/invite", url.Values{"token": {token}, "name": {"Newbie"}, "password": {"short"}}); p.Status != 400 {
		t.Fatalf("short password: %d", p.Status)
	}
	if p := ib.post("/hosted/invite", url.Values{"token": {token}, "name": {"Newbie"}, "password": {"newbie password 123"}}); p.Status != 200 || !strings.Contains(p.Body, "You joined Beta") {
		t.Fatalf("accept: %d %s", p.Status, p.Body)
	}
	if p := ib.post("/hosted/invite", url.Values{"token": {token}, "name": {"Newbie"}, "password": {"newbie password 123"}}); p.Status != 400 {
		t.Fatalf("second accept: %d", p.Status)
	}

	// The SPA does not swallow hosted paths.
	if p := e.browser().get("/hosted/nope"); p.Status != 404 {
		t.Fatalf("unknown hosted path: %d", p.Status)
	}
}

// federate completes a provider round trip the hosted pages started.
func (b *browser) federate(p *fakeIdP, authorizeURL string, claims map[string]any) page {
	b.t.Helper()
	authorization, err := url.Parse(authorizeURL)
	if err != nil {
		b.t.Fatal(err)
	}
	p.mu.Lock()
	p.nonce, p.claims = authorization.Query().Get("nonce"), claims
	p.mu.Unlock()
	return b.get("/identity/v1/federation/callback?code=provider-code&state=" + url.QueryEscape(authorization.Query().Get("state")))
}
