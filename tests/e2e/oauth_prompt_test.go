package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// authorizeQuery is a valid authorize request for client plus extra.
func authorizeQuery(client string, extra url.Values) string {
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	for k, v := range extra {
		q[k] = v
	}
	return "/oauth/authorize?" + q.Encode()
}

// TestAuthorizePromptAndMaxAge covers OIDC prompt and max_age at
// /oauth/authorize for hosted-login and custom-UI clients.
func TestAuthorizePromptAndMaxAge(t *testing.T) {
	e := newEnv(t)
	hosted := e.hostedClient()
	custom := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true}, 201).JSON["client_id"].(string)

	// Discovery advertises the values.
	disc := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).JSON
	if got := strs(disc["prompt_values_supported"]); !equal(got, []string{"none", "login", "consent", "select_account"}) {
		t.Fatalf("prompt_values_supported = %v", got)
	}

	// Malformed values are invalid_request, before any ticket exists.
	for name, extra := range map[string]url.Values{
		"none with login": {"prompt": {"none login"}},
		"unknown prompt":  {"prompt": {"register"}},
		"max_age text":    {"max_age": {"abc"}},
		"max_age minus":   {"max_age": {"-1"}},
	} {
		for _, client := range []string{hosted, custom} {
			b := e.browser()
			p := b.get(authorizeQuery(client, extra))
			if p.Status != 400 || !strings.Contains(p.Body, "INVALID_REQUEST") || len(b.cookies) != 0 {
				t.Fatalf("%s: %d %s", name, p.Status, p.Body)
			}
		}
	}

	// prompt=none: no session is ever reused, so the client is sent back
	// with login_required and its state, and no ticket is created.
	for _, client := range []string{hosted, custom} {
		b := e.browser()
		p := b.get(authorizeQuery(client, url.Values{"prompt": {"none"}}))
		loc, err := url.Parse(p.Location)
		if p.Status != 303 || err != nil || loc.Scheme+"://"+loc.Host+loc.Path != "https://app.example/callback" ||
			loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "unpredictable-state-123456" || loc.Query().Get("code") != "" {
			t.Fatalf("prompt=none: %d %q %s", p.Status, p.Location, p.Body)
		}
		if _, ok := b.cookies["__Host-iamkit-authorization"]; ok {
			t.Fatal("prompt=none must not bind a ticket")
		}
	}
	// A custom UI fetching the authorization cannot read the redirect.
	req := httptest.NewRequest("GET", authorizeQuery(custom, url.Values{"prompt": {"none"}}), nil)
	req.Header.Set("Accept", "application/json")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var done map[string]string
	json.NewDecoder(res.Body).Decode(&done)
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Location") != "" || !strings.Contains(done["redirect_to"], "error=login_required") {
		t.Fatalf("prompt=none as JSON: %d %v", res.StatusCode, done)
	}

	// prompt=login, max_age and consent on the hosted pages: a normal
	// sign-in, and the ID token says when it happened.
	for name, extra := range map[string]url.Values{
		"login":           {"prompt": {"login"}},
		"consent":         {"prompt": {"consent"}},
		"login consent":   {"prompt": {"login consent"}},
		"max_age":         {"max_age": {"300"}},
		"max_age zero":    {"max_age": {"0"}},
		"select_account":  {"prompt": {"select_account"}, "organization_id": {e.Org}},
		"login and age 0": {"prompt": {"login"}, "max_age": {"0"}},
	} {
		b := e.browser()
		start := b.get(authorizeQuery(hosted, extra))
		if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=") {
			t.Fatalf("%s: authorize %d %q %s", name, start.Status, start.Location, start.Body)
		}
		tk := b.get(start.Location).field("ticket")
		tokens := b.exchange(hosted, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
		if _, ok := claims(t, tokens["id_token"].(string))["auth_time"].(float64); !ok {
			t.Fatalf("%s: ID token without auth_time: %v", name, claims(t, tokens["id_token"].(string)))
		}
	}

	// prompt=select_account shows the chooser even with a single organization.
	b := e.browser()
	start := b.get(authorizeQuery(hosted, url.Values{"prompt": {"select_account"}}))
	tk := b.get(start.Location).field("ticket")
	chooser := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if chooser.Status != 200 || len(chooser.fields("organization_id")) != 1 {
		t.Fatalf("select_account chooser: %d %s", chooser.Status, chooser.Body)
	}
	b.exchange(hosted, b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {e.Org}}))

	// Custom UI: a sign-in that predates the request does not satisfy
	// prompt=login or max_age=0; one made for it does.
	complete := func(b *browser, ticket, token string) page {
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": ticket, "approve": true})
		req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		for _, c := range b.cookies {
			req.AddCookie(c)
		}
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return page{Status: res.StatusCode, Location: res.Header.Get("Location")}
	}
	older := e.Login(e.AliceEmail)
	time.Sleep(1100 * time.Millisecond) // auth_time has whole-second precision
	for _, extra := range []url.Values{{"prompt": {"login"}}, {"max_age": {"0"}}} {
		b := e.browser()
		var begin map[string]any
		json.Unmarshal([]byte(b.get(authorizeQuery(custom, extra)).Body), &begin)
		stale := complete(b, begin["authorization_ticket"].(string), older)
		if loc, _ := url.Parse(stale.Location); stale.Status != 303 || loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
			t.Fatalf("stale sign-in with %v: %d %q", extra, stale.Status, stale.Location)
		}
		b = e.browser()
		json.Unmarshal([]byte(b.get(authorizeQuery(custom, extra)).Body), &begin)
		fresh := complete(b, begin["authorization_ticket"].(string), e.Login(e.AliceEmail))
		tokens := b.exchange(custom, fresh)
		if _, ok := claims(t, tokens["id_token"].(string))["auth_time"].(float64); !ok {
			t.Fatalf("custom UI %v: ID token without auth_time", extra)
		}
	}
	// Without prompt an older sign-in is fine.
	b = e.browser()
	var begin map[string]any
	json.Unmarshal([]byte(b.get(authorizeQuery(custom, nil)).Body), &begin)
	b.exchange(custom, complete(b, begin["authorization_ticket"].(string), older))
}

// TestAuthorizePromptUpstream covers prompt and max_age through an upstream
// OpenID provider: the request reaches it, and the ID token's auth_time is
// checked when the user comes back.
func TestAuthorizePromptUpstream(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "prompt-client")
	e.IdP.Set(idp.Client().Transport)
	hosted := e.hostedClient()
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"name": "Upstream", "issuer": idp.URL, "client_id": "prompt-client", "client_secret": "sealed-secret", "link_email": true})
	identity := func(authTime any) map[string]any {
		c := map[string]any{"sub": "alice-upstream", "email": e.AliceEmail, "email_verified": true}
		if authTime != nil {
			c["auth_time"] = authTime
		}
		return c
	}
	// start opens the hosted sign-in for extra and follows the connection's
	// button to the provider.
	start := func(extra url.Values) (*browser, *url.URL) {
		b := e.browser()
		first := b.get(authorizeQuery(hosted, extra))
		if first.Status != 303 {
			t.Fatalf("authorize %v: %d %s", extra, first.Status, first.Body)
		}
		tk := b.get(first.Location).field("ticket")
		redirect := b.post("/hosted/login/sso", url.Values{"ticket": {tk}, "connection_id": {conn}})
		if redirect.Status != 303 || !strings.HasPrefix(redirect.Location, idp.URL+"/authorize") {
			t.Fatalf("upstream start %v: %d %q %s", extra, redirect.Status, redirect.Location, redirect.Body)
		}
		u, _ := url.Parse(redirect.Location)
		return b, u
	}
	now := time.Now()

	// The request reaches the provider: prompt=login and max_age.
	_, u := start(url.Values{"prompt": {"login"}, "max_age": {"300"}})
	if u.Query().Get("prompt") != "login" || u.Query().Get("max_age") != "300" {
		t.Fatalf("upstream query = %v", u.Query())
	}
	_, u = start(nil)
	if u.Query().Has("prompt") || u.Query().Has("max_age") {
		t.Fatalf("plain sign-in asked the provider for %v", u.Query())
	}

	// prompt=login: a sign-in that predates the request is refused; one made
	// since, or without auth_time (the provider does not say), is accepted.
	b, u := start(url.Values{"prompt": {"login"}})
	if r := b.federate(idp, u.String(), identity(now.Add(-time.Hour).Unix())); r.Status != 401 || !strings.Contains(r.Body, "reused an earlier sign-in") || strings.Contains(r.Location, "code=") {
		t.Fatalf("stale auth_time: %d %q %s", r.Status, r.Location, r.Body)
	}
	b, u = start(url.Values{"prompt": {"login"}})
	b.exchange(hosted, b.federate(idp, u.String(), identity(time.Now().Unix())))
	b, u = start(url.Values{"prompt": {"login"}})
	b.exchange(hosted, b.federate(idp, u.String(), identity(nil)))

	// max_age: older than allowed is refused, within it is accepted.
	b, u = start(url.Values{"max_age": {"60"}})
	if r := b.federate(idp, u.String(), identity(now.Add(-time.Hour).Unix())); r.Status != 401 || !strings.Contains(r.Body, "reused an earlier sign-in") {
		t.Fatalf("auth_time past max_age: %d %s", r.Status, r.Body)
	}
	b, u = start(url.Values{"max_age": {"3600"}})
	b.exchange(hosted, b.federate(idp, u.String(), identity(now.Add(-10*time.Minute).Unix())))

	// Without prompt or max_age an old sign-in at the provider is fine.
	b, u = start(nil)
	b.exchange(hosted, b.federate(idp, u.String(), identity(now.Add(-24*time.Hour).Unix())))
}
