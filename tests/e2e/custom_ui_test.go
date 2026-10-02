package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestCustomSignInUI covers a client without hosted login whose sign-in UI
// is served from another origin: its allowed origins open CORS on the
// browser-facing routes only, the ticket describes the sign-in like hosted
// pages render it, and the UI completes the authorization with the user
// token.
func TestCustomSignInUI(t *testing.T) {
	e := newEnv(t)
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	const origin = "https://login.example.com"

	// Origins are validated and normalized.
	if r := e.Do("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{"https://login.example.com/path"}}); r.Status != 400 {
		t.Fatalf("origin with a path: %d %s", r.Status, r.Body)
	}
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{"https://Login.Example.com:443"}}, 201).JSON["client_id"].(string)
	view := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON
	if !equal(strs(view["allowed_origins"]), []string{origin}) {
		t.Fatalf("allowed_origins = %v", view["allowed_origins"])
	}

	// CORS: the client's origin on /identity/v1 and /oauth, nowhere else;
	// unknown origins never.
	preflight := func(path, from string) string {
		req := httptest.NewRequest("OPTIONS", path, nil)
		req.Header.Set("Origin", from)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.Header.Get("Access-Control-Allow-Origin")
	}
	for path, want := range map[string]string{"/identity/v1/login": origin, "/oauth/authorize/complete": origin, "/management/v1/projects": "", "/api/v1/users": ""} {
		if got := preflight(path, origin); got != want {
			t.Fatalf("preflight %s = %q, want %q", path, got, want)
		}
	}
	if got := preflight("/identity/v1/login", "https://evil.example"); got != "" {
		t.Fatalf("unknown origin allowed: %q", got)
	}

	// Authorize: the custom UI receives the ticket (and the browser the
	// binding cookie), then reads what to render.
	b := e.browser()
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "login_hint": {e.AliceEmail}, "ui_locales": {"es"}}
	start := b.get("/oauth/authorize?" + q.Encode())
	var begin map[string]any
	json.Unmarshal([]byte(start.Body), &begin)
	ticket, _ := begin["authorization_ticket"].(string)
	if start.Status != 200 || ticket == "" {
		t.Fatalf("authorize: %d %s", start.Status, start.Body)
	}
	if p := e.browser().get("/identity/v1/authorize/" + url.PathEscape(ticket)); p.Status != 401 {
		t.Fatalf("ticket without its binding: %d %s", p.Status, p.Body)
	}
	info := b.get("/identity/v1/authorize/" + url.PathEscape(ticket))
	var described map[string]any
	json.Unmarshal([]byte(info.Body), &described)
	if info.Status != 200 || info.Header.Get("Cache-Control") != "no-store" || described["client_id"] != client || described["environment_id"] != e.EnvID ||
		described["application_id"] != e.Client || described["resource_id"] != e.Res || described["audience"] != e.Audience ||
		described["login_hint"] != e.AliceEmail || described["locale"] != "es" || !equal(strs(described["scopes"]), []string{"openid", "offline_access"}) {
		t.Fatalf("authorization: %d %s", info.Status, info.Body)
	}
	methods, _ := described["methods"].(map[string]any)
	if methods["password"] != true || described["organization_id"] != nil {
		t.Fatalf("methods = %v", described)
	}
	// Hosted-login tickets are not for custom UIs.
	hosted := e.hostedClient()
	hb := e.browser()
	hostedTicket := hb.authorize(hosted).field("ticket")
	if p := hb.get("/identity/v1/authorize/" + url.PathEscape(hostedTicket)); p.Status != 403 {
		t.Fatalf("hosted ticket: %d %s", p.Status, p.Body)
	}

	// The UI signs in through the identity API and completes the
	// authorization with the user token (bearer, no session cookie); a
	// script asks for JSON and navigates to redirect_to.
	token := e.Login(e.AliceEmail)
	body, _ := json.Marshal(fiber.Map{"authorization_ticket": ticket, "approve": true})
	req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", origin)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	res, err := e.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var done map[string]string
	json.NewDecoder(res.Body).Decode(&done)
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Access-Control-Allow-Origin") != origin || res.Header.Get("Location") != "" || done["redirect_to"] == "" {
		t.Fatalf("complete: %d %v %v", res.StatusCode, res.Header, done)
	}
	tokens := b.exchange(client, page{Status: 303, Location: done["redirect_to"]})
	if claims(t, tokens["access_token"].(string))["sub"] != e.Alice {
		t.Fatal("wrong subject")
	}

	// Single sign-on from the custom UI: the callback returns to the UI
	// with a one-time result that only the start's verifier redeems.
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Acme", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	e.Must("POST", e.Base+"/external-identities", e.Owner, fiber.Map{"connection_id": conn, "user_id": e.Alice, "subject": "alice-sub"}, 204)
	verifier := strings.Repeat("f", 43)
	sum = sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	startSSO := func(returnTo, challenge string) Response {
		return e.Do("POST", "/identity/v1/federation/start", "", fiber.Map{"connection_id": conn, "environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "return_to": returnTo, "code_challenge": challenge})
	}
	for name, r := range map[string]Response{
		"origin not allowed": startSSO("https://evil.example/sso", challenge),
		"no challenge":       startSSO(origin+"/sso", ""),
		"plain http":         startSSO("http://login.example.com/sso", challenge),
	} {
		if r.Status != 400 {
			t.Fatalf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	// ssoBack starts with return_to in a fresh browser and completes the
	// provider round trip as the provider subject.
	ssoBack := func(subject, email string) (page, url.Values) {
		fb := e.browser()
		body, _ := json.Marshal(fiber.Map{"connection_id": conn, "environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "return_to": origin + "/sso?step=back", "code_challenge": challenge})
		req := httptest.NewRequest("POST", "/identity/v1/federation/start", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		res, err := e.App.Test(req, 10000)
		if err != nil {
			t.Fatal(err)
		}
		var started map[string]string
		json.NewDecoder(res.Body).Decode(&started)
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("start: %d %v", res.StatusCode, started)
		}
		for _, c := range res.Cookies() {
			fb.cookies[c.Name] = c
		}
		back := fb.federate(idp, started["authorization_url"], map[string]any{"sub": subject, "email": email, "email_verified": true})
		returned, _ := url.Parse(back.Location)
		return back, returned.Query()
	}
	back, returned := ssoBack("alice-sub", e.AliceEmail)
	result := returned.Get("federation_result")
	if back.Status != 303 || !strings.HasPrefix(back.Location, origin+"/sso?") || returned.Get("step") != "back" || !strings.HasPrefix(result, "ik_fedres_") {
		t.Fatalf("callback: %d %q", back.Status, back.Location)
	}
	// The wrong verifier spends the result.
	e.Must("POST", "/identity/v1/federation/result", "", fiber.Map{"federation_result": result, "code_verifier": strings.Repeat("g", 43)}, 401)
	e.Must("POST", "/identity/v1/federation/result", "", fiber.Map{"federation_result": result, "code_verifier": verifier}, 401)
	// The right one redeems once.
	_, returned = ssoBack("alice-sub", e.AliceEmail)
	result = returned.Get("federation_result")
	signed := e.Must("POST", "/identity/v1/federation/result", "", fiber.Map{"federation_result": result, "code_verifier": verifier}, 200).JSON
	if access, _ := signed["access_token"].(string); access == "" || claims(t, access)["sub"] != e.Alice {
		t.Fatalf("redeem: %v", signed)
	}
	e.Must("POST", "/identity/v1/federation/result", "", fiber.Map{"federation_result": result, "code_verifier": verifier}, 401)
	// A failed callback returns the error to the UI.
	back, returned = ssoBack("stranger-sub", "stranger@elsewhere.example")
	if back.Status != 303 || returned.Get("error") == "" || returned.Get("federation_result") != "" {
		t.Fatalf("failed callback: %d %q", back.Status, back.Location)
	}

	// Removing the origin closes CORS (after the cache interval; a new
	// server instance sees it at once).
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"allowed_origins": []string{}}, 204)
	if v := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON; len(strs(v["allowed_origins"])) != 0 {
		t.Fatalf("allowed_origins after clearing = %v", v["allowed_origins"])
	}
}
