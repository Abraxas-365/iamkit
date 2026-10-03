package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// appTransport sends a relying party library's requests to the in-memory
// app, as if it were served at the issuer.
type appTransport struct{ app *App }

func (a appTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.URL = &url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	req.Host = r.URL.Host
	return a.app.Test(req, 10000)
}

// TestStandardOIDCEndpoints drives userinfo, introspection and RP-initiated
// logout with real relying-party libraries (go-oidc, x/oauth2).
func TestStandardOIDCEndpoints(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	httpClient := &http.Client{Transport: appTransport{e.App}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "post_logout_redirect_uris": []string{"https://app.example/bye"}}, 201).JSON
	clientID, secret := registered["client_id"].(string), registered["client_secret"].(string)
	if got := e.Must("GET", e.Base+"/oauth-clients/"+clientID, e.Owner, nil, 200).JSON["post_logout_redirect_uris"].([]any); len(got) != 1 || got[0] != "https://app.example/bye" {
		t.Fatalf("post_logout_redirect_uris = %v", got)
	}
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "post_logout_redirect_uris": []string{"http://app.example/bye"}}, 400)
	public := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true}, 201).JSON["client_id"].(string)

	provider, err := oidc.NewProvider(ctx, "https://iam.example")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err = provider.Claims(&meta); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"userinfo_endpoint": "/oauth/userinfo", "introspection_endpoint": "/oauth/introspect", "end_session_endpoint": "/oauth/end_session", "revocation_endpoint": "/oauth/revoke"} {
		if meta[key] != "https://iam.example"+want {
			t.Fatalf("discovery %s = %v", key, meta[key])
		}
	}
	if claims, _ := meta["claims_supported"].([]any); len(claims) == 0 {
		t.Fatal("discovery lacks claims_supported")
	}
	config := oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: "https://app.example/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess}}

	// Sign in: authorize → headless completion with the user's token → code.
	signIn := func() (*oauth2.Token, *oidc.IDToken) {
		t.Helper()
		verifier := oauth2.GenerateVerifier()
		auth, err := url.Parse(config.AuthCodeURL("unpredictable-state-123456", oauth2.S256ChallengeOption(verifier), oidc.Nonce("unpredictable-nonce-123456")))
		if err != nil {
			t.Fatal(err)
		}
		res, err := httpClient.Get(auth.String())
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("authorize: %v %v", err, res)
		}
		var begin map[string]any
		json.NewDecoder(res.Body).Decode(&begin)
		res.Body.Close()
		body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
		req, _ := http.NewRequest("POST", "https://iam.example/oauth/authorize/complete", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+e.Login(e.AliceEmail))
		req.AddCookie(res.Cookies()[0])
		done, err := httpClient.Do(req)
		if err != nil || done.StatusCode != 303 {
			t.Fatalf("complete: %v %v", err, done)
		}
		location, _ := url.Parse(done.Header.Get("Location"))
		token, err := config.Exchange(ctx, location.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := token.Extra("id_token").(string)
		idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		return token, idToken
	}
	token, idToken := signIn()
	var idClaims struct {
		SID string `json:"sid"`
	}
	if err = idToken.Claims(&idClaims); err != nil || idClaims.SID == "" {
		t.Fatalf("ID token sid: %v %v", idClaims, err)
	}
	var bound string
	if err = e.DB.Get(&bound, `SELECT oauth_client_id FROM sessions WHERE id=$1`, idClaims.SID); err != nil || bound != clientID {
		t.Fatalf("session oauth_client_id = %q %v", bound, err)
	}

	// UserInfo: scope-driven claims for a live OAuth access token.
	info, err := provider.UserInfo(ctx, config.TokenSource(ctx, token))
	if err != nil {
		t.Fatal(err)
	}
	var extra struct {
		Name         string `json:"name"`
		Organization string `json:"organization_id"`
		Environment  string `json:"environment_id"`
	}
	info.Claims(&extra)
	if info.Subject != e.Alice || info.Email != e.AliceEmail || extra.Name != "Alice" || extra.Organization != e.Org || extra.Environment != e.EnvID {
		t.Fatalf("userinfo = %+v %+v", info, extra)
	}
	// Identity-API tokens are not OAuth access tokens.
	if res := e.Do("GET", "/oauth/userinfo", e.Login(e.AliceEmail), nil); res.Status != 401 {
		t.Fatalf("userinfo with identity token: %d %s", res.Status, res.Body)
	}
	if res := e.Do("GET", "/oauth/userinfo", "", nil); res.Status != 401 {
		t.Fatalf("userinfo without token: %d", res.Status)
	}

	// Introspection (RFC 7662): confidential clients only.
	introspect := func(id, secret, raw string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("POST", "https://iam.example/oauth/introspect", strings.NewReader(url.Values{"token": {raw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if id != "" {
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw2, _ := io.ReadAll(res.Body)
		var out map[string]any
		json.Unmarshal(raw2, &out)
		return res.StatusCode, out
	}
	status, got := introspect(clientID, secret, token.AccessToken)
	perms, _ := got["permissions"].([]any)
	if status != 200 || got["active"] != true || got["sub"] != e.Alice || got["client_id"] != clientID || got["environment_id"] != e.EnvID || got["organization_id"] != e.Org || got["sid"] != idClaims.SID || len(perms) != 1 || perms[0] != "invoices:read" || got["token_type"] != "Bearer" {
		t.Fatalf("introspect access = %d %v", status, got)
	}
	if status, got = introspect(clientID, secret, token.RefreshToken); status != 200 || got["active"] != true || got["token_use"] != "refresh_token" {
		t.Fatalf("introspect refresh = %d %v", status, got)
	}
	if status, got = introspect(clientID, secret, "not-a-token"); status != 200 || got["active"] != false {
		t.Fatalf("introspect junk = %d %v", status, got)
	}
	if status, _ = introspect(clientID, "wrong", token.AccessToken); status != 401 {
		t.Fatalf("introspect wrong secret = %d", status)
	}
	if status, _ = introspect(public, "", token.AccessToken); status != 401 {
		t.Fatalf("introspect public client = %d", status)
	}
	if status, _ = introspect("", "", token.AccessToken); status != 401 {
		t.Fatalf("introspect anonymous = %d", status)
	}

	// RP-initiated logout.
	endSession := func(q url.Values) *http.Response {
		t.Helper()
		res, err := httpClient.Get("https://iam.example/oauth/end_session?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := endSession(url.Values{"id_token_hint": {idToken2Raw(token)}, "post_logout_redirect_uri": {"https://evil.example/bye"}}); res.StatusCode != 400 {
		t.Fatalf("unregistered post-logout redirect: %d", res.StatusCode)
	}
	if res := endSession(url.Values{"id_token_hint": {"garbage"}}); res.StatusCode != 400 || res.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("bad hint: %d %v (an /oauth answer must never be framed)", res.StatusCode, res.Header)
	}
	if res := endSession(url.Values{"id_token_hint": {idToken2Raw(token)}, "client_id": {public}}); res.StatusCode != 400 {
		t.Fatalf("client not in hint audience: %d", res.StatusCode)
	}
	res := endSession(url.Values{"id_token_hint": {idToken2Raw(token)}, "post_logout_redirect_uri": {"https://app.example/bye"}, "state": {"s1"}})
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://app.example/bye?state=s1" {
		t.Fatalf("end_session: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if status, got = introspect(clientID, secret, token.AccessToken); got["active"] != false {
		t.Fatalf("access token active after logout: %d %v", status, got)
	}
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		t.Fatal("userinfo accepted after logout")
	}
	if _, err = config.TokenSource(ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token(); err == nil {
		t.Fatal("refresh accepted after logout")
	}
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE environment_id=$1 AND action='oauth.logout' AND target_id=$2`, e.EnvID, idClaims.SID)
	if audits != 1 {
		t.Fatalf("oauth.logout audits = %d", audits)
	}

	// An expired ID token is still a hint; a foreign signature is not.
	_, second := signIn()
	var secondClaims struct {
		SID string `json:"sid"`
	}
	second.Claims(&secondClaims)
	expired := func(key *rsa.PrivateKey) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "sub": e.Alice, "aud": []string{clientID}, "environment_id": e.EnvID, "sid": secondClaims.SID, "iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix()}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	foreign, _ := rsa.GenerateKey(rand.Reader, 2048)
	if res = endSession(url.Values{"id_token_hint": {expired(foreign)}}); res.StatusCode != 400 {
		t.Fatalf("foreign hint: %d", res.StatusCode)
	}
	res = endSession(url.Values{"id_token_hint": {expired(e.Key)}})
	if res.StatusCode != 200 {
		t.Fatalf("expired hint without redirect: %d", res.StatusCode)
	}
	var revoked bool
	e.DB.Get(&revoked, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1`, secondClaims.SID)
	if !revoked {
		t.Fatal("expired hint did not end the session")
	}
	// Logging out twice is harmless.
	if res = endSession(url.Values{"id_token_hint": {expired(e.Key)}}); res.StatusCode != 200 {
		t.Fatalf("repeat logout: %d", res.StatusCode)
	}
	// Post-logout URIs are editable.
	e.Must("PATCH", e.Base+"/oauth-clients/"+clientID, e.Owner, fiber.Map{"post_logout_redirect_uris": []string{}}, 204)
	if got := e.Must("GET", e.Base+"/oauth-clients/"+clientID, e.Owner, nil, 200).JSON["post_logout_redirect_uris"].([]any); len(got) != 0 {
		t.Fatalf("cleared post_logout_redirect_uris = %v", got)
	}
}

func idToken2Raw(token *oauth2.Token) string {
	raw, _ := token.Extra("id_token").(string)
	return raw
}
