package e2e_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// TestOpaqueAccessTokens: a client switched to access_token_format=opaque
// receives ory_at_ handles that /oauth/introspect and /oauth/userinfo
// resolve, while /identity/v1 and /api/v1 refuse them. JWTs issued before
// the switch keep working.
func TestOpaqueAccessTokens(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	httpClient := &http.Client{Transport: appTransport{e.App}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	clientID, secret := registered["client_id"].(string), registered["client_secret"].(string)
	if got := e.Must("GET", e.Base+"/oauth-clients/"+clientID, e.Owner, nil, 200).JSON["access_token_format"]; got != "jwt" {
		t.Fatalf("default access_token_format = %v", got)
	}
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "access_token_format": "reference"}, 400)
	e.Must("PATCH", e.Base+"/oauth-clients/"+clientID, e.Owner, fiber.Map{"access_token_format": "paseto"}, 400)

	provider, err := oidc.NewProvider(ctx, "https://iam.example")
	if err != nil {
		t.Fatal(err)
	}
	config := oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: "https://app.example/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess}}
	signIn := func() *oauth2.Token {
		t.Helper()
		verifier := oauth2.GenerateVerifier()
		res, err := httpClient.Get(config.AuthCodeURL("unpredictable-state-123456", oauth2.S256ChallengeOption(verifier), oidc.Nonce("unpredictable-nonce-123456")))
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
		if _, err = provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, raw); err != nil {
			t.Fatalf("ID token stays a verifiable JWT: %v", err)
		}
		return token
	}
	introspect := func(raw string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest("POST", "https://iam.example/oauth/introspect", strings.NewReader(url.Values{"token": {raw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, url.QueryEscape(secret))
		res, err := httpClient.Do(req)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("introspect: %v %v", err, res)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		var out map[string]any
		json.Unmarshal(data, &out)
		return out
	}

	before := signIn()
	if strings.Count(before.AccessToken, ".") != 2 {
		t.Fatalf("default token is not a JWT: %q", before.AccessToken)
	}

	e.Must("PATCH", e.Base+"/oauth-clients/"+clientID, e.Owner, fiber.Map{"access_token_format": "opaque"}, 204)
	if got := e.Must("GET", e.Base+"/oauth-clients/"+clientID, e.Owner, nil, 200).JSON["access_token_format"]; got != "opaque" {
		t.Fatalf("access_token_format = %v", got)
	}
	token := signIn()
	if !strings.HasPrefix(token.AccessToken, "ory_at_") || strings.Count(token.AccessToken, ".") != 1 {
		t.Fatalf("opaque token = %q", token.AccessToken)
	}

	// Introspection and UserInfo resolve it.
	got := introspect(token.AccessToken)
	perms, _ := got["permissions"].([]any)
	if got["active"] != true || got["sub"] != e.Alice || got["client_id"] != clientID || got["environment_id"] != e.EnvID || len(perms) != 1 || perms[0] != "invoices:read" {
		t.Fatalf("introspect opaque = %v", got)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != e.Alice || info.Email != e.AliceEmail {
		t.Fatalf("userinfo opaque = %+v %v", info, err)
	}
	// POST form variant.
	res := e.Do("POST", "/oauth/userinfo", "", nil)
	if res.Status != 401 {
		t.Fatalf("userinfo without token: %d", res.Status)
	}
	if res = e.Do("GET", "/oauth/userinfo", "ory_at_bogus.signature", nil); res.Status != 401 {
		t.Fatalf("userinfo forged opaque: %d %s", res.Status, res.Body)
	}

	// Resource APIs accept JWTs only.
	if res = e.Do("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), token.AccessToken, nil); res.Status != 401 {
		t.Fatalf("identity API accepted an opaque token: %d %s", res.Status, res.Body)
	}
	if res = e.Do("GET", "/api/v1/environments/"+e.EnvID+"/users", token.AccessToken, nil); res.Status != 401 {
		t.Fatalf("/api/v1 accepted an opaque token: %d %s", res.Status, res.Body)
	}

	// Tokens issued before the switch keep validating.
	if got = introspect(before.AccessToken); got["active"] != true {
		t.Fatalf("pre-switch JWT inactive: %v", got)
	}
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(before)); err != nil {
		t.Fatalf("pre-switch JWT userinfo: %v", err)
	}

	// Refresh keeps the opaque format.
	refreshed, err := config.TokenSource(ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
	if err != nil || !strings.HasPrefix(refreshed.AccessToken, "ory_at_") {
		t.Fatalf("refresh = %v %v", refreshed, err)
	}
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(refreshed)); err != nil {
		t.Fatalf("refreshed opaque userinfo: %v", err)
	}

	// Revocation deactivates the handle at once.
	req, _ := http.NewRequest("POST", "https://iam.example/oauth/revoke", strings.NewReader(url.Values{"token": {refreshed.AccessToken}, "token_type_hint": {"access_token"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, url.QueryEscape(secret))
	if revoked, err := httpClient.Do(req); err != nil || revoked.StatusCode != 200 {
		t.Fatalf("revoke: %v %v", err, revoked)
	}
	if got = introspect(refreshed.AccessToken); got["active"] != false {
		t.Fatalf("revoked opaque token active: %v", got)
	}
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(refreshed)); err == nil {
		t.Fatal("userinfo accepted a revoked opaque token")
	}

	// Ending the user's session deactivates opaque tokens too.
	third := signIn()
	e.DB.MustExec(`UPDATE sessions SET revoked_at=now() WHERE oauth_client_id=$1`, clientID)
	if got = introspect(third.AccessToken); got["active"] != false {
		t.Fatalf("opaque token active after session end: %v", got)
	}
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(third)); err == nil {
		t.Fatal("userinfo accepted an opaque token of an ended session")
	}
}
