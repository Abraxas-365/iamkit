package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// kidOf reads the kid header of a JWT.
func kidOf(t *testing.T, raw string) string {
	t.Helper()
	header, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Kid string `json:"kid"`
	}
	json.Unmarshal(header, &out)
	return out.Kid
}

// jwksKids lists the kids /.well-known/jwks.json publishes.
func (e *Env) jwksKids() map[string]bool {
	e.t.Helper()
	res := e.Must("GET", "/.well-known/jwks.json", "", nil, 200)
	out := map[string]bool{}
	for _, k := range res.JSON["keys"].([]any) {
		out[k.(map[string]any)["kid"].(string)] = true
	}
	return out
}

// TestSigningKeyRotation rotates an environment's signing key: the new key
// is published before it signs, tokens signed by the old key keep
// validating until it is retired, and other environments keep the
// deployment key.
func TestSigningKeyRotation(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	me := "/identity/v1/me?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
	keys := e.Base + "/signing-keys"

	before := e.Login(e.AliceEmail)
	deployment := kidOf(t, before)
	if !e.jwksKids()[deployment] || len(e.jwksKids()) != 1 {
		t.Fatalf("jwks = %v", e.jwksKids())
	}
	if list := e.Must("GET", keys, e.Owner, nil, 200).JSON; list["page"].(map[string]any)["total"].(float64) != 0 {
		t.Fatalf("keys = %v", list)
	}

	// A next key is published but does not sign.
	first := e.Must("POST", keys, e.Owner, nil, 201).JSON
	kid := first["kid"].(string)
	if first["state"] != "next" || first["public_jwk"].(map[string]any)["kid"] != kid {
		t.Fatalf("created = %v", first)
	}
	if !e.jwksKids()[kid] || !e.jwksKids()[deployment] {
		t.Fatal("next key not published")
	}
	if got := kidOf(t, e.Login(e.AliceEmail)); got != deployment {
		t.Fatalf("next key signed: %s", got)
	}
	if e.audited("signing_key.create", kid) != 1 {
		t.Fatal("create not audited")
	}

	// Activating it: new tokens carry its kid; old ones still validate.
	if got := e.Must("POST", keys+"/"+kid+"/activate", e.Owner, nil, 200).JSON; got["state"] != "active" {
		t.Fatalf("activated = %v", got)
	}
	after := e.Login(e.AliceEmail)
	if kidOf(t, after) != kid {
		t.Fatalf("active key did not sign: %s", kidOf(t, after))
	}
	e.Must("GET", me, before, nil, 200)
	e.Must("GET", me, after, nil, 200)
	if errorOf(e.Do("POST", keys+"/"+kid+"/retire", e.Owner, nil))["code"] != "KEY_IN_USE" {
		t.Fatal("retired the active key")
	}

	// Another environment keeps the deployment key, and never accepts the
	// environment's key.
	project := e.ID("POST", "/management/v1/projects", fiber.Map{"name": "Other"})
	other := e.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "staging"})
	e.Must("GET", "/management/v1/environments/"+other+"/signing-keys/"+kid, e.Owner, nil, 404)
	e.Must("POST", "/management/v1/environments/"+other+"/signing-keys/"+kid+"/activate", e.Owner, nil, 404)

	// OIDC: the relying party verifies ID tokens through the JWKS.
	httpClient := &http.Client{Transport: appTransport{e.App}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	provider, err := oidc.NewProvider(ctx, "https://iam.example")
	if err != nil {
		t.Fatal(err)
	}
	config := oauth2.Config{ClientID: registered["client_id"].(string), ClientSecret: registered["client_secret"].(string), Endpoint: provider.Endpoint(), RedirectURL: "https://app.example/callback", Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}}
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
	req.Header.Set("Authorization", "Bearer "+after)
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
	rawID, _ := token.Extra("id_token").(string)
	if kidOf(t, rawID) != kid || kidOf(t, token.AccessToken) != kid {
		t.Fatalf("OAuth tokens kid = %s / %s", kidOf(t, rawID), kidOf(t, token.AccessToken))
	}
	if _, err = provider.Verifier(&oidc.Config{ClientID: config.ClientID}).Verify(ctx, rawID); err != nil {
		t.Fatal(err)
	}
	e.Must("GET", "/oauth/userinfo", token.AccessToken, nil, 200)

	// Rotate again: the first key is retiring, still verifies, and cannot be
	// retired early without force.
	second := e.Must("POST", keys, e.Owner, nil, 201).JSON["kid"].(string)
	e.Must("POST", keys+"/"+second+"/activate", e.Owner, nil, 200)
	if got := e.Must("GET", keys+"/"+kid, e.Owner, nil, 200).JSON; got["state"] != "retiring" || got["retire_after"] == nil {
		t.Fatalf("replaced key = %v", got)
	}
	e.Must("GET", me, after, nil, 200)
	e.Must("GET", "/oauth/userinfo", token.AccessToken, nil, 200)
	if kidOf(t, e.Login(e.AliceEmail)) != second {
		t.Fatal("second key does not sign")
	}
	if res := e.Do("POST", keys+"/"+kid+"/retire", e.Owner, nil); res.Status != 409 || errorOf(res)["code"] != "KEY_IN_USE" {
		t.Fatalf("early retire: %d %s", res.Status, res.Body)
	}
	// Refreshing an OAuth token signed by the retiring key re-signs it with
	// the active one.
	refreshed, err := config.TokenSource(ctx, &oauth2.Token{RefreshToken: token.RefreshToken}).Token()
	if err != nil || kidOf(t, refreshed.AccessToken) != second {
		t.Fatalf("refresh: %v", err)
	}

	// Forced retirement (a compromise): tokens it signed stop validating.
	if got := e.Must("POST", keys+"/"+kid+"/retire", e.Owner, fiber.Map{"force": true}, 200).JSON; got["state"] != "retired" || got["public_jwk"] != nil {
		t.Fatalf("retired = %v", got)
	}
	if e.jwksKids()[kid] {
		t.Fatal("retired key still published")
	}
	e.Must("GET", me, after, nil, 401)
	e.Must("GET", "/oauth/userinfo", token.AccessToken, nil, 401)
	e.Must("GET", me, before, nil, 200) // deployment key: still valid
	e.Must("POST", keys+"/"+kid+"/activate", e.Owner, nil, 409)
	if e.audited("signing_key.activate", second) != 1 || e.audited("signing_key.retire", kid) != 1 {
		t.Fatal("rotation not audited")
	}
	list := e.Must("GET", keys, e.Owner, nil, 200).JSON["items"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["kid"] != second {
		t.Fatalf("list = %v", list)
	}

	// A token forged with another environment's valid kid is refused: an
	// environment key only verifies its own environment's tokens (covered
	// by the codec unit test); here, the key stays out of other environments.
	e.Must("GET", "/management/v1/environments/"+other+"/signing-keys", e.Owner, nil, 200)
}

// Without IAMKIT_ENCRYPTION_KEY, environment keys cannot be created; the
// deployment key keeps working.
func TestSigningKeysNeedEncryptionKey(t *testing.T) {
	e := newEnv(t, bootstrap.WithSealer(nil))
	res := e.Do("POST", e.Base+"/signing-keys", e.Owner, nil)
	if res.Status != 422 || errorOf(res)["code"] != "ENCRYPTION_KEY_REQUIRED" {
		t.Fatalf("create: %d %s", res.Status, res.Body)
	}
	e.Login(e.AliceEmail)
}
