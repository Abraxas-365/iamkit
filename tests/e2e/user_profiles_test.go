package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// TestUserMetadataAndProfiles covers per-key metadata on users and
// organizations (limits, audit, /api/v1), the user schema (save, version,
// non-conforming count, remote $ref refused), operator and self-service
// profile writes checked against it, and the x-iamkit-claim release in ID
// tokens and UserInfo.
func TestUserMetadataAndProfiles(t *testing.T) {
	e := newEnv(t)
	user := e.Base + "/users/" + e.Alice

	// Per-key metadata.
	e.Must("PUT", user+"/metadata/plan.tier", e.Owner, json.RawMessage(`{"name":"gold"}`), 204)
	e.Must("PUT", user+"/metadata/seats", e.Owner, json.RawMessage(`12`), 204)
	if got := e.Must("GET", user+"/metadata/plan.tier", e.Owner, nil, 200).JSON["name"]; got != "gold" {
		t.Fatalf("metadata value = %v", got)
	}
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["metadata"].(map[string]any)["seats"]; got != float64(12) {
		t.Fatalf("whole metadata = %v", got)
	}
	e.Must("PUT", user+"/metadata/bad%20key", e.Owner, json.RawMessage(`1`), 400)
	e.Must("PUT", user+"/metadata/big", e.Owner, json.RawMessage(`"`+strings.Repeat("x", 5000)+`"`), 400)
	e.Must("DELETE", user+"/metadata/seats", e.Owner, nil, 204)
	e.Must("DELETE", user+"/metadata/seats", e.Owner, nil, 404)
	e.Must("GET", user+"/metadata/seats", e.Owner, nil, 404)
	if e.audited("user.metadata_set", e.Alice) != 2 || e.audited("user.metadata_deleted", e.Alice) != 1 {
		t.Fatal("metadata changes not audited")
	}
	// PATCH keeps whole-object semantics, now with the limits.
	e.Must("PATCH", user, e.Owner, fiber.Map{"metadata": fiber.Map{"a b": 1}}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"metadata": fiber.Map{"only": true}}, 204)
	e.Must("GET", user+"/metadata/plan.tier", e.Owner, nil, 404)

	org := e.Base + "/organizations/" + e.Org
	e.Must("PUT", org+"/metadata/region", e.Owner, json.RawMessage(`"eu"`), 204)
	if got := e.Must("GET", org, e.Owner, nil, 200).JSON["metadata"].(map[string]any)["region"]; got != "eu" {
		t.Fatalf("organization metadata = %v", got)
	}
	e.Must("DELETE", org+"/metadata/region", e.Owner, nil, 204)
	e.Must("DELETE", org+"/metadata/region", e.Owner, nil, 404)

	api := "/api/v1/environments/" + e.EnvID
	e.Must("PUT", api+"/users/"+e.Alice+"/metadata/k", e.scopedToken("iam:users:read"), json.RawMessage(`1`), 403)
	e.Must("PUT", api+"/users/"+e.Alice+"/metadata/k", e.scopedToken("iam:users:write"), json.RawMessage(`1`), 204)
	e.Must("GET", api+"/users/"+e.Alice+"/metadata/k", e.scopedToken("iam:users:read"), nil, 200)
	e.Must("PUT", api+"/organizations/"+e.Org+"/metadata/k", e.scopedToken("iam:orgs:write"), json.RawMessage(`1`), 204)

	// Profiles: free-form until a schema is saved.
	e.Must("PATCH", user+"/profile", e.Owner, fiber.Map{"legacy": 1}, 200)
	e.Must("GET", e.Base+"/user-schema", e.Owner, nil, 404)
	schema := fiber.Map{"type": "object", "additionalProperties": false, "properties": fiber.Map{
		"department":  fiber.Map{"type": "string", "enum": []string{"sales", "eng"}, "x-iamkit-self": "read", "x-iamkit-claim": "department"},
		"nickname":    fiber.Map{"type": "string", "maxLength": 20, "x-iamkit-self": "write"},
		"cost_center": fiber.Map{"type": "string"},
	}}
	e.Must("PUT", e.Base+"/user-schema", e.Owner, fiber.Map{"schema": fiber.Map{"type": "object", "properties": fiber.Map{"a": fiber.Map{"$ref": "https://example.com/s.json"}}}}, 400)
	e.Must("PUT", e.Base+"/user-schema", e.Owner, fiber.Map{"schema": fiber.Map{"type": "object", "properties": fiber.Map{"a": fiber.Map{"x-iamkit-claim": "sub"}}}}, 400)
	saved := e.Must("PUT", e.Base+"/user-schema", e.Owner, fiber.Map{"schema": schema}, 200).JSON
	if saved["version"] != float64(1) || saved["non_conforming"] != float64(1) {
		t.Fatalf("saved schema = %v", saved)
	}
	if got := e.Must("PUT", e.Base+"/user-schema", e.Owner, fiber.Map{"schema": schema}, 200).JSON["version"]; got != float64(2) {
		t.Fatalf("schema version = %v", got)
	}
	e.Must("GET", api+"/user-schema", e.scopedToken("iam:users:read"), nil, 200)
	e.Must("PUT", api+"/user-schema", e.scopedToken("iam:users:read"), fiber.Map{"schema": schema}, 403)

	// The non-conforming profile must conform on its next write.
	e.Must("PATCH", user+"/profile", e.Owner, fiber.Map{"department": "eng"}, 400)
	res := e.Must("PATCH", user+"/profile", e.Owner, fiber.Map{"legacy": nil, "department": "hr"}, 400)
	if !strings.Contains(res.Body, "department") {
		t.Fatalf("schema error does not name the attribute: %s", res.Body)
	}
	profile := e.Must("PATCH", user+"/profile", e.Owner, fiber.Map{"legacy": nil, "department": "eng", "cost_center": "cc-7"}, 200).JSON["profile"].(map[string]any)
	if profile["department"] != "eng" || profile["legacy"] != nil {
		t.Fatalf("profile = %v", profile)
	}
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["profile"].(map[string]any)["cost_center"]; got != "cc-7" {
		t.Fatalf("user profile = %v", got)
	}
	if e.audited("user.profile_updated", e.Alice) != 2 || e.audited("user.schema_updated", e.EnvID) != 2 {
		t.Fatal("profile/schema changes not audited")
	}

	// Self-service: sees read+write properties, changes only write ones.
	token := e.Login(e.AliceEmail)
	self := "/identity/v1/me/profile?environment_id=" + e.EnvID + "&audience=" + e.Audience
	own := e.Must("GET", self, token, nil, 200).JSON["profile"].(map[string]any)
	if own["department"] != "eng" || own["cost_center"] != nil {
		t.Fatalf("own profile = %v", own)
	}
	body := func(p fiber.Map) fiber.Map {
		return fiber.Map{"environment_id": e.EnvID, "audience": e.Audience, "profile": p}
	}
	e.Must("PATCH", "/identity/v1/me/profile", token, body(fiber.Map{"department": "sales"}), 403)
	e.Must("PATCH", "/identity/v1/me/profile", token, body(fiber.Map{"nickname": strings.Repeat("n", 30)}), 400)
	own = e.Must("PATCH", "/identity/v1/me/profile", token, body(fiber.Map{"nickname": "Al"}), 200).JSON["profile"].(map[string]any)
	if own["nickname"] != "Al" || own["department"] != "eng" {
		t.Fatalf("own profile after write = %v", own)
	}
	e.Must("GET", self, "", nil, 401)

	// x-iamkit-claim properties are released with the profile scope.
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	httpClient := &http.Client{Transport: appTransport{e.App}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	clientID, secret := registered["client_id"].(string), registered["client_secret"].(string)
	provider, err := oidc.NewProvider(ctx, "https://iam.example")
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(scopes ...string) (*oidc.IDToken, *oauth2.Token) {
		t.Helper()
		config := oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: "https://app.example/callback", Scopes: scopes}
		verifier := oauth2.GenerateVerifier()
		res, err := httpClient.Get(config.AuthCodeURL("unpredictable-state-123456", oauth2.S256ChallengeOption(verifier), oidc.Nonce("unpredictable-nonce-123456")))
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("authorize: %v %v", err, res)
		}
		var begin map[string]any
		json.NewDecoder(res.Body).Decode(&begin)
		res.Body.Close()
		raw, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
		req, _ := http.NewRequest("POST", "https://iam.example/oauth/authorize/complete", strings.NewReader(string(raw)))
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
		id, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, token.Extra("id_token").(string))
		if err != nil {
			t.Fatal(err)
		}
		return id, token
	}
	claims := func(id *oidc.IDToken) map[string]any {
		out := map[string]any{}
		_ = id.Claims(&out)
		return out
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": "https://cdn.example/alice.png", "username": "alice"}, 204)
	id, token2 := signIn(oidc.ScopeOpenID, "profile")
	if got := claims(id); got["department"] != "eng" || got["picture"] != "https://cdn.example/alice.png" || got["preferred_username"] != "alice" {
		t.Fatalf("ID token department/picture = %v", got)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token2))
	if err != nil {
		t.Fatal(err)
	}
	var fromInfo map[string]any
	_ = info.Claims(&fromInfo)
	if fromInfo["department"] != "eng" || fromInfo["cost_center"] != nil || fromInfo["sub"] != e.Alice || fromInfo["picture"] != "https://cdn.example/alice.png" || fromInfo["preferred_username"] != "alice" {
		t.Fatalf("userinfo = %v", fromInfo)
	}
	id, _ = signIn(oidc.ScopeOpenID)
	if got := claims(id); got["department"] != nil || got["picture"] != nil || got["preferred_username"] != nil {
		t.Fatal("profile claims released without the profile scope")
	}

	// Deleting the schema stops the checks.
	e.Must("DELETE", e.Base+"/user-schema", e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/user-schema", e.Owner, nil, 404)
	e.Must("PATCH", user+"/profile", e.Owner, fiber.Map{"anything": []int{1}}, 200)
	e.Must("GET", self, token, nil, 200)
}

// TestUserAvatars covers the avatar URL: operator create/update/clear with
// https-only validation, /api/v1, self-service through /identity/v1/me, and
// its place in user lists.
func TestUserAvatars(t *testing.T) {
	e := newEnv(t)
	user := e.Base + "/users/" + e.Alice
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": "http://cdn.example/a.png"}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": "javascript:alert(1)"}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": "https://cdn.example/" + strings.Repeat("a", 2100)}, 400)
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": " https://cdn.example/a.png "}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["avatar_url"]; got != "https://cdn.example/a.png" {
		t.Fatalf("avatar_url = %v", got)
	}
	found := false
	for _, item := range e.Must("GET", e.Base+"/users", e.Owner, nil, 200).JSON["items"].([]any) {
		u := item.(map[string]any)
		found = found || u["id"] == e.Alice && u["avatar_url"] == "https://cdn.example/a.png"
	}
	if !found {
		t.Fatal("user list does not carry avatar_url")
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"name": "Alice"}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["avatar_url"]; got != "https://cdn.example/a.png" {
		t.Fatal("an update without avatar_url keeps it")
	}
	e.Must("PATCH", user, e.Owner, fiber.Map{"avatar_url": ""}, 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON["avatar_url"]; got != "" {
		t.Fatalf("cleared avatar_url = %v", got)
	}

	created := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "pic@example.com", "name": "Pic", "avatar_url": "https://cdn.example/pic.png"}, 201).JSON["id"].(string)
	if got := e.Must("GET", e.Base+"/users/"+created, e.Owner, nil, 200).JSON["avatar_url"]; got != "https://cdn.example/pic.png" {
		t.Fatalf("created avatar_url = %v", got)
	}
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "bad@example.com", "name": "Bad", "avatar_url": "ftp://x"}, 400)
	api := "/api/v1/environments/" + e.EnvID + "/users/" + e.Alice
	e.Must("PATCH", api, e.scopedToken("iam:users:write"), fiber.Map{"avatar_url": "https://cdn.example/api.png"}, 204)

	// Self-service.
	token := e.Login(e.AliceEmail)
	me := func(body fiber.Map) fiber.Map {
		body["environment_id"], body["audience"] = e.EnvID, e.Audience
		return body
	}
	e.Must("PATCH", "/identity/v1/me", token, me(fiber.Map{"avatar_url": "http://x.example/a.png"}), 400)
	e.Must("PATCH", "/identity/v1/me", token, me(fiber.Map{}), 400)
	e.Must("PATCH", "/identity/v1/me", token, me(fiber.Map{"avatar_url": "https://cdn.example/self.png"}), 204)
	profile := e.Must("GET", "/identity/v1/me?environment_id="+e.EnvID+"&audience="+e.Audience, token, nil, 200).JSON
	if profile["avatar_url"] != "https://cdn.example/self.png" || profile["name"] != "Alice" {
		t.Fatalf("own profile = %v", profile)
	}
	e.Must("PATCH", "/identity/v1/me", token, me(fiber.Map{"name": "Alice Two"}), 204)
	if got := e.Must("GET", user, e.Owner, nil, 200).JSON; got["avatar_url"] != "https://cdn.example/self.png" || got["name"] != "Alice Two" {
		t.Fatalf("a name-only update keeps the avatar: %v", got)
	}
}
