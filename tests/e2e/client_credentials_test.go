package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// tokenRequest posts form to /oauth/token, with HTTP Basic when user is set.
func (e *Env) tokenRequest(form url.Values, user, password string) Response {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(password))
	}
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

func ecJWK(key *ecdsa.PrivateKey, kid string) map[string]any {
	pad := func(b []byte) string {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	return map[string]any{"kty": "EC", "kid": kid, "crv": "P-256", "x": pad(key.X.Bytes()), "y": pad(key.Y.Bytes())}
}

// assertion is an RFC 7523 client assertion for client.
func assertion(t *testing.T, method jwt.SigningMethod, key any, kid, client, audience, jti string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims{"iss": client, "sub": client, "aud": audience, "jti": jti, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	json.Unmarshal(payload, &out)
	return out
}

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// TestClientCredentials: service accounts get tokens at /oauth/token with
// their secret (Basic or form, as configured) or private_key_jwt (inline
// keys or jwks_uri); the token equals the machine token.
func TestClientCredentials(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	grant := url.Values{"grant_type": {"client_credentials"}}

	meta := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200).JSON
	if !strings.Contains(strings.Join(anyStrings(meta["grant_types_supported"]), ","), "client_credentials") || !contains(anyStrings(meta["token_endpoint_auth_methods_supported"]), "private_key_jwt") || !contains(anyStrings(meta["token_endpoint_auth_signing_alg_values_supported"]), "ES256") {
		t.Fatalf("discovery = %v", meta)
	}

	sa := e.Must("POST", e.Base+"/service-accounts", e.Owner, fiber.Map{"name": "worker", "application_id": e.Client, "resource_id": e.Res, "permissions": []string{"invoices:read"}}, 201).JSON
	id, secret := sa["id"].(string), sa["secret"].(string)
	if got := e.Must("GET", e.Base+"/service-accounts/"+id, e.Owner, nil, 200).JSON; got["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("account = %v", got)
	}

	// Secret over HTTP Basic: the same token as /identity/v1/machine-token.
	res := e.tokenRequest(grant, id, secret)
	if res.Status != 200 || res.JSON["token_type"] != "Bearer" || res.JSON["expires_in"] == nil {
		t.Fatalf("client_credentials = %d %s", res.Status, res.Body)
	}
	machine := e.Must("POST", "/identity/v1/machine-token", secret, nil, 200).JSON["access_token"].(string)
	got, want := claimsOf(t, res.JSON["access_token"].(string)), claimsOf(t, machine)
	for _, claim := range []string{"sub", "aud", "iss", "environment_id", "token_use"} {
		if !jsonEqual(got[claim], want[claim]) {
			t.Fatalf("claim %s = %v, machine token %v", claim, got[claim], want[claim])
		}
	}
	if !jsonEqual(got["permissions"], []any{"invoices:read"}) {
		t.Fatalf("permissions = %v", got["permissions"])
	}
	// Wrong secret, unknown account, secret in the body while Basic is
	// configured, missing grant for clients.
	for name, r := range map[string]Response{
		"wrong secret": e.tokenRequest(grant, id, "ik_svc_wrong"),
		"unknown":      e.tokenRequest(grant, uuid.NewString(), secret),
		"post":         e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, "", ""),
	} {
		if r.Status != 401 || r.JSON["error"] != "invalid_client" {
			t.Fatalf("%s = %d %s", name, r.Status, r.Body)
		}
	}

	// client_secret_post once configured (then Basic is refused).
	auth := e.Base + "/service-accounts/" + id + "/authentication"
	e.Must("PUT", auth, e.Owner, fiber.Map{"token_endpoint_auth_method": "client_secret_post"}, 200)
	if e.audited("service_account.authentication", id) != 1 {
		t.Fatal("authentication change not audited")
	}
	if r := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, "", ""); r.Status != 200 {
		t.Fatalf("post = %d %s", r.Status, r.Body)
	}
	if r := e.tokenRequest(grant, id, secret); r.Status != 401 {
		t.Fatalf("basic after post = %d", r.Status)
	}

	// Invalid configurations.
	for _, body := range []fiber.Map{
		{"token_endpoint_auth_method": "none"},
		{"token_endpoint_auth_method": "private_key_jwt"},
		{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://keys.example/jwks"},
		{"token_endpoint_auth_method": "private_key_jwt", "jwks": fiber.Map{"keys": []fiber.Map{{"kty": "oct", "k": "c2VjcmV0"}}}},
		{"token_endpoint_auth_method": "client_secret_basic", "jwks_uri": "https://keys.example/jwks"},
		{"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "HS256", "jwks_uri": "https://keys.example/jwks"},
	} {
		e.Must("PUT", auth, e.Owner, body, 400)
	}

	// private_key_jwt with inline keys: the secret stops working.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	e.Must("PUT", auth, e.Owner, fiber.Map{"token_endpoint_auth_method": "private_key_jwt", "jwks": fiber.Map{"keys": []any{rsaJWK(key, "k1")}}}, 200)
	withAssertion := func(signed string, clientID bool) Response {
		form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {signed}}
		if clientID {
			form.Set("client_id", id)
		}
		return e.tokenRequest(form, "", "")
	}
	signed := assertion(t, jwt.SigningMethodRS256, key, "k1", id, "https://iam.example/oauth/token", uuid.NewString())
	if r := withAssertion(signed, true); r.Status != 200 || claimsOf(t, r.JSON["access_token"].(string))["sub"] != want["sub"] {
		t.Fatalf("private_key_jwt = %d %s", r.Status, r.Body)
	}
	if r := withAssertion(signed, true); r.Status != 401 {
		t.Fatalf("replayed assertion = %d %s", r.Status, r.Body)
	}
	// The issuer is an accepted audience; client_id may come from sub.
	if r := withAssertion(assertion(t, jwt.SigningMethodRS256, key, "k1", id, "https://iam.example", uuid.NewString()), false); r.Status != 200 {
		t.Fatalf("issuer audience = %d %s", r.Status, r.Body)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, bad := range map[string]string{
		"other key":      assertion(t, jwt.SigningMethodRS256, other, "k1", id, "https://iam.example/oauth/token", uuid.NewString()),
		"wrong audience": assertion(t, jwt.SigningMethodRS256, key, "k1", id, "https://elsewhere.example/token", uuid.NewString()),
		"wrong alg":      assertion(t, jwt.SigningMethodPS256, key, "k1", id, "https://iam.example/oauth/token", uuid.NewString()),
	} {
		if r := withAssertion(bad, true); r.Status != 401 {
			t.Fatalf("%s = %d %s", name, r.Status, r.Body)
		}
	}
	if r := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, "", ""); r.Status != 401 {
		t.Fatalf("secret with private_key_jwt = %d", r.Status)
	}
	e.Must("POST", "/identity/v1/machine-token", secret, nil, 401)

	// private_key_jwt with a jwks_uri (ES256), fetched over the guarded
	// transport the test points at its TLS server.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{ecJWK(ec, "ec1")}})
	}))
	defer keys.Close()
	e.IdP.Set(keys.Client().Transport)
	e.Must("PUT", auth, e.Owner, fiber.Map{"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "ES256", "jwks_uri": keys.URL + "/jwks"}, 200)
	if r := withAssertion(assertion(t, jwt.SigningMethodES256, ec, "ec1", id, "https://iam.example/oauth/token", uuid.NewString()), true); r.Status != 200 {
		t.Fatalf("jwks_uri = %d %s", r.Status, r.Body)
	}

	// Revoked accounts cannot authenticate.
	e.Must("DELETE", e.Base+"/service-accounts/"+id, e.Owner, nil, 204)
	if r := withAssertion(assertion(t, jwt.SigningMethodES256, ec, "ec1", id, "https://iam.example/oauth/token", uuid.NewString()), true); r.Status != 401 {
		t.Fatalf("revoked = %d %s", r.Status, r.Body)
	}
}

// TestOAuthClientPrivateKeyJWT: a confidential OAuth client authenticates
// with private_key_jwt at the token endpoint (code exchange, refresh,
// revocation), while its secret stops working.
func TestOAuthClientPrivateKeyJWT(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "token_endpoint_auth_method": "private_key_jwt"}, 400)
	registered := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "token_endpoint_auth_method": "private_key_jwt", "jwks": fiber.Map{"keys": []any{rsaJWK(key, "c1")}}}, 201).JSON
	client, secret := registered["client_id"].(string), registered["client_secret"].(string)
	view := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON
	if view["token_endpoint_auth_method"] != "private_key_jwt" || view["jwks"] == nil {
		t.Fatalf("client = %v", view)
	}

	code, verifier := e.authorizationCode(client)
	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}
	if r := e.tokenRequest(exchange, client, secret); r.Status != 401 {
		t.Fatalf("secret = %d %s", r.Status, r.Body)
	}
	code, verifier = e.authorizationCode(client)
	exchange.Set("code", code)
	exchange.Set("code_verifier", verifier)
	exchange.Set("client_assertion_type", assertionType)
	exchange.Set("client_assertion", assertion(t, jwt.SigningMethodRS256, key, "c1", client, "https://iam.example/oauth/token", uuid.NewString()))
	tokens := e.tokenRequest(exchange, "", "")
	if tokens.Status != 200 || tokens.JSON["refresh_token"] == nil {
		t.Fatalf("code exchange = %d %s", tokens.Status, tokens.Body)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens.JSON["refresh_token"].(string)}, "client_assertion_type": {assertionType}, "client_assertion": {exchange.Get("client_assertion")}}
	if r := e.tokenRequest(refresh, "", ""); r.Status != 400 || r.JSON["error"] != "jti_known" {
		t.Fatalf("replayed assertion = %d %s", r.Status, r.Body)
	}
	refresh.Set("client_assertion", assertion(t, jwt.SigningMethodRS256, key, "c1", client, "https://iam.example", uuid.NewString()))
	if r := e.tokenRequest(refresh, "", ""); r.Status != 200 {
		t.Fatalf("refresh = %d %s", r.Status, r.Body)
	}

	// Switching back to the secret clears the keys.
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"token_endpoint_auth_method": "client_secret_basic"}, 204)
	if view = e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON; view["token_endpoint_auth_method"] != "client_secret_basic" || view["jwks"] != nil {
		t.Fatalf("client = %v", view)
	}
	code, verifier = e.authorizationCode(client)
	exchange = url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}
	if r := e.tokenRequest(exchange, client, secret); r.Status != 200 {
		t.Fatalf("secret again = %d %s", r.Status, r.Body)
	}
	// OAuth clients do not get client_credentials.
	if r := e.tokenRequest(url.Values{"grant_type": {"client_credentials"}}, client, secret); r.Status != 401 {
		t.Fatalf("client client_credentials = %d %s", r.Status, r.Body)
	}
}

// authorizationCode runs a headless authorization for alice and returns
// the code and its PKCE verifier.
func (e *Env) authorizationCode(client string) (string, string) {
	e.t.Helper()
	verifier := strings.Repeat("v", 50) + uuid.NewString()
	challenge := pkceS256(verifier)
	q := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	res, err := e.App.Test(httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil), 10000)
	if err != nil || res.StatusCode != 200 {
		e.t.Fatalf("authorize: %v %v", err, res)
	}
	var begin map[string]any
	json.NewDecoder(res.Body).Decode(&begin)
	res.Body.Close()
	body, _ := json.Marshal(fiber.Map{"authorization_ticket": begin["authorization_ticket"], "approve": true})
	req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.Login(e.AliceEmail))
	req.AddCookie(res.Cookies()[0])
	done, err := e.App.Test(req, 10000)
	if err != nil || done.StatusCode != 303 {
		e.t.Fatalf("complete: %v %v", err, done)
	}
	location, _ := url.Parse(done.Header.Get("Location"))
	return location.Query().Get("code"), verifier
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func anyStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
