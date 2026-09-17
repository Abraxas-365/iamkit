package e2e_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func federationJourney(t *testing.T, app *fiber.App, key *rsa.PrivateKey, call func(string, string, string, any, int) map[string]any, owner, base, env, org, user, client, resource string) {
	t.Helper()
	var issuer, nonce string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "provider", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", 400)
				return
			}
			if r.Form.Get("code") != "provider-code" || r.Form.Get("code_verifier") == "" {
				http.Error(w, "invalid code", 400)
				return
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "provider-user", "aud": "provider-client", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce})
			token.Header["kid"] = "provider"
			signed, err := token.SignedString(key)
			if err != nil {
				http.Error(w, "sign", 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-access", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	original := http.DefaultTransport
	http.DefaultTransport = provider.Client().Transport
	defer func() { http.DefaultTransport = original }()
	binding, _ := json.Marshal([]map[string]string{{"environment_id": env, "issuer": issuer, "client_id": "provider-client", "secret_env": "IAMKIT_PROVIDER_TEST"}})
	t.Setenv("FEDERATION_CREDENTIAL_BINDINGS", string(binding))
	t.Setenv("IAMKIT_PROVIDER_TEST", "provider-secret")
	connection := call("POST", base+"/federation-connections", owner, fiber.Map{"name": "Test IdP", "issuer": issuer, "client_id": "provider-client", "secret_env": "IAMKIT_PROVIDER_TEST"}, 201)["id"].(string)
	call("POST", base+"/external-identities", owner, fiber.Map{"connection_id": connection, "user_id": user, "subject": "provider-user"}, 204)
	body, _ := json.Marshal(fiber.Map{"connection_id": connection, "environment_id": env, "organization_id": org, "application_id": client, "resource_id": resource})
	req := httptest.NewRequest("POST", "/identity/v1/federation/start", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var start map[string]any
	if err = json.NewDecoder(res.Body).Decode(&start); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("start: %d %v", res.StatusCode, start)
	}
	authorization, _ := url.Parse(start["authorization_url"].(string))
	nonce = authorization.Query().Get("nonce")
	state := authorization.Query().Get("state")
	if nonce == "" || state == "" {
		t.Fatal("missing state/nonce")
	}
	callback := "/identity/v1/federation/callback?code=provider-code&state=" + url.QueryEscape(state)
	call("GET", callback, "", nil, 401)
	req = httptest.NewRequest("GET", callback, nil)
	req.AddCookie(res.Cookies()[0])
	result, err := app.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	var pair map[string]any
	if err = json.NewDecoder(result.Body).Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != 200 {
		t.Fatalf("callback: %d %v", result.StatusCode, pair)
	}
	access := pair["access_token"].(string)
	if call("POST", "/identity/v1/introspect", access, fiber.Map{"environment_id": env, "audience": "https://billing.example"}, 200)["active"] != true {
		t.Fatal("federated access invalid")
	}
	req = httptest.NewRequest("GET", callback, nil)
	req.AddCookie(res.Cookies()[0])
	replay, err := app.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if replay.StatusCode != 401 {
		t.Fatal("federation replay accepted")
	}
}
