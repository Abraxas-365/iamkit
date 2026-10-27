package resourceserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/golang-jwt/jwt/v5"
)

func TestCanonicalResourceSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name      string  `json:"name"`
			Input     string  `json:"input"`
			Canonical *string `json:"canonical"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 20 {
		t.Fatalf("only %d vectors", len(vectors.Cases))
	}
	for _, tc := range vectors.Cases {
		got, err := CanonicalResource(tc.Input)
		switch {
		case tc.Canonical == nil && err == nil:
			t.Errorf("%s: CanonicalResource(%q) = %q, want an error", tc.Name, tc.Input, got)
		case tc.Canonical != nil && err != nil:
			t.Errorf("%s: CanonicalResource(%q): %v", tc.Name, tc.Input, err)
		case tc.Canonical != nil && got != *tc.Canonical:
			t.Errorf("%s: CanonicalResource(%q) = %q, want %q", tc.Name, tc.Input, got, *tc.Canonical)
		}
	}
}

func TestMetadataURL(t *testing.T) {
	for resource, want := range map[string]string{
		"https://mcp.example.com":         "https://mcp.example.com/.well-known/oauth-protected-resource",
		"https://mcp.example.com/mcp":     "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
		"http://localhost:3000/a/b":       "http://localhost:3000/.well-known/oauth-protected-resource/a/b",
		"https://mcp.example.com:8443/v1": "https://mcp.example.com:8443/.well-known/oauth-protected-resource/v1",
	} {
		if got := MetadataURL(resource); got != want {
			t.Errorf("MetadataURL(%q) = %q, want %q", resource, got, want)
		}
	}
}

type fixture struct {
	t      *testing.T
	key    *rsa.PrivateKey
	server *Server
}

const (
	issuer   = "https://iam.example"
	resource = "https://mcp.example.com/mcp"
)

func newFixture(t *testing.T, cfg Config) *fixture {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(jwks.Close)
	cfg.Issuer, cfg.EnvironmentID = issuer, "env-1"
	if cfg.Resource == "" {
		cfg.Resource = "https://MCP.example.com:443/mcp/"
	}
	cfg.Keys = authclient.NewKeySet(jwks.URL, jwks.Client())
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, key: key, server: s}
}

func (f *fixture) token(edit func(jwt.MapClaims)) string {
	now := time.Now()
	c := jwt.MapClaims{"iss": issuer, "sub": "user-1", "aud": []string{resource}, "exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
		"environment_id": "env-1", "organization_id": "org-1", "application_id": "app-1", "resource_id": "res-1", "sid": "s-1", "purpose": "application",
		"permissions": []string{"mcp:tools:read"}, "scp": []string{"mcp:tools:read", "offline_access"}, "scope": "mcp:tools:read offline_access", "resource": resource}
	if edit != nil {
		edit(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	raw, err := tok.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func TestVerify(t *testing.T) {
	f := newFixture(t, Config{})
	if f.server.Resource() != resource {
		t.Fatalf("resource %q", f.server.Resource())
	}
	ctx := context.Background()
	c, err := f.server.Verify(ctx, f.token(nil))
	if err != nil || c.Subject != "user-1" || c.OrganizationID != "org-1" || !c.HasScope("mcp:tools:read") || c.HasScope("mcp:tools:write") {
		t.Fatalf("valid token: %v %+v", err, c)
	}
	// aud is compared canonically.
	if _, err = f.server.Verify(ctx, f.token(func(c jwt.MapClaims) { c["aud"] = "https://mcp.example.com:443/mcp" })); err != nil {
		t.Fatalf("canonical aud: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "sub": "u", "aud": resource, "exp": time.Now().Add(time.Hour).Unix(), "environment_id": "env-1", "organization_id": "o", "sid": "s", "purpose": "application"})
	forged.Header["kid"] = "k1"
	forgedRaw, _ := forged.SignedString(other)
	for name, raw := range map[string]string{
		"other audience":    f.token(func(c jwt.MapClaims) { c["aud"] = "https://iam.example/api" }),
		"other issuer":      f.token(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }),
		"expired":           f.token(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"not yet valid":     f.token(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }),
		"no exp":            f.token(func(c jwt.MapClaims) { delete(c, "exp") }),
		"other environment": f.token(func(c jwt.MapClaims) { c["environment_id"] = "env-2" }),
		"machine token":     f.token(func(c jwt.MapClaims) { c["purpose"] = "machine"; delete(c, "sid"); delete(c, "organization_id") }),
		"no session":        f.token(func(c jwt.MapClaims) { delete(c, "sid") }),
		"no resource":       f.token(func(c jwt.MapClaims) { delete(c, "resource") }),
		"other resource":    f.token(func(c jwt.MapClaims) { c["resource"] = "https://mcp.example.com/other" }),
		"forged signature":  forgedRaw,
		"opaque":            "ik_at_opaque",
	} {
		if _, err := f.server.Verify(ctx, raw); err != ErrInvalidToken {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err = f.server.Verify(ctx, ""); err != ErrNoToken {
		t.Fatalf("no token: %v", err)
	}
	// Small clock skew is tolerated.
	if _, err = f.server.Verify(ctx, f.token(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-10 * time.Second).Unix() })); err != nil {
		t.Fatalf("leeway: %v", err)
	}

	// Organizations narrow the admitted tokens.
	g := newFixture(t, Config{Organizations: []string{"org-2"}})
	if _, err = g.server.Verify(ctx, g.token(nil)); err != ErrInvalidToken {
		t.Fatalf("other organization: %v", err)
	}

	// Permissions are the granted scopes, never the permissions claim.
	c, err = f.server.Verify(ctx, f.token(func(c jwt.MapClaims) {
		c["permissions"] = []string{"mcp:tools:read", "mcp:tools:write", "mcp:admin"}
		c["scp"] = []string{"openid", "mcp:tools:read", "offline_access", "urn:iamkit:org:id:org-1"}
	}))
	if err != nil || !slices.Equal(c.Permissions, []string{"mcp:tools:read"}) || c.HasScope("mcp:tools:write") || c.Resource != resource {
		t.Fatalf("permissions from scopes: %v %+v", err, c)
	}
	// A token without scopes holds nothing, whatever its permissions claim.
	c, err = f.server.Verify(ctx, f.token(func(c jwt.MapClaims) { delete(c, "scp"); delete(c, "scope") }))
	if err != nil || c.HasScope("mcp:tools:read") || len(c.Permissions) != 0 || Require(c, "mcp:tools:read") == nil {
		t.Fatalf("no scopes: %v %+v", err, c)
	}

	// Tokens without the resource claim only with the explicit opt-out.
	h := newFixture(t, Config{AllowTokensWithoutResource: true})
	c, err = h.server.Verify(ctx, h.token(func(c jwt.MapClaims) { delete(c, "resource") }))
	if err != nil || c.Resource != "" || !c.HasScope("mcp:tools:read") {
		t.Fatalf("opt-out: %v %+v", err, c)
	}
	if _, err = h.server.Verify(ctx, h.token(func(c jwt.MapClaims) { c["resource"] = "https://mcp.example.com/other" })); err != ErrInvalidToken {
		t.Fatalf("opt-out keeps checking a present resource: %v", err)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no issuer":     {Resource: resource, EnvironmentID: "e"},
		"no env":        {Issuer: issuer, Resource: resource},
		"bad resource":  {Issuer: issuer, Resource: "https://mcp.example.com/mcp?x=1", EnvironmentID: "e"},
		"plain http":    {Issuer: issuer, Resource: "http://mcp.example.com/mcp", EnvironmentID: "e"},
		"with fragment": {Issuer: issuer, Resource: "https://mcp.example.com/#a", EnvironmentID: "e"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHTTP(t *testing.T) {
	f := newFixture(t, Config{ScopesSupported: []string{"mcp:tools:read", "mcp:tools:write"}, ResourceName: "Tools"})
	mux := http.NewServeMux()
	f.server.Mount(mux)
	mux.Handle("/mcp", f.server.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the client's token reached the handler")
		}
		if r.URL.Query().Get("tool") == "write" && !f.server.RequireScopes(w, r, "mcp:tools:write") {
			return
		}
		c, _ := FromContext(r.Context())
		w.Write([]byte(c.Subject))
	}), "mcp:tools:read"))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	do := func(method, path, token string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Origin", "https://inspector.example")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { res.Body.Close() })
		return res
	}
	metadataURL := "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

	// Metadata at both well-known paths, with CORS.
	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		res := do("GET", path, "")
		var m Metadata
		json.NewDecoder(res.Body).Decode(&m)
		if res.StatusCode != 200 || m.Resource != resource || len(m.AuthorizationServers) != 1 || m.AuthorizationServers[0] != issuer ||
			len(m.ScopesSupported) != 2 || m.BearerMethodsSupported[0] != "header" || res.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("metadata %s: %d %+v %v", path, res.StatusCode, m, res.Header)
		}
	}
	if res := do("OPTIONS", "/.well-known/oauth-protected-resource/mcp", ""); res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("metadata preflight: %d", res.StatusCode)
	}

	// No token: 401 with resource_metadata and the scope, no error code.
	res := do("POST", "/mcp", "")
	if got := res.Header.Get("WWW-Authenticate"); res.StatusCode != 401 || got != `Bearer resource_metadata="`+metadataURL+`", scope="mcp:tools:read"` {
		t.Fatalf("no token: %d %q", res.StatusCode, got)
	}
	// Invalid token: invalid_token.
	res = do("POST", "/mcp", f.token(func(c jwt.MapClaims) { c["aud"] = "https://other.example" }))
	if got := res.Header.Get("WWW-Authenticate"); res.StatusCode != 401 || !strings.HasPrefix(got, `Bearer error="invalid_token"`) || !strings.Contains(got, `resource_metadata="`+metadataURL+`"`) {
		t.Fatalf("invalid token: %d %q", res.StatusCode, got)
	}
	// Valid token.
	res = do("POST", "/mcp", f.token(nil))
	if res.StatusCode != 200 {
		t.Fatalf("valid token: %d", res.StatusCode)
	}
	// Missing the route's scope: 403 insufficient_scope.
	res = do("POST", "/mcp", f.token(func(c jwt.MapClaims) { c["scp"] = []string{"offline_access"}; c["permissions"] = []string{} }))
	if got := res.Header.Get("WWW-Authenticate"); res.StatusCode != 403 || got != `Bearer error="insufficient_scope", resource_metadata="`+metadataURL+`", scope="offline_access mcp:tools:read"` {
		t.Fatalf("insufficient scope: %d %q", res.StatusCode, got)
	}
	// Step-up inside a handler: the challenge keeps the granted scopes.
	res = do("POST", "/mcp?tool=write", f.token(nil))
	if got := res.Header.Get("WWW-Authenticate"); res.StatusCode != 403 || !strings.Contains(got, `scope="mcp:tools:read offline_access mcp:tools:write"`) || !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("step-up: %d %q", res.StatusCode, got)
	}
	res = do("POST", "/mcp?tool=write", f.token(func(c jwt.MapClaims) {
		c["scp"] = []string{"mcp:tools:read", "mcp:tools:write"}
		c["permissions"] = []string{"mcp:tools:read", "mcp:tools:write"}
	}))
	if res.StatusCode != 200 {
		t.Fatalf("after step-up: %d", res.StatusCode)
	}
}

// TestUnavailableKeys: a JWKS that cannot be fetched is a 503 without a
// challenge, not an invalid token the client would throw away.
func TestUnavailableKeys(t *testing.T) {
	f := newFixture(t, Config{})
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer down.Close()
	f.server.keys = authclient.NewKeySet(down.URL, down.Client())
	if _, err := f.server.Verify(context.Background(), f.token(nil)); err != ErrUnavailable {
		t.Fatalf("Verify: %v", err)
	}
	h := f.server.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached the handler") }))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+f.token(nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("Protect: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}
