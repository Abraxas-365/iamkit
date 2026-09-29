package authclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A key set follows rotation: a key published after the first fetch is
// found on its first unknown kid; unknown kids refresh at most once per
// MinRefresh; a key the server stops publishing stops validating.
func TestKeySetRotation(t *testing.T) {
	first, _ := rsa.GenerateKey(rand.Reader, 2048)
	second, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := func(kid string, k *rsa.PrivateKey) map[string]string {
		return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
	}
	var published atomic.Value
	published.Store([]map[string]string{jwk("one", first)})
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": published.Load()})
	}))
	defer server.Close()

	keys := NewKeySet(server.URL, server.Client())
	clock := time.Now()
	keys.now = func() time.Time { return clock }
	claims := Claims{EnvironmentID: "prod", OrganizationID: "acme", ApplicationID: "web", ResourceID: "billing", Purpose: "application", SessionID: "session", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://iam.example", Subject: "alice", Audience: jwt.ClaimStrings{"billing"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	sign := func(kid string, k *rsa.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		raw, err := token.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	ctx := context.Background()
	check := func(raw string) error {
		_, err := ValidateWithKeySet(ctx, raw, keys, "https://iam.example", "billing", "prod", "web", "billing")
		return err
	}

	if err := check(sign("one", first)); err != nil || fetches.Load() != 1 {
		t.Fatalf("first: %v (%d fetches)", err, fetches.Load())
	}
	// The server publishes a second key; its first token triggers a refresh.
	published.Store([]map[string]string{jwk("one", first), jwk("two", second)})
	clock = clock.Add(time.Minute)
	if err := check(sign("two", second)); err != nil || fetches.Load() != 2 {
		t.Fatalf("rotated: %v (%d fetches)", err, fetches.Load())
	}
	// Unknown kids refresh at most once per MinRefresh.
	for range 5 {
		if check(sign("nope", second)) == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if fetches.Load() != 2 {
		t.Fatalf("burst fetches = %d", fetches.Load())
	}
	// A kid naming the wrong key fails the signature.
	if check(sign("one", second)) == nil {
		t.Fatal("wrong key accepted")
	}
	// The first key is retired: after MaxAge it stops validating.
	published.Store([]map[string]string{jwk("two", second)})
	clock = clock.Add(11 * time.Minute)
	if check(sign("one", first)) == nil {
		t.Fatal("retired key accepted")
	}
	if err := check(sign("two", second)); err != nil {
		t.Fatal(err)
	}
	// A failing JWKS keeps serving the last set.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetches.Add(1); w.WriteHeader(500) })
	clock = clock.Add(11 * time.Minute)
	before := fetches.Load()
	for range 3 {
		if err := check(sign("two", second)); err != nil {
			t.Fatalf("outage dropped keys: %v", err)
		}
	}
	if fetches.Load() > before+1 {
		t.Fatalf("outage fetches = %d", fetches.Load()-before)
	}
	if _, err := ValidateWithKeySet(ctx, sign("two", second), nil, "https://iam.example", "billing", "prod", "web", "billing"); err == nil {
		t.Fatal("nil key set accepted")
	}
}
