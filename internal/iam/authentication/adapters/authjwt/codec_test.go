package authjwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

// ring is a fixed keyring: the deployment key plus environment keys.
type ring struct {
	deployment *rsa.PrivateKey
	env        map[identity.EnvironmentID]*rsa.PrivateKey
}

func (r ring) Signer(_ context.Context, environment identity.EnvironmentID) (signing.Signer, error) {
	key := r.deployment
	if k, ok := r.env[environment]; ok {
		key = k
	}
	return signing.Signer{ID: signing.KeyID(&key.PublicKey), Private: key}, nil
}
func (r ring) Verifier(_ context.Context, kid string) (signing.Verifier, error) {
	if kid == "" || kid == signing.KeyID(&r.deployment.PublicKey) {
		return signing.Verifier{ID: kid, Public: &r.deployment.PublicKey}, nil
	}
	for environment, key := range r.env {
		if signing.KeyID(&key.PublicKey) == kid {
			return signing.Verifier{ID: kid, Public: &key.PublicKey, Environment: environment}, nil
		}
	}
	return signing.Verifier{}, errx.Unauthorized("unknown signing key")
}
func (r ring) JWKS(context.Context) ([]signing.JWK, error) { return nil, nil }

// auth_time round-trips, and the float form fosite writes (1.7e+09) parses.
func TestAuthTime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ring{deployment: key}, "https://iam.example")
	ctx := context.Background()
	now := time.Now().Unix()
	raw, err := c.Sign(ctx, authentication.Token{Purpose: "application", Audience: []string{"api"}, AuthTime: now - 60, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Verify(ctx, raw, "api"); err != nil || got.AuthTime != now-60 {
		t.Fatalf("auth_time = %d %v", got.AuthTime, err)
	}

	float := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "aud": "api", "exp": float64(now + 60), "auth_time": float64(1790494900), "purpose": "application"})
	signed, err := float.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Verify(ctx, signed, "api"); err != nil || got.AuthTime != 1790494900 {
		t.Fatalf("float auth_time = %d %v", got.AuthTime, err)
	}
}

// An impersonating service account travels as the RFC 8693 act claim.
func TestActorAccount(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ring{deployment: key}, "https://iam.example")
	ctx := context.Background()
	now := time.Now().Unix()
	account := identity.NewAccountID()
	raw, err := c.Sign(ctx, authentication.Token{Purpose: "application", ActorAccount: account, Audience: []string{"api"}, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Verify(ctx, raw, "api")
	if err != nil || got.ActorAccount != account || !got.ActorID.IsZero() || !got.Impersonated() {
		t.Fatalf("actor = %+v %v", got, err)
	}
	// Unset optional IDs are left out, not the nil UUID: SDKs read a present
	// actor_id as operator impersonation and a sid on a machine token as invalid.
	plain, err := c.Sign(ctx, authentication.Token{Purpose: "machine", Audience: []string{"api"}, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(plain, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	for _, name := range []string{"actor_id", "oauth_client_id", "sid", "act"} {
		if v, ok := claims[name]; ok {
			t.Fatalf("%s = %v, want absent", name, v)
		}
	}
	bad := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "aud": "api", "exp": now + 60, "purpose": "application", "act": map[string]any{"sub": "nope"}})
	signed, err := bad.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(ctx, signed, "api"); err == nil {
		t.Fatal("malformed act accepted")
	}
}

// An environment with its own key signs with it; the kid picks the key;
// another environment's key never vouches for a token.
func TestEnvironmentKeys(t *testing.T) {
	deployment, _ := rsa.GenerateKey(rand.Reader, 2048)
	own, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, b := identity.NewEnvironmentID(), identity.NewEnvironmentID()
	c := New(ring{deployment: deployment, env: map[identity.EnvironmentID]*rsa.PrivateKey{a: own}}, "https://iam.example")
	ctx := context.Background()
	now := time.Now().Unix()
	token := func(environment identity.EnvironmentID) authentication.Token {
		return authentication.Token{Access: identity.Access{EnvironmentID: environment}, Purpose: "application", Audience: []string{"api"}, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60}
	}
	kid := func(raw string) string {
		parsed, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
		out, _ := parsed.Header["kid"].(string)
		return out
	}
	rawA, err := c.Sign(ctx, token(a))
	if err != nil || kid(rawA) != signing.KeyID(&own.PublicKey) {
		t.Fatalf("environment key not used: %v", err)
	}
	rawB, err := c.Sign(ctx, token(b))
	if err != nil || kid(rawB) != signing.KeyID(&deployment.PublicKey) {
		t.Fatalf("deployment key not used: %v", err)
	}
	for _, raw := range []string{rawA, rawB} {
		if _, err := c.Verify(ctx, raw, "api"); err != nil {
			t.Fatal(err)
		}
	}
	// A token of environment b signed with a's key (same kid) is refused.
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "aud": "api", "exp": now + 60, "environment_id": b.String(), "purpose": "application"})
	forged.Header["kid"] = signing.KeyID(&own.PublicKey)
	signed, _ := forged.SignedString(own)
	if _, err := c.Verify(ctx, signed, "api"); err == nil {
		t.Fatal("cross-environment key accepted")
	}
	// An unknown kid is refused.
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknown := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "aud": "api", "exp": now + 60, "environment_id": a.String()})
	unknown.Header["kid"] = signing.KeyID(&stranger.PublicKey)
	if signed, _ = unknown.SignedString(stranger); signed != "" {
		if _, err := c.Verify(ctx, signed, "api"); err == nil {
			t.Fatal("unknown key accepted")
		}
	}
}
