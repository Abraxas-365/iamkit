package oauthfosite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

// oneKey is a keyring with only the deployment key.
type oneKey struct{ key *rsa.PrivateKey }

func (k oneKey) Signer(context.Context, identity.EnvironmentID) (signing.Signer, error) {
	return signing.Signer{ID: signing.KeyID(&k.key.PublicKey), Private: k.key}, nil
}
func (k oneKey) Verifier(_ context.Context, kid string) (signing.Verifier, error) {
	if kid != "" && kid != signing.KeyID(&k.key.PublicKey) {
		return signing.Verifier{}, errx.Unauthorized("unknown signing key")
	}
	return signing.Verifier{ID: kid, Public: &k.key.PublicKey}, nil
}
func (k oneKey) JWKS(context.Context) ([]signing.JWK, error) { return nil, nil }

func TestHintsParse(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	hints := Hints{Keys: oneKey{key}, Issuer: "https://iam.example"}
	ctx := context.Background()
	user, env, sid, client := identity.NewUserID(), identity.NewEnvironmentID(), identity.NewSessionID(), identity.NewClientID()
	claims := func(change func(jwt.MapClaims)) jwt.MapClaims {
		c := jwt.MapClaims{"iss": "https://iam.example", "sub": user.String(), "aud": client.String(), "environment_id": env.String(), "sid": sid.String(), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if change != nil {
			change(c)
		}
		return c
	}
	sign := func(k *rsa.PrivateKey, method jwt.SigningMethod, c jwt.MapClaims) string {
		raw, err := jwt.NewWithClaims(method, c).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	got, err := hints.Parse(ctx, sign(key, jwt.SigningMethodRS256, claims(nil)))
	if err != nil || got.Subject != user || got.Environment != env || got.Session != sid || got.Client() != client || !got.Names(client) {
		t.Fatalf("valid hint = %+v %v", got, err)
	}
	expired := claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	if got, err = hints.Parse(ctx, sign(key, jwt.SigningMethodRS256, expired)); err != nil || got.Session != sid {
		t.Fatalf("expired hint refused: %v", err)
	}
	noSID := claims(func(c jwt.MapClaims) { delete(c, "sid") })
	if got, err = hints.Parse(ctx, sign(key, jwt.SigningMethodRS256, noSID)); err != nil || !got.Session.IsZero() {
		t.Fatalf("hint without sid: %+v %v", got, err)
	}
	for name, raw := range map[string]string{
		"foreign key":    sign(other, jwt.SigningMethodRS256, claims(nil)),
		"foreign issuer": sign(key, jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" })),
		"wrong alg":      sign(key, jwt.SigningMethodRS512, claims(nil)),
		"no audience":    sign(key, jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { delete(c, "aud") })),
		"bad subject":    sign(key, jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["sub"] = "x" })),
		"no environment": sign(key, jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { delete(c, "environment_id") })),
		"not yet valid":  sign(key, jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() })),
		"garbage":        "not.a.jwt",
	} {
		if _, err := hints.Parse(ctx, raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	multi := claims(func(c jwt.MapClaims) { c["aud"] = []string{client.String(), "other"} })
	if got, err = hints.Parse(ctx, sign(key, jwt.SigningMethodRS256, multi)); err != nil || !got.Client().IsZero() || !got.Names(client) {
		t.Fatalf("multi-audience hint: %+v %v", got, err)
	}
}
