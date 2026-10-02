package authjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

// VerifyAssertion accepts exactly RFC 7523 assertions of the key's user,
// for this issuer, signed by the key with an algorithm of its type.
func TestVerifyAssertion(t *testing.T) {
	const issuer = "https://iam.example"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	user := identity.NewUserID()
	machineKey := func(public crypto.PublicKey) authentication.MachineKey {
		jwk, err := identity.MarshalPublicJWK(public)
		if err != nil {
			t.Fatal(err)
		}
		return authentication.MachineKey{ID: identity.NewUserKeyID(), User: user, PublicKey: jwk}
	}
	rsaMachine, ecMachine := machineKey(&rsaKey.PublicKey), machineKey(&ecKey.PublicKey)
	now := time.Now()
	claims := func(edit func(jwt.MapClaims)) jwt.MapClaims {
		c := jwt.MapClaims{"iss": user.String(), "sub": user.String(), "aud": issuer + "/oauth/token", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "j1"}
		if edit != nil {
			edit(c)
		}
		return c
	}
	sign := func(method jwt.SigningMethod, key crypto.Signer, kid string, c jwt.MapClaims) string {
		token := jwt.NewWithClaims(method, c)
		token.Header["kid"] = kid
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	codec := New(ring{deployment: rsaKey}, issuer)
	for name, c := range map[string]struct {
		raw string
		key authentication.MachineKey
		ok  bool
	}{
		"rsa":             {raw: sign(jwt.SigningMethodRS256, rsaKey, rsaMachine.ID.String(), claims(nil)), key: rsaMachine, ok: true},
		"pss":             {raw: sign(jwt.SigningMethodPS384, rsaKey, rsaMachine.ID.String(), claims(nil)), key: rsaMachine, ok: true},
		"ec":              {raw: sign(jwt.SigningMethodES256, ecKey, ecMachine.ID.String(), claims(nil)), key: ecMachine, ok: true},
		"issuer audience": {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["aud"] = issuer })), key: rsaMachine, ok: true},
		"other key":       {raw: sign(jwt.SigningMethodRS256, other, "", claims(nil)), key: rsaMachine},
		"wrong alg type":  {raw: sign(jwt.SigningMethodES256, ecKey, "", claims(nil)), key: rsaMachine},
		"other subject":   {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["sub"] = identity.NewUserID().String() })), key: rsaMachine},
		"other issuer":    {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["iss"] = "someone" })), key: rsaMachine},
		"other audience":  {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["aud"] = "https://elsewhere/oauth/token" })), key: rsaMachine},
		"no jti":          {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { delete(c, "jti") })), key: rsaMachine},
		"no exp":          {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { delete(c, "exp") })), key: rsaMachine},
		"expired":         {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() })), key: rsaMachine},
		"too long":        {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["exp"] = now.Add(2 * time.Hour).Unix() })), key: rsaMachine},
		"not yet valid":   {raw: sign(jwt.SigningMethodRS256, rsaKey, "", claims(func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Hour).Unix() })), key: rsaMachine},
		"garbage":         {raw: "a.b.c", key: rsaMachine},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := codec.VerifyAssertion(context.Background(), c.raw, c.key)
			if c.ok != (err == nil) {
				t.Fatalf("err = %v", err)
			}
			if c.ok && (got.JTI != "j1" || got.Expires.IsZero()) {
				t.Fatalf("assertion = %+v", got)
			}
		})
	}

	// The kid names the key; anything else is refused before any lookup.
	if id, err := codec.AssertionKey(sign(jwt.SigningMethodRS256, rsaKey, rsaMachine.ID.String(), claims(nil))); err != nil || id != rsaMachine.ID {
		t.Fatalf("kid = %v %v", id, err)
	}
	for _, raw := range []string{sign(jwt.SigningMethodRS256, rsaKey, "", claims(nil)), sign(jwt.SigningMethodRS256, rsaKey, "not-a-uuid", claims(nil)), "garbage"} {
		if _, err := codec.AssertionKey(raw); err == nil {
			t.Fatalf("kid of %q accepted", raw)
		}
	}
}
