package oauthfosite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

func TestFormatStrategy(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ctx := context.Background()
	cfg := &fosite.Config{GlobalSecret: []byte(strings.Repeat("s", 32)), AccessTokenLifespan: time.Hour, AccessTokenIssuer: "https://iam.example"}
	hmac := compose.NewOAuth2HMACStrategy(cfg)
	jwtStrategy := &oauth2.DefaultJWTStrategy{Signer: Signer{Keys: oneKey{key}}, HMACSHAStrategy: hmac, Config: cfg}
	request := func() fosite.Requester {
		session := NewSession()
		session.AccessClaims.Subject = "user"
		session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour))
		return &fosite.Request{Client: &fosite.DefaultClient{ID: "client"}, Session: session, RequestedAt: time.Now()}
	}

	opaque := &formatStrategy{HMACSHAStrategy: hmac, jwt: jwtStrategy, opaque: true}
	jwtOnly := &formatStrategy{HMACSHAStrategy: hmac, jwt: jwtStrategy}
	handle, signature, err := opaque.GenerateAccessToken(ctx, request())
	if err != nil || !strings.HasPrefix(handle, OpaquePrefix) || isJWT(handle) {
		t.Fatalf("opaque token = %q %v", handle, err)
	}
	signed, jwtSignature, err := jwtOnly.GenerateAccessToken(ctx, request())
	if err != nil || !isJWT(signed) {
		t.Fatalf("jwt token = %q %v", signed, err)
	}
	// Either strategy recognises both shapes: switching a client's format
	// does not strand tokens already issued.
	for _, s := range []*formatStrategy{opaque, jwtOnly} {
		if got := s.AccessTokenSignature(ctx, handle); got != signature {
			t.Fatalf("opaque signature = %q, want %q", got, signature)
		}
		if got := s.AccessTokenSignature(ctx, signed); got != jwtSignature {
			t.Fatalf("jwt signature = %q, want %q", got, jwtSignature)
		}
		if err = s.ValidateAccessToken(ctx, request(), handle); err != nil {
			t.Fatalf("validate opaque: %v", err)
		}
		if err = s.ValidateAccessToken(ctx, request(), signed); err != nil {
			t.Fatalf("validate jwt: %v", err)
		}
	}
	if err = opaque.ValidateAccessToken(ctx, request(), handle+"x"); err == nil {
		t.Fatal("tampered opaque token validated")
	}
	if OpaqueKey(handle) != SignatureHash(signature) {
		t.Fatal("OpaqueKey does not match the stored key")
	}
	for _, raw := range []string{signed, "", "ory_at_", "ory_at_abc", "ory_rt_a.b", "ory_at_a."} {
		if OpaqueKey(raw) != "" {
			t.Fatalf("OpaqueKey(%q) accepted", raw)
		}
	}
}
