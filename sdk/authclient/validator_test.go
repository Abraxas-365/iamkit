package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestTokenBoundaries(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{EnvironmentID: "prod", OrganizationID: "acme", ApplicationID: "web", ResourceID: "billing", Permissions: []string{"invoices:read"}, Purpose: "application", SessionID: "session", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://iam.example", Subject: "alice", Audience: jwt.ClaimStrings{"billing"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}
	sign := func(c Claims) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := sign(c)
	if _, err = Validate(raw, &key.PublicKey, "https://iam.example", "billing", "prod", "web", "billing"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ issuer, audience, environment, application, resource string }{
		{"wrong", "billing", "prod", "web", "billing"}, {"https://iam.example", "wrong", "prod", "web", "billing"}, {"https://iam.example", "billing", "dev", "web", "billing"}, {"https://iam.example", "billing", "prod", "mobile", "billing"}, {"https://iam.example", "billing", "prod", "web", "support"},
	} {
		if _, err = Validate(raw, &key.PublicKey, tc.issuer, tc.audience, tc.environment, tc.application, tc.resource); err == nil {
			t.Fatal("boundary accepted", tc)
		}
	}
	c.Purpose = "management"
	if _, err = Validate(sign(c), &key.PublicKey, "https://iam.example", "billing", "prod", "web", "billing"); err == nil {
		t.Fatal("management accepted")
	}
}
