package authjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/golang-jwt/jwt/v5"
)

// auth_time round-trips, and the float form fosite writes (1.7e+09) parses.
func TestAuthTime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := New(key, "https://iam.example")
	now := time.Now().Unix()
	raw, err := c.Sign(authentication.Token{Purpose: "application", Audience: []string{"api"}, AuthTime: now - 60, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Verify(raw, "api"); err != nil || got.AuthTime != now-60 {
		t.Fatalf("auth_time = %d %v", got.AuthTime, err)
	}

	float := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "aud": "api", "exp": float64(now + 60), "auth_time": float64(1790494900), "purpose": "application"})
	signed, err := float.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Verify(signed, "api"); err != nil || got.AuthTime != 1790494900 {
		t.Fatalf("float auth_time = %d %v", got.AuthTime, err)
	}
}
