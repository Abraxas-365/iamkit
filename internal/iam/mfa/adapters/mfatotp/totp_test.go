package mfatotp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
)

// RFC 6238 appendix B, SHA-1 key "12345678901234567890"; the 8-digit
// reference values truncated to the last 6 digits.
func TestRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := Code(key, v.unix/30); got != v.want {
			t.Errorf("T=%d: got %s want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	at := time.Unix(1111111111, 0)
	step := at.Unix() / 30
	key := []byte("12345678901234567890")
	var totp TOTP

	got, ok := totp.Verify(secret, Code(key, step), 0, at)
	if !ok || got != step {
		t.Fatalf("current step: ok=%v step=%d", ok, got)
	}
	if _, ok := totp.Verify(secret, Code(key, step-1), 0, at); !ok {
		t.Fatal("previous step should be accepted")
	}
	if _, ok := totp.Verify(secret, Code(key, step+1), 0, at); !ok {
		t.Fatal("next step should be accepted")
	}
	if _, ok := totp.Verify(secret, Code(key, step-2), 0, at); ok {
		t.Fatal("two steps back must be refused")
	}
	if _, ok := totp.Verify(secret, Code(key, step), step, at); ok {
		t.Fatal("a used step must be refused (replay)")
	}
	if _, ok := totp.Verify(secret, Code(key, step-1), step, at); ok {
		t.Fatal("a step before the last used one must be refused")
	}
	if _, ok := totp.Verify(secret, "12345", 0, at); ok {
		t.Fatal("wrong length must be refused")
	}
	if _, ok := totp.Verify(strings.ToLower(secret), Code(key, step), 0, at); !ok {
		t.Fatal("lowercase secret should decode")
	}
}

func TestSecretAndURI(t *testing.T) {
	var totp TOTP
	a, err := totp.Secret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := totp.Secret()
	if a == b || len(a) != 32 {
		t.Fatalf("secrets should be random 32-char base32: %q %q", a, b)
	}
	uri := totp.URI("ABC", mfa.Account{Email: "ana@example.com", Issuer: "Acme Corp"})
	for _, part := range []string{"otpauth://totp/Acme%20Corp:ana@example.com?", "secret=ABC", "issuer=Acme+Corp", "digits=6", "period=30"} {
		if !strings.Contains(uri, part) {
			t.Errorf("uri %q missing %q", uri, part)
		}
	}
}
