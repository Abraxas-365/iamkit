package cryptox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealRoundTrip(t *testing.T) {
	s, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("client-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:"+KeyID(key(1))+":") || strings.Contains(sealed, "client-secret") {
		t.Fatalf("unexpected sealed format %q", sealed)
	}
	again, _ := s.Seal([]byte("client-secret"))
	if again == sealed {
		t.Fatal("nonce reused")
	}
	plain, err := s.Open(sealed)
	if err != nil || string(plain) != "client-secret" {
		t.Fatalf("open: %q %v", plain, err)
	}
}

func TestOpenRejectsWrongKeyAndTampering(t *testing.T) {
	a, _ := New(key(1))
	b, _ := New(key(2))
	sealed, _ := a.Seal([]byte("secret"))
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("foreign key opened value")
	}
	// Relabel with b's key ID: authentication must fail, not decrypt garbage.
	relabelled := "v1:" + KeyID(key(2)) + sealed[strings.LastIndexByte(sealed, ':'):]
	if _, err := b.Open(relabelled); err == nil {
		t.Fatal("relabelled value opened")
	}
	raw := []byte(sealed)
	raw[len(raw)-2] ^= 1
	if _, err := a.Open(string(raw)); err == nil {
		t.Fatal("tampered value opened")
	}
	for _, bad := range []string{"", "v1:x", "v2:" + KeyID(key(1)) + ":AAAA", "v1:" + KeyID(key(1)) + ":!!"} {
		if _, err := a.Open(bad); err == nil {
			t.Fatalf("malformed %q opened", bad)
		}
	}
}

func TestRotation(t *testing.T) {
	old, _ := New(key(1))
	sealed, _ := old.Seal([]byte("secret"))
	rotated, err := Parse(base64.StdEncoding.EncodeToString(key(2)), " "+base64.StdEncoding.EncodeToString(key(1))+", ")
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := rotated.Open(sealed); err != nil || string(plain) != "secret" {
		t.Fatalf("old key not usable for decrypt: %v", err)
	}
	resealed, _ := rotated.Seal([]byte("secret"))
	if !strings.HasPrefix(resealed, "v1:"+KeyID(key(2))+":") {
		t.Fatal("new values must use the current key")
	}
}

func TestDisabledAndInvalidConfiguration(t *testing.T) {
	s, err := Parse("", "")
	if err != nil || s.Enabled() {
		t.Fatalf("empty key must yield a disabled sealer: %v", err)
	}
	if _, err := s.Seal([]byte("x")); err == nil {
		t.Fatal("disabled sealer sealed")
	}
	if _, err := s.Open("v1:abcd:AAAA"); err == nil {
		t.Fatal("disabled sealer opened")
	}
	for _, c := range [][2]string{{"not-base64", ""}, {base64.StdEncoding.EncodeToString(key(1)[:16]), ""}, {"", base64.StdEncoding.EncodeToString(key(1))}, {base64.StdEncoding.EncodeToString(key(1)), "bad"}} {
		if _, err := Parse(c[0], c[1]); err == nil {
			t.Fatalf("accepted %q/%q", c[0], c[1])
		}
	}
}
