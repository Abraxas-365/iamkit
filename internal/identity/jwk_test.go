package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePublicJWK(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaJWK, _ := MarshalPublicJWK(&rsaKey.PublicKey)
	ecJWK, _ := MarshalPublicJWK(&ecKey.PublicKey)
	smallJWK, _ := MarshalPublicJWK(&small.PublicKey)
	with := func(raw json.RawMessage, key string, value any) json.RawMessage {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		m[key] = value
		out, _ := json.Marshal(m)
		return out
	}
	for name, c := range map[string]struct {
		raw  json.RawMessage
		fail string
	}{
		"rsa":         {raw: rsaJWK},
		"ec":          {raw: ecJWK},
		"not json":    {raw: json.RawMessage(`{`), fail: "JSON Web Key"},
		"array":       {raw: json.RawMessage(`[]`), fail: "JSON Web Key"},
		"private":     {raw: with(rsaJWK, "d", "AQAB"), fail: "private"},
		"symmetric":   {raw: json.RawMessage(`{"kty":"oct","k":"AAAA"}`), fail: "private"},
		"encryption":  {raw: with(rsaJWK, "use", "enc"), fail: "signing"},
		"okp":         {raw: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`), fail: "RSA or EC"},
		"short rsa":   {raw: smallJWK, fail: "2048"},
		"even e":      {raw: with(rsaJWK, "e", "Ag"), fail: "exponent"},
		"bad curve":   {raw: with(ecJWK, "crv", "P-192"), fail: "P-256"},
		"short x":     {raw: with(ecJWK, "x", "AAAA"), fail: "coordinates"},
		"not a point": {raw: with(ecJWK, "y", strings.Repeat("A", 43)), fail: "curve"},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ParsePublicJWK(c.raw)
			if c.fail == "" {
				if err != nil || KeyAlgorithms(key) == nil {
					t.Fatalf("key=%v err=%v", key, err)
				}
				round, _ := MarshalPublicJWK(key)
				if string(round) != string(c.raw) {
					t.Fatalf("round trip %s != %s", round, c.raw)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.fail) {
				t.Fatalf("err = %v, want %q", err, c.fail)
			}
		})
	}
}

func TestKeyAlgorithms(t *testing.T) {
	for curve, want := range map[elliptic.Curve]string{elliptic.P256(): "ES256", elliptic.P384(): "ES384", elliptic.P521(): "ES512"} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if got := KeyAlgorithms(&key.PublicKey); len(got) != 1 || got[0] != want {
			t.Fatalf("%s: %v", curve.Params().Name, got)
		}
	}
}
