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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateLogoutToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	keys := NewKeySet(server.URL, server.Client())
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "https://iam.example", "aud": "client1", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "j1", "sub": "alice", "sid": "s1", "events": map[string]any{BackchannelLogoutEvent: map[string]any{}}}
	}
	sign := func(c jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		token.Header["kid"], token.Header["typ"] = "k1", "logout+jwt"
		raw, _ := token.SignedString(key)
		return raw
	}
	ctx := context.Background()
	got, err := ValidateLogoutToken(ctx, sign(base()), keys, "https://iam.example", "client1")
	if err != nil || got.SessionID != "s1" || got.Subject != "alice" {
		t.Fatalf("valid token = %+v %v", got, err)
	}
	bad := map[string]func(jwt.MapClaims){
		"other client": func(c jwt.MapClaims) { c["aud"] = "client2" },
		"other issuer": func(c jwt.MapClaims) { c["iss"] = "https://evil.example" },
		"expired":      func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"no event":     func(c jwt.MapClaims) { c["events"] = map[string]any{} },
		"nonce":        func(c jwt.MapClaims) { c["nonce"] = "n" },
		"no sid":       func(c jwt.MapClaims) { delete(c, "sid") },
		"no jti":       func(c jwt.MapClaims) { delete(c, "jti") },
	}
	for name, change := range bad {
		c := base()
		change(c)
		if _, err := ValidateLogoutToken(ctx, sign(c), keys, "https://iam.example", "client1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ValidateLogoutToken(ctx, sign(base()), nil, "https://iam.example", "client1"); err == nil {
		t.Error("nil key set accepted")
	}
}
