package identity

import (
	"encoding/json"
	"testing"
)

func TestClientAuth(t *testing.T) {
	rsa := json.RawMessage(`{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB"}]}`)
	if got := (ClientAuth{}).WithDefaults(true); got.Method != AuthNone || got.SigningAlg != "RS256" {
		t.Fatalf("public defaults = %+v", got)
	}
	if got := (ClientAuth{}).WithDefaults(false); got.Method != AuthSecretBasic {
		t.Fatalf("confidential defaults = %+v", got)
	}
	valid := map[string]struct {
		auth   ClientAuth
		public bool
	}{
		"public":      {ClientAuth{Method: AuthNone}, true},
		"basic":       {ClientAuth{Method: AuthSecretBasic}, false},
		"post":        {ClientAuth{Method: AuthSecretPost}, false},
		"inline keys": {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: rsa}, false},
		"key url":     {ClientAuth{Method: AuthPrivateKeyJWT, JWKSURI: "https://keys.example/jwks", SigningAlg: "ES256"}, false},
	}
	for name, c := range valid {
		if err := c.auth.WithDefaults(c.public).Validate(c.public); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := map[string]struct {
		auth   ClientAuth
		public bool
	}{
		"public with secret": {ClientAuth{Method: AuthSecretBasic}, true},
		"confidential none":  {ClientAuth{Method: AuthNone}, false},
		"unknown method":     {ClientAuth{Method: "client_secret_jwt"}, false},
		"symmetric alg":      {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: rsa, SigningAlg: "HS256"}, false},
		"no keys":            {ClientAuth{Method: AuthPrivateKeyJWT}, false},
		"both keys":          {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: rsa, JWKSURI: "https://keys.example/jwks"}, false},
		"http key url":       {ClientAuth{Method: AuthPrivateKeyJWT, JWKSURI: "http://keys.example/jwks"}, false},
		"credentials in url": {ClientAuth{Method: AuthPrivateKeyJWT, JWKSURI: "https://u:p@keys.example/jwks"}, false},
		"keys for secret":    {ClientAuth{Method: AuthSecretBasic, JWKSURI: "https://keys.example/jwks"}, false},
		"private key":        {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}]}`)}, false},
		"symmetric key":      {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)}, false},
		"encryption key":     {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[{"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"}]}`)}, false},
		"empty set":          {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[]}`)}, false},
		"not a set":          {ClientAuth{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`[1]`)}, false},
	}
	for name, c := range invalid {
		if c.auth.WithDefaults(c.public).Validate(c.public) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if (ClientAuth{}).StoredJWKS() != nil || (ClientAuth{JWKS: rsa}).StoredJWKS() != string(rsa) {
		t.Fatal("StoredJWKS")
	}
}
