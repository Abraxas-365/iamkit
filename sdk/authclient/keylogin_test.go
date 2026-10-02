package authclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestKeyLogin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/oauth/token" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("client_id") != "" ||
			r.Form.Get("organization_id") != "o1" || r.Form.Get("environment_id") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request %s %v", r.URL.Path, r.Form)
		}
		var claims jwt.RegisteredClaims
		token, err := jwt.ParseWithClaims(r.Form.Get("assertion"), &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
			jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(base+"/oauth/token"), jwt.WithIssuer("u1"), jwt.WithSubject("u1"))
		if err != nil || token.Header["kid"] != "k1" || claims.ID == "" {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"jwt","token_type":"Bearer","expires_in":900}`))
	}))
	defer srv.Close()
	base = srv.URL

	// The PEM IAMKit returns parses back to the signer.
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	login, err := NewKeyLogin(srv.URL, "u1", "k1", signer)
	if err != nil {
		t.Fatal(err)
	}
	out, err := login.Token(context.Background(), KeyBoundary{OrganizationID: "o1", ApplicationID: "a1", ResourceID: "r1"})
	if err != nil || out.AccessToken != "jwt" {
		t.Fatalf("token = %+v %v", out, err)
	}

	// Refusals surface as OAuth errors.
	wrong, _ := NewKeyLogin(srv.URL, "u1", "k2", key)
	var oauthErr *OAuthError
	if _, err := wrong.Token(context.Background(), KeyBoundary{OrganizationID: "o1"}); !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_grant" {
		t.Fatalf("err = %v", err)
	}

	// Only RSA and EC keys; garbage PEM is refused.
	if _, err := ParsePrivateKey([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewKeyLogin(srv.URL, "u1", "k1", rsaKey); err != nil {
		t.Fatal(err)
	}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, err := NewKeyLogin(srv.URL, "u1", "k1", p224); err == nil {
		t.Fatal("P-224 accepted")
	}
}
