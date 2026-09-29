package oauthfosite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

func TestLogoutSender(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var got string
	status := 200
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(400)
			return
		}
		got = r.PostFormValue("logout_token")
		w.WriteHeader(status)
	}))
	defer rp.Close()
	sender := NewLogoutSender(oneKey{key}, "https://iam.example", rp.Client().Transport)
	n := oauth.LogoutNotification{ID: 1, Environment: identity.NewEnvironmentID(), Client: identity.NewClientID(), Session: identity.NewSessionID(), Subject: identity.NewUserID(), URI: rp.URL + "/bc"}
	if err := sender.Send(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(got, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://iam.example"), jwt.WithAudience(n.Client.String()))
	if err != nil {
		t.Fatalf("logout token: %v", err)
	}
	if token.Header["typ"] != "logout+jwt" || token.Header["kid"] == nil {
		t.Fatalf("header = %v", token.Header)
	}
	events, _ := claims["events"].(map[string]any)
	if claims["sub"] != n.Subject.String() || claims["sid"] != n.Session.String() || claims["jti"] == "" || claims["nonce"] != nil || events[oauth.BackchannelLogoutEvent] == nil {
		t.Fatalf("claims = %v", claims)
	}
	status = 500
	if sender.Send(context.Background(), n) == nil {
		t.Fatal("a 500 answer counted as delivered")
	}
	// The production transport refuses loopback addresses.
	if NewLogoutSender(oneKey{key}, "https://iam.example", nil).Send(context.Background(), n) == nil {
		t.Fatal("guarded transport reached a loopback address")
	}
}
