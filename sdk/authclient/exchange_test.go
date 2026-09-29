package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user, pass, _ := r.BasicAuth()
		if r.URL.Path != "/oauth/token" || r.Form.Get("grant_type") != TokenExchangeGrantType || user != "api" || pass != "s3cret" {
			t.Errorf("request = %s %v %s", r.URL.Path, r.Form, user)
		}
		switch r.Form.Get("subject_token_type") {
		case AccessTokenType:
			if r.Form.Get("subject_token") != "user-at" || r.Form.Get("audience") != "https://reports" || r.Form.Get("scope") != "reports:read" {
				t.Errorf("exchange form = %v", r.Form)
			}
		case UserIDTokenType:
			if r.Form.Get("subject_token") != "u1" || r.Form.Get("organization_id") != "o1" || r.Form.Get("reason") != "support ticket 1" {
				t.Errorf("impersonate form = %v", r.Form)
			}
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized_client"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at2", "issued_token_type": AccessTokenType, "token_type": "Bearer", "expires_in": 900})
	}))
	defer srv.Close()
	c := NewOAuth(srv.URL, "api", "s3cret")
	out, err := c.ExchangeToken(context.Background(), "user-at", "https://reports", "reports:read")
	if err != nil || out.AccessToken != "at2" || out.IssuedTokenType != AccessTokenType || out.ExpiresIn != 900 {
		t.Fatalf("ExchangeToken = %+v %v", out, err)
	}
	_, err = c.Impersonate(context.Background(), "u1", "o1", "support ticket 1")
	var failure *OAuthError
	if !errors.As(err, &failure) || failure.Code != "unauthorized_client" {
		t.Fatalf("Impersonate err = %v", err)
	}
}
