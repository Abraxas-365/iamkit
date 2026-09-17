package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthClient(t *testing.T) {
	verifier, challenge, err := NewPKCE()
	if err != nil || len(verifier) != 43 || len(challenge) != 43 {
		t.Fatalf("PKCE %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			t.Error("client authentication")
		}
		if r.Form.Get("code") == "bad" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		if r.URL.Path == "/oauth/revoke" {
			return
		}
		json.NewEncoder(w).Encode(OAuthTokens{TokenPair: TokenPair{AccessToken: "token"}})
	}))
	defer srv.Close()
	client := OAuthClient{BaseURL: srv.URL, ClientID: "client", ClientSecret: "secret"}
	pair, err := client.Exchange(context.Background(), "code", "https://app.example/cb", verifier)
	if err != nil || pair.AccessToken != "token" {
		t.Fatalf("exchange %v", err)
	}
	_, err = client.Exchange(context.Background(), "bad", "https://app.example/cb", verifier)
	var custom *OAuthError
	if !errors.As(err, &custom) || custom.Code != "invalid_grant" {
		t.Fatalf("error %v", err)
	}
	if err = client.Revoke(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
}
