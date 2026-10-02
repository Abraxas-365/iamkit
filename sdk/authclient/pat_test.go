package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchangeAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/identity/v1/token-exchange" || r.Header.Get("Authorization") != "Bearer ik_pat_secret" {
			t.Errorf("unexpected: %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"jwt","token_type":"Bearer","expires_in":900}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	out, err := c.ExchangeAccessToken(context.Background(), "ik_pat_secret")
	if err != nil || out.AccessToken != "jwt" {
		t.Fatalf("exchange = %+v %v", out, err)
	}
	if _, err := c.ExchangeAccessToken(context.Background(), "ik_svc_secret"); err == nil {
		t.Fatal("service account secret accepted")
	}
}
