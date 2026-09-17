package authclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestClientCustomError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/v1/login" {
			t.Error("wrong path")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"code":"AUTHORIZATION","message":"invalid credential","type":"AUTHORIZATION","http_status":401}}`))
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL}).Login(context.Background(), PasswordLogin{})
	var custom *apierror.Error
	if !errors.As(err, &custom) || custom.Code != "AUTHORIZATION" || custom.HTTPStatus != 401 {
		t.Fatalf("expected typed error: %v", err)
	}
}
func TestIdentityClientRefusesRedirects(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	_, err := (Client{BaseURL: source.URL}).MachineToken(context.Background(), "ik_svc_secret")
	if err == nil || leaked {
		t.Fatal("followed credential redirect")
	}
}
