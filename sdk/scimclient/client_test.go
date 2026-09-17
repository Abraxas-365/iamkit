package scimclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestProvisioningClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ik_scim_test" {
			t.Error("missing scoped credential")
		}
		if r.URL.Path == "/scim/v2/Users/missing" {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]string{"detail": "not found"})
			return
		}
		json.NewEncoder(w).Encode(User{ID: "user-1", UserName: "a@example.com"})
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, Secret: "ik_scim_test"}
	ctx := context.Background()
	u, err := c.Create(ctx, User{UserName: "a@example.com"})
	if err != nil || u.ID != "user-1" {
		t.Fatalf("create %v %v", u, err)
	}
	_, err = c.Get(ctx, "missing")
	var custom *apierror.Error
	if !errors.As(err, &custom) || custom.HTTPStatus != 404 {
		t.Fatalf("error: %v", err)
	}
	if _, err = c.Get(ctx, "../x"); err == nil {
		t.Fatal("unsafe path")
	}
	c.Secret = "ik_mgmt_wrong"
	if _, err = c.Get(ctx, "user-1"); err == nil {
		t.Fatal("management credential accepted")
	}
}
