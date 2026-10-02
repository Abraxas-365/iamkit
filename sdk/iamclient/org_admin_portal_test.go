package iamclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOrgAdminPortalEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "DELETE":
			w.WriteHeader(204)
		case "PUT":
			w.Write([]byte(`{"enabled":true,"client_id":"c1","application_id":"a1","url":"https://iam.example/org-admin/env-1"}`))
		default:
			w.Write([]byte(`{"enabled":false}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	portal, err := env.OrgAdminPortal(ctx)
	if err != nil || portal.Enabled || portal.URL != "" {
		t.Fatalf("portal = %+v %v", portal, err)
	}
	portal, err = env.EnableOrgAdminPortal(ctx)
	if err != nil || !portal.Enabled || portal.ClientID != "c1" || portal.URL != "https://iam.example/org-admin/env-1" {
		t.Fatalf("enabled = %+v %v", portal, err)
	}
	if err := env.DisableOrgAdminPortal(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /management/v1/environments/env-1/org-admin-portal",
		"PUT /management/v1/environments/env-1/org-admin-portal",
		"DELETE /management/v1/environments/env-1/org-admin-portal",
	}
	for i, c := range want {
		if calls[i] != c {
			t.Fatalf("call %d = %s, want %s", i, calls[i], c)
		}
	}
}
