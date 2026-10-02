package iamclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrganizationBrandingEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte(`{"organization_id":"o1","display_name":"Acme","logo_url":null,"accent_color":"#aa0000","theme":{"mode":"dark"},"updated_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	b, err := env.OrganizationBranding(ctx, "o1")
	if err != nil || *b.DisplayName != "Acme" || b.LogoURL != nil || *b.AccentColor != "#aa0000" || !strings.Contains(string(b.Theme), "dark") {
		t.Fatalf("branding = %+v %v", b, err)
	}
	// Read-only fields are not sent back; nil fields go as null (inherit).
	b.Theme = json.RawMessage(`{"mode":"light"}`)
	if _, err := env.SetOrganizationBranding(ctx, "o1", b); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteOrganizationBranding(ctx, "o1"); err != nil {
		t.Fatal(err)
	}
	path := "/management/v1/environments/env-1/login-settings/organizations/o1"
	if want := []string{"GET " + path, "PUT " + path, "DELETE " + path}; strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if want := `{"display_name":"Acme","logo_url":null,"accent_color":"#aa0000","theme":{"mode":"light"}}`; bodies[1] != want {
		t.Fatalf("body = %s", bodies[1])
	}
}
