package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientGrantsAndConnectedApps(t *testing.T) {
	var calls []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		switch r.Method + " " + r.URL.Path {
		case "GET /management/v1/environments/env/protected-resources/p1/clients/c1/grants":
			w.Write([]byte(`{"items":[{"id":"g1","client_id":"c1","protected_resource_id":"p1","organization_id":null,"scopes":["notes:read"],"expires_at":null,"revoked_at":"2026-01-02T03:04:05Z","revoked_reason":"admin"}]}`))
		case "PUT /management/v1/environments/env/protected-resources/p1/clients/c1/grants":
			scopes, _ := in["scopes"].([]any)
			if len(scopes) != 1 || in["organization_id"] != "o1" || in["expires_at"] != "2030-01-01T00:00:00Z" {
				t.Errorf("grant body = %v", in)
			}
			w.Write([]byte(`{"id":"g1","client_id":"c1","scopes":["notes:read"],"organization_id":"o1"}`))
		case "DELETE /management/v1/environments/env/protected-resources/p1/clients/c1/grants/g1":
			w.WriteHeader(http.StatusNoContent)
		case "GET /management/v1/environments/env/users/u1/connected-apps":
			w.Write([]byte(`{"items":[{"client":{"id":"c1","client_id":"https://claude.ai/m.json","name":"Claude","host":"claude.ai"},"scopes":["notes:read"],"active_sessions":2,"consented_at":null,"last_used_at":null}]}`))
		case "DELETE /management/v1/environments/env/users/u1/connected-apps/c1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()

	grants, err := env.ClientGrants(ctx, "p1", "c1", true)
	if err != nil || len(grants) != 1 || grants[0].OrganizationID != nil || grants[0].RevokedAt == nil || grants[0].RevokedReason != "admin" {
		t.Fatalf("grants = %+v %v", grants, err)
	}
	org := "o1"
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	grant, err := env.GrantClient(ctx, "p1", "c1", ClientGrantInput{Scopes: []string{"notes:read"}, OrganizationID: &org, ExpiresAt: &until})
	if err != nil || grant.ID != "g1" || *grant.OrganizationID != "o1" {
		t.Fatalf("grant = %+v %v", grant, err)
	}
	if err := env.RevokeClientGrant(ctx, "p1", "c1", "g1"); err != nil {
		t.Fatal(err)
	}
	apps, err := env.UserConnectedApps(ctx, "u1", "o1")
	if err != nil || len(apps) != 1 || apps[0].Client.Host != "claude.ai" || apps[0].ActiveSessions != 2 {
		t.Fatalf("apps = %+v %v", apps, err)
	}
	if err := env.DisconnectUserApp(ctx, "u1", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ClientGrants(ctx, "../p", "c1", false); err == nil {
		t.Fatal("unsafe id accepted")
	}
	want := []string{
		"GET /management/v1/environments/env/protected-resources/p1/clients/c1/grants?revoked=true",
		"PUT /management/v1/environments/env/protected-resources/p1/clients/c1/grants",
		"DELETE /management/v1/environments/env/protected-resources/p1/clients/c1/grants/g1",
		"GET /management/v1/environments/env/users/u1/connected-apps?organization_id=o1",
		"DELETE /management/v1/environments/env/users/u1/connected-apps/c1",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
}

func TestConsentFields(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		b, _ := json.Marshal(in)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/management/v1/environments/env/protected-resources":
			w.Write([]byte(`{"id":"p1","consent_mode":"admin_granted","access_token_ttl_seconds":900}`))
		case "/management/v1/environments/env/protected-resource-policy":
			w.Write([]byte(`{"consent_ui":"custom"}`))
		default:
			w.Write([]byte(`{"id":"c-1","consent_policy":"required"}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()
	p, err := env.CreateProtectedResource(ctx, ProtectedResourceCreate{ApplicationID: "a", ResourceID: "r", Name: "n", ConsentMode: ConsentModeAdminGranted, AccessTokenTTLSeconds: 900})
	if err != nil || p.ConsentMode != ConsentModeAdminGranted || p.AccessTokenTTLSeconds != 900 {
		t.Fatalf("create = %+v %v", p, err)
	}
	mode, ttl := ConsentModePerUser, int64(600)
	if _, err = env.UpdateProtectedResource(ctx, "p1", ProtectedResourceUpdate{ConsentMode: &mode, AccessTokenTTLSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	policy, err := env.SetProtectedResourcePolicy(ctx, ProtectedResourcePolicy{MaxIdleTTLSeconds: 600, MaxLifetimeTTLSeconds: 7200, ConsentUI: ConsentUICustom})
	if err != nil || policy.ConsentUI != ConsentUICustom {
		t.Fatalf("policy = %+v %v", policy, err)
	}
	if _, err = env.CreateOAuthClient(ctx, OAuthClient{ApplicationID: "a", ResourceID: "r", RedirectURIs: []string{"https://x"}, ConsentPolicy: ConsentRequired}); err != nil {
		t.Fatal(err)
	}
	policyValue := ConsentSkip
	if err = env.UpdateOAuthClient(ctx, "c-1", OAuthClientPatch{ConsentPolicy: &policyValue}); err != nil {
		t.Fatal(err)
	}
	if view, err := env.OAuthClient(ctx, "c-1"); err != nil || view.ConsentPolicy != ConsentRequired {
		t.Fatalf("view = %+v %v", view, err)
	}
	for i, want := range []string{`"consent_mode":"admin_granted"`, `"access_token_ttl_seconds":900`, `"consent_mode":"per_user"`, `"consent_ui":"custom"`, `"consent_policy":"required"`, `{"consent_policy":"skip"}`} {
		idx := []int{0, 0, 1, 2, 3, 4}[i]
		if !strings.Contains(got[idx], want) {
			t.Errorf("request %d = %s, want %s", idx, got[idx], want)
		}
	}
}
