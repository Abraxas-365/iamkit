package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIKeys(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/api-key-permissions"):
			w.WriteHeader(204)
		case r.Method == "PUT":
			w.Write([]byte(`{"user_keys":true,"organization_keys":false,"max_ttl_days":30,"max_per_user":10,"max_per_organization":50,"updated_at":"2026-10-01T00:00:00Z"}`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/api-key-policy"):
			w.Write([]byte(`{"user_keys":true,"organization_keys":true,"max_ttl_days":null,"max_per_user":10,"max_per_organization":50,"updated_at":"2026-10-01T00:00:00Z"}`))
		case r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"k1","owner":{"type":"organization"},"organization_id":"o1","resource_id":"r1","name":"erp","permissions":["orders:read"],"obfuscated_value":"ik_key_…abcd","expires":false,"state":"active","created_by":{"kind":"operator","id":"op"},"value":"ik_key_secret"}`))
		case strings.HasSuffix(r.URL.Path, "/api-keys"):
			w.Write([]byte(`{"items":[{"id":"k1","owner":{"type":"user","user_id":"u1"},"state":"revoked"}],"page":{"total":1,"limit":20,"offset":0}}`))
		default:
			w.Write([]byte(`{"id":"k1","owner":{"type":"organization"},"expires_at":"2027-01-01T00:00:00Z","expires":true,"state":"active"}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	list, err := env.APIKeys(ctx, APIKeyFilter{OwnerType: "user", OrganizationID: "o1", UserID: "u1", ResourceID: "r1", State: "revoked"}, Page{Limit: 5, Offset: 10})
	if err != nil || len(list.Items) != 1 || list.Items[0].Owner.UserID != "u1" || list.Page.Total != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	key, err := env.APIKey(ctx, "k1")
	if err != nil || !key.Expires || key.ExpiresAt.Year() != 2027 || key.State != APIKeyActive {
		t.Fatalf("key = %+v %v", key, err)
	}
	issued, err := env.CreateAPIKey(ctx, NewAPIKey{OrganizationID: "o1", ResourceID: "r1", Name: "erp", Permissions: []string{"orders:read"}, ExpiresIn: "never"})
	if err != nil || issued.Value != "ik_key_secret" || issued.ID != "k1" || issued.CreatedBy.Kind != "operator" {
		t.Fatalf("issued = %+v %v", issued, err)
	}
	if bodies[2]["expires_in"] != "never" || bodies[2]["application_id"] != nil {
		t.Fatalf("create body = %v", bodies[2])
	}
	if err := env.RevokeAPIKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	policy, err := env.APIKeyPolicy(ctx)
	if err != nil || !policy.OrganizationKeys || policy.MaxTTLDays != nil || policy.MaxPerUser != 10 {
		t.Fatalf("policy = %+v %v", policy, err)
	}
	ttl := 30
	saved, err := env.SaveAPIKeyPolicy(ctx, APIKeyPolicyInput{UserKeys: true, MaxTTLDays: &ttl, MaxPerUser: 10, MaxPerOrganization: 50})
	if err != nil || saved.MaxTTLDays == nil || *saved.MaxTTLDays != 30 {
		t.Fatalf("saved = %+v %v", saved, err)
	}
	if v, ok := bodies[5]["max_ttl_days"]; !ok || v != float64(30) || bodies[5]["organization_keys"] != false {
		t.Fatalf("policy body = %v", bodies[5])
	}
	if err := env.SetResourceAPIKeyPermissions(ctx, "r1", APIKeyPermissions{User: []string{"orders:read"}}); err != nil {
		t.Fatal(err)
	}
	if org, ok := bodies[6]["organization"].([]any); !ok || len(org) != 0 {
		t.Fatalf("allowlist body must send empty lists, got %v", bodies[6])
	}
	if _, err := env.UserAPIKeys(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.CreateMachineAPIKey(ctx, "m1", NewAPIKey{OrganizationID: "o1", ApplicationID: "a1", ResourceID: "r1", Name: "ci"}); err != nil {
		t.Fatal(err)
	}
	if err := env.RevokeUserAPIKey(ctx, "m1", "k1"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func() error{
		func() error { _, err := env.APIKey(ctx, "../x"); return err },
		func() error { return env.RevokeAPIKey(ctx, "a/b") },
		func() error { return env.RevokeUserAPIKey(ctx, "m1", "..") },
		func() error { _, err := env.UserAPIKeys(ctx, "a?b"); return err },
	} {
		if bad() == nil {
			t.Fatal("unsafe segment accepted")
		}
	}
	base := "/management/v1/environments/env-1/"
	expected := []string{
		"GET " + base + "api-keys?limit=5&offset=10&organization_id=o1&owner_type=user&resource_id=r1&state=revoked&user_id=u1",
		"GET " + base + "api-keys/k1",
		"POST " + base + "api-keys",
		"DELETE " + base + "api-keys/k1",
		"GET " + base + "api-key-policy",
		"PUT " + base + "api-key-policy",
		"PUT " + base + "resources/r1/api-key-permissions",
		"GET " + base + "users/u1/api-keys",
		"POST " + base + "users/m1/api-keys",
		"DELETE " + base + "users/m1/api-keys/k1",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}

func TestResourceAPIKeyPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"r1","name":"Orders","audience":"https://orders","permissions":["orders:read"],"api_key_permissions":{"user":["orders:read"],"organization":[]}}`))
	}))
	defer srv.Close()
	resource, err := New(srv.URL, "ik_mgmt_test").Environment("env-1").Resource(context.Background(), "r1")
	if err != nil || resource.APIKeyPermissions == nil || len(resource.APIKeyPermissions.User) != 1 || len(resource.APIKeyPermissions.Organization) != 0 {
		t.Fatalf("resource = %+v %v", resource, err)
	}
}
