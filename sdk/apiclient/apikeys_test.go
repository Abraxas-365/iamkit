package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func apiKeyServer(t *testing.T, calls *[]string, bodies *[]map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		call := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		*calls = append(*calls, call)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		*bodies = append(*bodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE" || (r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/api-key-permissions")):
			w.WriteHeader(204)
		case r.Method == "PUT":
			w.Write([]byte(`{"user_keys":false,"organization_keys":true,"max_ttl_days":null,"max_per_user":10,"max_per_organization":50}`))
		case strings.HasSuffix(r.URL.Path, "/api-key-policy"):
			w.Write([]byte(`{"user_keys":true,"organization_keys":true,"max_ttl_days":90,"max_per_user":10,"max_per_organization":50}`))
		case strings.HasSuffix(r.URL.Path, "/options"):
			w.Write([]byte(`{"enabled":true,"max_ttl_days":365,"resources":[{"id":"r1","name":"Orders","audience":"https://orders","permissions":["orders:read"]}]}`))
		case r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"k1","owner":{"type":"organization"},"name":"erp","state":"active","value":"ik_key_secret"}`))
		case strings.HasSuffix(r.URL.Path, "/api-keys"):
			w.Write([]byte(`{"items":[{"id":"k1","owner":{"type":"organization"}}],"page":{"total":1,"limit":20,"offset":0}}`))
		default:
			w.Write([]byte(`{"id":"k1","owner":{"type":"user","user_id":"u1"},"state":"active"}`))
		}
	}))
}

func TestEnvironmentAPIKeys(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := apiKeyServer(t, &calls, &bodies)
	defer srv.Close()
	env := New(srv.URL, "jwt").Environment("e1")
	ctx := context.Background()

	list, err := env.APIKeys(ctx, APIKeyFilter{OwnerType: "organization", State: "active"}, Page{Limit: 2})
	if err != nil || len(list.Items) != 1 || list.Page.Total != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if key, err := env.APIKey(ctx, "k1"); err != nil || key.Owner.UserID != "u1" {
		t.Fatalf("key = %+v %v", key, err)
	}
	issued, err := env.CreateAPIKey(ctx, NewAPIKey{OrganizationID: "o1", ResourceID: "r1", Name: "erp", Permissions: []string{"orders:read"}})
	if err != nil || issued.Value != "ik_key_secret" {
		t.Fatalf("issued = %+v %v", issued, err)
	}
	if _, ok := bodies[2]["expires_in"]; ok {
		t.Fatalf("omitted expires_in must not be sent: %v", bodies[2])
	}
	if err := env.RevokeAPIKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if policy, err := env.APIKeyPolicy(ctx); err != nil || policy.MaxTTLDays == nil || *policy.MaxTTLDays != 90 {
		t.Fatalf("policy = %+v %v", policy, err)
	}
	if saved, err := env.SaveAPIKeyPolicy(ctx, APIKeyPolicyInput{OrganizationKeys: true, MaxPerUser: 10, MaxPerOrganization: 50}); err != nil || saved.UserKeys || saved.MaxTTLDays != nil {
		t.Fatalf("saved = %+v %v", saved, err)
	}
	if v, ok := bodies[5]["max_ttl_days"]; !ok || v != nil {
		t.Fatalf("no cap must be sent as null: %v", bodies[5])
	}
	if err := env.SetResourceAPIKeyPermissions(ctx, "r1", APIKeyPermissions{Organization: []string{"orders:read"}}); err != nil {
		t.Fatal(err)
	}
	if user, ok := bodies[6]["user"].([]any); !ok || len(user) != 0 {
		t.Fatalf("allowlist body = %v", bodies[6])
	}
	if _, err := env.UserAPIKeys(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.CreateMachineAPIKey(ctx, "m1", NewAPIKey{OrganizationID: "o1", ApplicationID: "a1", ResourceID: "r1", Name: "ci", ExpiresIn: "720h"}); err != nil {
		t.Fatal(err)
	}
	if err := env.RevokeUserAPIKey(ctx, "m1", "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.APIKey(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/api/v1/environments/e1/"
	expected := []string{
		"GET " + base + "api-keys?limit=2&owner_type=organization&state=active",
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

func TestOrgAdminAPIKeys(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := apiKeyServer(t, &calls, &bodies)
	defer srv.Close()
	admin := New(srv.URL, "jwt").Environment("e1").OrgAdmin("o1")
	ctx := context.Background()

	if list, err := admin.APIKeys(ctx, APIKeyFilter{OwnerType: "user", OrganizationID: "ignored"}, Page{}); err != nil || len(list.Items) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if options, err := admin.APIKeyOptions(ctx); err != nil || !options.Enabled || len(options.Resources) != 1 || *options.MaxTTLDays != 365 {
		t.Fatalf("options = %+v %v", options, err)
	}
	if _, err := admin.APIKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	issued, err := admin.CreateAPIKey(ctx, NewAPIKey{ResourceID: "r1", Name: "erp", Permissions: []string{"orders:read"}, ExpiresIn: "720h"})
	if err != nil || issued.Value != "ik_key_secret" {
		t.Fatalf("issued = %+v %v", issued, err)
	}
	if bodies[3]["organization_id"] != "o1" {
		t.Fatalf("create body must default to the administered organization: %v", bodies[3])
	}
	if err := admin.RevokeAPIKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := admin.RevokeAPIKey(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/api/v1/environments/e1/organizations/o1/admin/"
	expected := []string{
		"GET " + base + "api-keys?owner_type=user",
		"GET " + base + "api-keys/options",
		"GET " + base + "api-keys/k1",
		"POST " + base + "api-keys",
		"DELETE " + base + "api-keys/k1",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}
