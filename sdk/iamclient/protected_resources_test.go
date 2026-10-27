package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtectedResources(t *testing.T) {
	var seen []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		switch r.Method + " " + r.URL.Path {
		case "POST /management/v1/environments/env/protected-resources":
			if in["resource_id"] != "r1" || in["name"] != "Notes" || in["idle_ttl_seconds"] != nil {
				t.Errorf("create body = %v", in)
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"p1","uri":"https://mcp.example/mcp","default_scopes":["notes:read"],"idle_ttl_seconds":604800,"active":true}`))
		case "PATCH /management/v1/environments/env/protected-resources/p1":
			if in["active"] != false || len(in) != 1 {
				t.Errorf("update body = %v", in)
			}
			w.Write([]byte(`{"id":"p1","active":false}`))
		case "GET /management/v1/environments/env/protected-resources":
			w.Write([]byte(`{"items":[{"id":"p1"}],"page":{"total":1}}`))
		case "PUT /management/v1/environments/env/protected-resource-policy":
			w.Write([]byte(`{"max_idle_ttl_seconds":600,"max_lifetime_ttl_seconds":7200}`))
		case "DELETE /management/v1/environments/env/protected-resources/p1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()
	created, err := env.CreateProtectedResource(ctx, ProtectedResourceCreate{ApplicationID: "a1", ResourceID: "r1", Name: "Notes", DefaultScopes: []string{"notes:read"}})
	if err != nil || created.URI != "https://mcp.example/mcp" || created.IdleTTLSeconds != 604800 {
		t.Fatalf("create = %+v %v", created, err)
	}
	off := false
	if updated, err := env.UpdateProtectedResource(ctx, "p1", ProtectedResourceUpdate{Active: &off}); err != nil || updated.Active {
		t.Fatalf("update = %+v %v", updated, err)
	}
	if all, err := env.ProtectedResources(ctx); err != nil || len(all) != 1 {
		t.Fatalf("list = %+v %v", all, err)
	}
	if policy, err := env.SetProtectedResourcePolicy(ctx, ProtectedResourcePolicy{MaxIdleTTLSeconds: 600, MaxLifetimeTTLSeconds: 7200}); err != nil || policy.MaxIdleTTLSeconds != 600 {
		t.Fatalf("policy = %+v %v", policy, err)
	}
	if err := env.DeleteProtectedResource(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ProtectedResource(ctx, "../x"); err == nil {
		t.Fatal("unsafe id accepted")
	}
	if len(seen) != 5 {
		t.Fatalf("requests = %v", seen)
	}
}
