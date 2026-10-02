package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetadataAndProfileEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+" "+strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/metadata/tier"):
			w.Write([]byte(`"gold"`))
		case strings.HasSuffix(r.URL.Path, "/profile"):
			w.Write([]byte(`{"profile":{"department":"eng"}}`))
		case strings.HasSuffix(r.URL.Path, "/user-schema") && r.Method != "DELETE":
			w.Write([]byte(`{"schema":{"type":"object"},"version":2,"non_conforming":3}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	if err := env.SetUserMetadata(ctx, "u1", "tier", "gold"); err != nil {
		t.Fatal(err)
	}
	if value, err := env.UserMetadata(ctx, "u1", "tier"); err != nil || string(value) != `"gold"` {
		t.Fatalf("value %s %v", value, err)
	}
	if err := env.DeleteUserMetadata(ctx, "u1", "tier"); err != nil {
		t.Fatal(err)
	}
	if err := env.SetOrganizationMetadata(ctx, "o1", "region", "eu"); err != nil {
		t.Fatal(err)
	}
	profile, err := env.UpdateUserProfile(ctx, "u1", map[string]any{"department": "eng", "old": nil})
	if err != nil || profile["department"] != "eng" {
		t.Fatalf("profile %v %v", profile, err)
	}
	saved, err := env.SaveUserSchema(ctx, map[string]any{"type": "object"})
	if err != nil || saved.Version != 2 || saved.NonConforming != 3 {
		t.Fatalf("schema %+v %v", saved, err)
	}
	if err := env.DeleteUserSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.SetUserMetadata(ctx, "u1", "../x", 1); err == nil {
		t.Fatal("unsafe key accepted")
	}
	base := "/management/v1/environments/env-1/"
	expected := []string{
		"PUT " + base + `users/u1/metadata/tier "gold"`,
		"GET " + base + "users/u1/metadata/tier ",
		"DELETE " + base + "users/u1/metadata/tier ",
		"PUT " + base + `organizations/o1/metadata/region "eu"`,
		"PATCH " + base + `users/u1/profile {"department":"eng","old":null}`,
		"PUT " + base + `user-schema {"schema":{"type":"object"}}`,
		"DELETE " + base + "user-schema ",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}
