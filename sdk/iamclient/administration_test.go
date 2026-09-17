package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTypedAdministration(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer ik_mgmt_test" {
			t.Error("missing key")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(User{ID: "user-1"})
		} else {
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	env, err := (Client{BaseURL: srv.URL, Key: "ik_mgmt_test"}).Environment("env-1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, err := env.User(ctx, "user-1")
	if err != nil || user.ID != "user-1" {
		t.Fatalf("user: %v %v", user, err)
	}
	if err = env.SetMemberProfile(ctx, "org-1", "user-1", MemberProfile{}); err != nil {
		t.Fatal(err)
	}
	if err = env.DeleteRole(ctx, "../roles"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	if len(paths) != 2 || paths[1] != "PUT /management/v1/environments/env-1/organizations/org-1/members/user-1/profile" {
		t.Fatalf("routes %v", paths)
	}
}
