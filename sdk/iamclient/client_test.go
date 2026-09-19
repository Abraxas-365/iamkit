package iamclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	c := New("http://localhost:8080/", "ik_mgmt_test")
	if c.baseURL != "http://localhost:8080" {
		t.Fatalf("trailing slash not trimmed: %s", c.baseURL)
	}
	if c.key != "ik_mgmt_test" {
		t.Fatal("key not stored")
	}
	if c.http != nil {
		t.Fatal("http should be nil by default")
	}
	custom := &http.Client{}
	c2 := New("http://localhost", "ik_mgmt_x", WithHTTPClient(custom))
	if c2.http != custom {
		t.Fatal("WithHTTPClient not applied")
	}
}

func TestManagementClient(t *testing.T) {
	var calls int
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/management/v1/projects" || r.Header.Get("Authorization") != "Bearer ik_mgmt_test" {
			t.Error("unexpected request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"project"}`))
	}))
	defer remote.Close()
	c := New(remote.URL, "ik_mgmt_test")
	var out map[string]string
	if err := c.Do(context.Background(), "POST", "/projects", map[string]string{"name": "Demo"}, &out); err != nil || out["id"] != "project" {
		t.Fatal(out, err)
	}
	bad := New(remote.URL, "application-token")
	if err := bad.Do(context.Background(), "GET", "/projects", nil, nil); err == nil {
		t.Fatal("application token accepted")
	}
	if calls != 1 {
		t.Fatal("unexpected network request")
	}
}

func TestWorkspaceOps(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "ik_mgmt_test")
	ctx := context.Background()
	c.Me(ctx)
	c.SetPassword(ctx, "newpass123456")
	c.CreateKey(ctx, "720h")
	c.Keys(ctx)
	c.RevokeKey(ctx, "key-1")
	c.Operators(ctx)
	c.Delegate(ctx, "a@b.com", "admin", "never")
	c.DisableOperator(ctx, "op-1")
	c.CreateProject(ctx, "Demo")
	c.Projects(ctx)
	c.CreateEnvironment(ctx, "proj-1", "Production")
	c.Environments(ctx, "proj-1")
	c.Logout(ctx)
	expected := []string{
		"GET /management/v1/me",
		"POST /management/v1/password",
		"POST /management/v1/keys",
		"GET /management/v1/keys",
		"DELETE /management/v1/keys/key-1",
		"GET /management/v1/operators",
		"POST /management/v1/operators",
		"DELETE /management/v1/operators/op-1",
		"POST /management/v1/projects",
		"GET /management/v1/projects",
		"POST /management/v1/projects/proj-1/environments",
		"GET /management/v1/projects/proj-1/environments",
		"DELETE /management/v1/sessions/current",
	}
	if len(paths) != len(expected) {
		t.Fatalf("paths count %d != %d", len(paths), len(expected))
	}
	for i, p := range expected {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], p)
		}
	}
}
