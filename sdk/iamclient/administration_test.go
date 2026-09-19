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
	c := New(srv.URL, "ik_mgmt_test")
	env := c.Environment("env-1")
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

func TestEnvironmentMissingEndpoints(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "ik_mgmt_test")
	env := c.Environment("env-1")
	ctx := context.Background()

	// Test previously missing endpoints
	env.UnbindResource(ctx, "app-1", "res-1")
	env.ApplicationResources(ctx, "app-1")
	env.FederationConnections(ctx)
	env.FederationConnection(ctx, "conn-1")
	env.FederationIdentities(ctx, "conn-1")
	env.UnlinkExternalIdentity(ctx, "conn-1", "user-1")
	env.ProvisioningCredentials(ctx)
	env.OAuthClients(ctx)
	env.RoleAssignments(ctx)
	env.Grant(ctx, "grant-1")
	env.DeleteGrant(ctx, "grant-1")
	env.UnassignRole(ctx, RoleAssignment{RoleID: "r1", OrganizationID: "o1", UserID: "u1"})

	expected := []string{
		"DELETE /management/v1/environments/env-1/application-resources/app-1/res-1",
		"GET /management/v1/environments/env-1/applications/app-1/resources",
		"GET /management/v1/environments/env-1/federation-connections",
		"GET /management/v1/environments/env-1/federation-connections/conn-1",
		"GET /management/v1/environments/env-1/federation-connections/conn-1/identities",
		"DELETE /management/v1/environments/env-1/external-identities/conn-1/user-1",
		"GET /management/v1/environments/env-1/provisioning-credentials",
		"GET /management/v1/environments/env-1/oauth-clients",
		"GET /management/v1/environments/env-1/role-assignments",
		"GET /management/v1/environments/env-1/grants/grant-1",
		"DELETE /management/v1/environments/env-1/grants/grant-1",
		"DELETE /management/v1/environments/env-1/role-assignments/r1/o1/u1",
	}
	if len(paths) != len(expected) {
		t.Fatalf("paths count %d != %d: %v", len(paths), len(expected), paths)
	}
	for i, p := range expected {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], p)
		}
	}
}
