package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestNew(t *testing.T) {
	c := New("http://localhost:8080/", "jwt-token")
	if c.baseURL != "http://localhost:8080" {
		t.Fatalf("trailing slash not trimmed: %s", c.baseURL)
	}
	custom := &http.Client{}
	c2 := New("http://localhost", "tok", WithHTTPClient(custom))
	if c2.http != custom {
		t.Fatal("WithHTTPClient not applied")
	}
}

func TestSetToken(t *testing.T) {
	c := New("http://localhost", "old")
	c.SetToken("new")
	if c.token != "new" {
		t.Fatalf("expected new, got %s", c.token)
	}
}

func TestEmptyToken(t *testing.T) {
	c := New("http://localhost", "")
	err := c.Do(context.Background(), "GET", "/test", nil, nil)
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 401 {
		t.Fatalf("expected 401 for empty token, got %v", err)
	}
}

func TestBearerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer my-jwt" {
			t.Errorf("expected Bearer my-jwt, got %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "my-jwt")
	c.Do(context.Background(), "GET", "/test", nil, nil)
}

func TestAPIRefusesRedirects(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	c := New(source.URL, "jwt")
	err := c.Do(context.Background(), "GET", "/test", nil, nil)
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		// redirect gives an HTTP error, not a typed error — that's fine
	}
	if leaked {
		t.Fatal("followed credential redirect")
	}
}

func TestTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"code":"FORBIDDEN","message":"insufficient permissions","type":"AUTHORIZATION","http_status":403}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "jwt")
	err := c.Do(context.Background(), "GET", "/test", nil, nil)
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "FORBIDDEN" || apiErr.HTTPStatus != 403 {
		t.Fatalf("expected typed FORBIDDEN error, got %v", err)
	}
}

func TestAllAPIPaths(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" || r.Method == "PUT" || r.Method == "PATCH" {
			w.WriteHeader(204)
		} else if r.Method == "POST" {
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"new-id"}`))
		} else {
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "jwt").Environment("env-1")

	// Users
	env.CreateUser(ctx, CreateUser{Email: "a@b.com", Name: "A"})
	env.Users(ctx)
	env.User(ctx, "u1")
	env.UpdateUser(ctx, "u1", UpdateUser{})
	env.SuspendUser(ctx, "u1")

	// Organizations
	env.CreateOrganization(ctx, "Acme")
	env.Organizations(ctx)
	env.Organization(ctx, "o1")
	env.UpdateOrganization(ctx, "o1", nil)

	// Members
	env.AddMember(ctx, Membership{OrganizationID: "o1", UserID: "u1"})
	env.Members(ctx, "o1")
	env.RemoveMember(ctx, "o1", "u1")

	// Applications
	env.CreateApplication(ctx, Application{Name: "App"})
	env.Applications(ctx)
	env.Application(ctx, "a1")
	env.UpdateApplication(ctx, "a1", nil)

	// Resources
	env.CreateResource(ctx, Resource{Name: "R"})
	env.Resources(ctx)
	env.Resource(ctx, "r1")
	env.UpdateResource(ctx, "r1", nil)
	env.BindResource(ctx, "a1", "r1")
	env.UnbindResource(ctx, "a1", "r1")
	env.ResourcesByApplication(ctx, "a1")

	// Roles
	env.Roles(ctx)
	env.CreateRole(ctx, Role{Name: "Admin"})
	env.UpdateRole(ctx, "role1", Role{Name: "Admin"})
	env.DeleteRole(ctx, "role1")
	env.AssignRole(ctx, RoleAssignment{})
	env.RoleAssignments(ctx)
	env.UnassignRole(ctx, "role1", "o1", "u1")

	// Grants
	env.Grants(ctx)
	env.PutGrant(ctx, Grant{})
	env.DeleteGrant(ctx, "g1")

	// Service Accounts
	env.CreateServiceAccount(ctx, ServiceAccount{Name: "Bot"})
	env.ServiceAccounts(ctx)
	env.RevokeServiceAccount(ctx, "sa1")

	// Delivery Config
	env.DeliveryConfig(ctx)
	env.SetDeliveryConfig(ctx, SetDeliveryConfig{WebhookURL: "https://example.com/hook", WebhookToken: "tok"})
	env.DeleteDeliveryConfig(ctx)

	expected := []string{
		// Users
		"POST /api/v1/environments/env-1/users",
		"GET /api/v1/environments/env-1/users",
		"GET /api/v1/environments/env-1/users/u1",
		"PATCH /api/v1/environments/env-1/users/u1",
		"DELETE /api/v1/environments/env-1/users/u1",
		// Organizations
		"POST /api/v1/environments/env-1/organizations",
		"GET /api/v1/environments/env-1/organizations",
		"GET /api/v1/environments/env-1/organizations/o1",
		"PATCH /api/v1/environments/env-1/organizations/o1",
		// Members
		"POST /api/v1/environments/env-1/memberships",
		"GET /api/v1/environments/env-1/organizations/o1/members",
		"DELETE /api/v1/environments/env-1/organizations/o1/members/u1",
		// Applications
		"POST /api/v1/environments/env-1/applications",
		"GET /api/v1/environments/env-1/applications",
		"GET /api/v1/environments/env-1/applications/a1",
		"PATCH /api/v1/environments/env-1/applications/a1",
		// Resources
		"POST /api/v1/environments/env-1/resources",
		"GET /api/v1/environments/env-1/resources",
		"GET /api/v1/environments/env-1/resources/r1",
		"PUT /api/v1/environments/env-1/resources/r1",
		"POST /api/v1/environments/env-1/application-resources",
		"DELETE /api/v1/environments/env-1/application-resources/a1/r1",
		"GET /api/v1/environments/env-1/applications/a1/resources",
		// Roles
		"GET /api/v1/environments/env-1/roles",
		"POST /api/v1/environments/env-1/roles",
		"PUT /api/v1/environments/env-1/roles/role1",
		"DELETE /api/v1/environments/env-1/roles/role1",
		"POST /api/v1/environments/env-1/role-assignments",
		"GET /api/v1/environments/env-1/role-assignments",
		"DELETE /api/v1/environments/env-1/role-assignments/role1/o1/u1",
		// Grants
		"GET /api/v1/environments/env-1/grants",
		"PUT /api/v1/environments/env-1/grants",
		"DELETE /api/v1/environments/env-1/grants/g1",
		// Service Accounts
		"POST /api/v1/environments/env-1/service-accounts",
		"GET /api/v1/environments/env-1/service-accounts",
		"DELETE /api/v1/environments/env-1/service-accounts/sa1",
		// Delivery Config
		"GET /api/v1/environments/env-1/delivery",
		"PUT /api/v1/environments/env-1/delivery",
		"DELETE /api/v1/environments/env-1/delivery",
	}
	if len(paths) != len(expected) {
		t.Fatalf("paths count %d != %d:\n  got:  %v\n  want: %v", len(paths), len(expected), paths, expected)
	}
	for i, p := range expected {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], p)
		}
	}
}
