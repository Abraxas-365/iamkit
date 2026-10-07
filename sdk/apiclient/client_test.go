package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	env.UpdateUser(ctx, "u1", UserPatch{})
	env.SuspendUser(ctx, "u1")
	env.UnlockUser(ctx, "u1")

	// Organizations
	env.CreateOrganization(ctx, "Acme")
	env.Organizations(ctx)
	env.Organization(ctx, "o1")
	env.UpdateOrganization(ctx, "o1", OrganizationPatch{})

	// Members
	env.AddMember(ctx, Membership{OrganizationID: "o1", UserID: "u1"})
	env.Members(ctx, "o1")
	env.RemoveMember(ctx, "o1", "u1")

	// Applications
	env.CreateApplication(ctx, Application{Name: "App"})
	env.Applications(ctx)
	env.Application(ctx, "a1")
	env.UpdateApplication(ctx, "a1", ApplicationPatch{})

	// Resources
	env.CreateResource(ctx, Resource{Name: "R"})
	env.Resources(ctx)
	env.Resource(ctx, "r1")
	env.UpdateResource(ctx, "r1", ResourcePatch{})
	env.BindResource(ctx, "a1", "r1")
	env.UnbindResource(ctx, "a1", "r1")
	env.ApplicationResources(ctx, "a1")

	// Roles
	env.Roles(ctx)
	env.CreateRole(ctx, Role{Name: "Admin"})
	env.UpdateRole(ctx, "role1", Role{Name: "Admin"})
	env.DeleteRole(ctx, "role1")
	env.AssignRole(ctx, RoleAssignment{})
	env.RoleAssignments(ctx)
	env.UnassignRole(ctx, RoleAssignment{RoleID: "role1", OrganizationID: "o1", UserID: "u1"})

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
	env.DeliveryStatus(ctx)
	env.TestDelivery(ctx, "ops@example.com")
	env.PreviewDelivery(ctx, DeliveryPreview{Purpose: EmailLogin, Locale: "es"})
	env.PreviewDelivery(ctx, DeliveryPreview{Purpose: EmailLogin, Template: &EmailCopy{Subject: "Hola"}})
	env.EmailTemplates(ctx)
	env.EmailTemplate(ctx, EmailLogin, "es")
	env.SetEmailTemplate(ctx, EmailLogin, "es", EmailCopy{Subject: "Hola"})
	env.ResetEmailTemplate(ctx, EmailLogin, "es")

	expected := []string{
		// Users
		"POST /api/v1/environments/env-1/users",
		"GET /api/v1/environments/env-1/users",
		"GET /api/v1/environments/env-1/users/u1",
		"PATCH /api/v1/environments/env-1/users/u1",
		"DELETE /api/v1/environments/env-1/users/u1",
		"POST /api/v1/environments/env-1/users/u1/unlock",
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
		"GET /api/v1/environments/env-1/delivery/status",
		"POST /api/v1/environments/env-1/delivery/test",
		"GET /api/v1/environments/env-1/delivery/preview",
		"POST /api/v1/environments/env-1/delivery/preview",
		"GET /api/v1/environments/env-1/delivery/templates",
		"GET /api/v1/environments/env-1/delivery/templates/login/es",
		"PUT /api/v1/environments/env-1/delivery/templates/login/es",
		"DELETE /api/v1/environments/env-1/delivery/templates/login/es",
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

func TestListsDecodeEnvelopeAndStates(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte(`{"items":[{"id":"u1","email":"a@b.com","name":"A","active":true,"state":"locked"}],"page":{"total":1,"limit":20,"offset":0}}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "jwt").Environment("env-1")
	users, err := env.Users(ctx)
	if err != nil || len(users) != 1 || users[0].State != "locked" {
		t.Fatalf("users = %+v %v", users, err)
	}
	if users, err = env.UsersInState(ctx, "locked"); err != nil || len(users) != 1 {
		t.Fatalf("in state = %+v %v", users, err)
	}
	if env.DeactivateUser(ctx, "u1") != nil || env.ReactivateUser(ctx, "u1") != nil {
		t.Fatal("state change failed")
	}
	want := "GET /api/v1/environments/env-1/users\nGET /api/v1/environments/env-1/users?state=locked\nPOST /api/v1/environments/env-1/users/u1/deactivate\nPOST /api/v1/environments/env-1/users/u1/reactivate"
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("calls:\n%s", got)
	}
}
