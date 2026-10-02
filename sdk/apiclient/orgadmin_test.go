package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrgAdminPaths(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/events"):
			w.Write([]byte(`{"items":[{"id":"1","actor_kind":"user","actor_label":"a@b.c","action":"user.deactivated"}],"page":{"total":1,"limit":50,"offset":0}}`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/admin"):
			w.Write([]byte(`{"id":"o1","name":"Acme","active":true}`))
		case r.Method == "GET":
			w.Write([]byte(`{"items":[],"page":{"total":0,"limit":50,"offset":0}}`))
		case r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"new-id","verification":{"type":"TXT","name":"_iamkit.acme.io","value":"v"}}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	admin := New(srv.URL, "jwt").Environment("e1").OrgAdmin("o1")

	org, err := admin.Organization(ctx)
	if err != nil || org.Name != "Acme" {
		t.Fatalf("organization = %+v, %v", org, err)
	}
	name := "Acme Inc"
	admin.UpdateSettings(ctx, OrgSettings{Name: &name})
	admin.Members(ctx)
	admin.SetSSOBypass(ctx, "u1", true)
	admin.RemoveMember(ctx, "u1")
	admin.Users(ctx, "locked")
	admin.User(ctx, "u1")
	admin.CreateUser(ctx, CreateOrgUser{Email: "a@b.c", Name: "A"})
	admin.UpdateUser(ctx, "u1", UpdateOrgUser{Name: &name})
	admin.DeactivateUser(ctx, "u1")
	admin.ReactivateUser(ctx, "u1")
	admin.UnlockUser(ctx, "u1")
	admin.Roles(ctx)
	admin.MemberRoles(ctx, "u1")
	admin.AssignRole(ctx, "u1", "r1")
	admin.UnassignRole(ctx, "u1", "r1")
	admin.Invitations(ctx, "pending")
	admin.Invite(ctx, OrgInvite{Email: "a@b.c", RoleIDs: []string{"r1"}})
	admin.ResendInvitation(ctx, "i1")
	admin.RevokeInvitation(ctx, "i1")
	admin.Domains(ctx)
	domain, _ := admin.AddDomain(ctx, "acme.io")
	if domain.Verification.Name != "_iamkit.acme.io" {
		t.Fatalf("domain = %+v", domain)
	}
	admin.VerifyDomain(ctx, "acme.io")
	admin.DeleteDomain(ctx, "acme.io")
	admin.Connections(ctx)
	admin.Connection(ctx, "c1")
	admin.CreateConnection(ctx, OrgConnection{Name: "Okta", ClientSecret: "s"})
	admin.UpdateConnection(ctx, "c1", map[string]any{"enforcement": "required"})
	admin.DisableConnection(ctx, "c1")
	events, err := admin.Events(ctx, "user.")
	if err != nil || len(events) != 1 || events[0].ActorKind != "user" {
		t.Fatalf("events = %+v, %v", events, err)
	}

	base := "/api/v1/environments/e1/organizations/o1/admin"
	want := []string{
		"GET " + base, "PATCH " + base,
		"GET " + base + "/members", "PATCH " + base + "/members/u1", "DELETE " + base + "/members/u1",
		"GET " + base + "/users?state=locked", "GET " + base + "/users/u1", "POST " + base + "/users",
		"PATCH " + base + "/users/u1", "POST " + base + "/users/u1/deactivate", "POST " + base + "/users/u1/reactivate", "POST " + base + "/users/u1/unlock",
		"GET " + base + "/roles", "GET " + base + "/members/u1/roles", "POST " + base + "/role-assignments", "DELETE " + base + "/role-assignments/u1/r1",
		"GET " + base + "/invitations?status=pending", "POST " + base + "/invitations", "POST " + base + "/invitations/i1/resend", "DELETE " + base + "/invitations/i1",
		"GET " + base + "/domains", "POST " + base + "/domains", "POST " + base + "/domains/acme.io/verify", "DELETE " + base + "/domains/acme.io",
		"GET " + base + "/connections", "GET " + base + "/connections/c1", "POST " + base + "/connections", "PATCH " + base + "/connections/c1", "DELETE " + base + "/connections/c1",
		"GET " + base + "/events?action=user.",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}
	if bodies[14] == nil || bodies[14]["user_id"] != "u1" || bodies[14]["role_id"] != "r1" {
		t.Fatalf("assign body = %v", bodies[14])
	}
}

func TestResourceGrantPaths(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		var body strings.Builder
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		body.Write(buf[:n])
		bodies = append(bodies, strings.TrimSpace(body.String()))
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "resource-grants/") {
				w.Write([]byte(`{"id":"g1","resource_id":"r1","organization_id":"o2","role_ids":null}`))
				return
			}
			w.Write([]byte(`{"items":[{"id":"g1","resource_id":"r1","organization_id":"o2","organization_name":"Beta","role_ids":["x"]}],"page":{"total":1,"limit":50,"offset":0}}`))
		case "PUT":
			if strings.HasSuffix(r.URL.Path, "/access") {
				w.WriteHeader(204)
				return
			}
			w.Write([]byte(`{"id":"g1","resource_id":"r1","organization_id":"o2","role_ids":null}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "jwt").Environment("e1")
	owner := "o1"
	if err := env.SetResourceAccess(ctx, "r1", ResourceAccess{OwnerOrganizationID: &owner, RequireGrant: true}); err != nil {
		t.Fatal(err)
	}
	grants, err := env.ResourceGrants(ctx, "r1", "o2")
	if err != nil || len(grants) != 1 || grants[0].OrganizationName != "Beta" {
		t.Fatalf("grants = %+v, %v", grants, err)
	}
	grant, err := env.PutResourceGrant(ctx, ResourceGrant{ResourceID: "r1", OrganizationID: "o2"})
	if err != nil || grant.ID != "g1" || grant.RoleIDs != nil {
		t.Fatalf("grant = %+v, %v", grant, err)
	}
	env.ResourceGrant(ctx, "g1")
	env.DeleteResourceGrant(ctx, "g1")

	admin := env.OrgAdmin("o1")
	admin.Resources(ctx)
	admin.ResourceGrants(ctx, "r1")
	admin.GrantedResources(ctx)
	admin.PutResourceGrant(ctx, ResourceGrant{ResourceID: "r1", OrganizationID: "o2", RoleIDs: []string{"x"}})
	admin.DeleteResourceGrant(ctx, "g1")

	base := "/api/v1/environments/e1/"
	want := []string{
		"PUT " + base + "resources/r1/access",
		"GET " + base + "resource-grants?organization_id=o2&resource_id=r1",
		"PUT " + base + "resource-grants",
		"GET " + base + "resource-grants/g1",
		"DELETE " + base + "resource-grants/g1",
		"GET " + base + "organizations/o1/admin/resources",
		"GET " + base + "organizations/o1/admin/resource-grants?resource_id=r1",
		"GET " + base + "organizations/o1/admin/granted-resources",
		"PUT " + base + "organizations/o1/admin/resource-grants",
		"DELETE " + base + "organizations/o1/admin/resource-grants/g1",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	// A nil role list grants every role: it is sent as null, not omitted.
	if bodies[0] != `{"owner_organization_id":"o1","require_grant":true}` || bodies[2] != `{"resource_id":"r1","organization_id":"o2","role_ids":null}` {
		t.Fatalf("bodies = %q", bodies)
	}
}

func TestOrgBrandingPaths(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(raw)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/branding"):
			w.Write([]byte(`{"organization_id":"o1","display_name":"Acme","logo_url":null,"accent_color":null,"theme":null}`))
		default:
			w.Write([]byte(`{"min_length":16,"custom":true}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	admin := New(srv.URL, "jwt").Environment("e1").OrgAdmin("o1")
	b, err := admin.Branding(ctx)
	if err != nil || *b.DisplayName != "Acme" || b.LogoURL != nil {
		t.Fatalf("branding = %+v, %v", b, err)
	}
	name := "Acme Corp"
	admin.SaveBranding(ctx, OrgBranding{DisplayName: &name})
	admin.DeleteBranding(ctx)
	p, err := admin.PasswordPolicy(ctx)
	if err != nil || p.MinLength != 16 || !p.Custom {
		t.Fatalf("policy = %+v, %v", p, err)
	}
	admin.SetPasswordPolicy(ctx, OrgPasswordRequirements{MinLength: 16})
	admin.DeletePasswordPolicy(ctx)
	base := "/api/v1/environments/e1/organizations/o1/admin/"
	want := []string{"GET " + base + "branding", "PUT " + base + "branding", "DELETE " + base + "branding",
		"GET " + base + "password-policy", "PUT " + base + "password-policy", "DELETE " + base + "password-policy"}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	// Unset fields are sent as null (inherit); an unset theme is omitted.
	if bodies[1] != `{"display_name":"Acme Corp","logo_url":null,"accent_color":null}` {
		t.Fatalf("branding body = %s", bodies[1])
	}
}
