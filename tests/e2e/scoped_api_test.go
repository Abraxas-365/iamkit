package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// scopedToken returns a machine token for the environment's IAM resource
// holding exactly permissions.
func (e *Env) scopedToken(permissions ...string) string {
	e.t.Helper()
	iam := e.IAMResource()
	var linked bool
	if err := e.DB.Get(&linked, `SELECT EXISTS(SELECT 1 FROM application_resources WHERE application_id=$1 AND resource_id=$2)`, e.Client, iam); err != nil {
		e.t.Fatal(err)
	}
	if !linked {
		e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	}
	sa := e.Must("POST", e.Base+"/service-accounts", e.Owner, fiber.Map{"name": "scoped-" + strings.Join(permissions, "-"), "application_id": e.Client, "resource_id": iam, "permissions": permissions}, 201).JSON
	return e.Must("POST", "/identity/v1/machine-token", sa["secret"].(string), nil, 200).JSON["access_token"].(string)
}

// TestScopedAPIEnvironmentIsolation: a token of one environment is refused
// on every /api/v1 route family of another environment, even with the
// matching permission, and still works in its own environment.
func TestScopedAPIEnvironmentIsolation(t *testing.T) {
	a := newEnv(t)
	project := a.ID("POST", "/management/v1/projects", fiber.Map{"name": "Other"})
	other := a.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "staging"})
	otherBase := "/management/v1/environments/" + other
	otherOrg := a.ID("POST", otherBase+"/organizations", fiber.Map{"name": "Globex"})
	otherUser := a.ID("POST", otherBase+"/users", fiber.Map{"name": "Bob", "email": "bob@example.com", "password": a.Pass})

	all := []string{"iam:users:read", "iam:users:write", "iam:orgs:read", "iam:orgs:write", "iam:members:read", "iam:members:write",
		"iam:apps:read", "iam:apps:write", "iam:resources:read", "iam:resources:write", "iam:roles:read", "iam:roles:write",
		"iam:grants:read", "iam:grants:write", "iam:service-accounts:read", "iam:service-accounts:write", "iam:delivery:read", "iam:delivery:write"}
	token := a.scopedToken(all...)

	api := "/api/v1/environments/" + other
	for _, r := range []struct{ method, path string }{
		{"GET", "/users"},
		{"GET", "/users/" + otherUser},
		{"PATCH", "/users/" + otherUser},
		{"DELETE", "/users/" + otherUser},
		{"GET", "/organizations"},
		{"GET", "/organizations/" + otherOrg},
		{"POST", "/organizations"},
		{"POST", "/memberships"},
		{"GET", "/organizations/" + otherOrg + "/members"},
		{"GET", "/organizations/" + otherOrg + "/org-units"},
		{"GET", "/applications"},
		{"GET", "/resources"},
		{"GET", "/roles"},
		{"GET", "/role-assignments"},
		{"GET", "/effective-roles"},
		{"GET", "/grants"},
		{"GET", "/service-accounts"},
		{"GET", "/delivery/status"},
		{"GET", "/delivery/templates"},
	} {
		if res := a.Do(r.method, api+r.path, token, fiber.Map{"name": "x"}); res.Status != 403 {
			t.Errorf("%s %s from another environment: got %d want 403: %s", r.method, r.path, res.Status, res.Body)
		}
	}
	// Nothing changed in the other environment.
	if u := a.Must("GET", otherBase+"/users/"+otherUser, a.Owner, nil, 200).JSON; u["active"] != true {
		t.Fatalf("other environment's user changed: %v", u)
	}
	if res := a.Do("GET", "/api/v1/environments/not-a-uuid/users", token, nil); res.Status != 403 {
		t.Fatalf("malformed environment: got %d", res.Status)
	}

	// The same token works in its own environment.
	own := "/api/v1/environments/" + a.EnvID
	a.Must("GET", own+"/users", token, nil, 200)
	a.Must("GET", own+"/organizations/"+a.Org+"/members", token, nil, 200)
	a.Must("GET", own+"/delivery/status", token, nil, 200)
}

// TestScopedAPIPermissionFamilies: each route family needs exactly its own
// permission pair — no more (unrelated families' checks do not leak onto
// it) and no less.
func TestScopedAPIPermissionFamilies(t *testing.T) {
	e := newEnv(t)
	api := "/api/v1/environments/" + e.EnvID
	org := "/organizations/" + e.Org
	for _, f := range []struct {
		read, write string
		get         []string
	}{
		{"iam:users:read", "iam:users:write", []string{"/users", "/users/" + e.Alice}},
		{"iam:orgs:read", "iam:orgs:write", []string{"/organizations", "/organizations/" + e.Org}},
		{"iam:members:read", "iam:members:write", []string{org + "/members", org + "/org-units", org + "/tree", org + "/groups", org + "/domains", org + "/invitations"}},
		{"iam:apps:read", "iam:apps:write", []string{"/applications", "/applications/" + e.Client}},
		{"iam:resources:read", "iam:resources:write", []string{"/resources", "/resources/" + e.Res, "/applications/" + e.Client + "/resources"}},
		{"iam:roles:read", "iam:roles:write", []string{"/roles", "/role-assignments", "/group-role-assignments", "/effective-roles?user_id=" + e.Alice}},
		{"iam:grants:read", "iam:grants:write", []string{"/grants"}},
		{"iam:service-accounts:read", "iam:service-accounts:write", []string{"/service-accounts"}},
		{"iam:delivery:read", "iam:delivery:write", []string{"/delivery/status", "/delivery/templates"}},
	} {
		reader := e.scopedToken(f.read)
		for _, path := range f.get {
			if res := e.Do("GET", api+path, reader, nil); res.Status != 200 {
				t.Errorf("GET %s with only %s: got %d want 200: %s", path, f.read, res.Status, res.Body)
			}
		}
		// A token with a different family's permissions is refused.
		stranger := "iam:users:read"
		if f.read == stranger {
			stranger = "iam:orgs:read"
		}
		if res := e.Do("GET", api+f.get[0], e.scopedToken(stranger), nil); res.Status != 403 {
			t.Errorf("GET %s with only %s: got %d want 403", f.get[0], stranger, res.Status)
		}
	}
	// Writes need the write permission.
	e.Must("POST", api+"/organizations", e.scopedToken("iam:orgs:read"), fiber.Map{"name": "Nope"}, 403)
	e.Must("POST", api+"/organizations", e.scopedToken("iam:orgs:write"), fiber.Map{"name": "Yes"}, 201)
}
