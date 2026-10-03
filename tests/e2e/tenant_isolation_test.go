package e2e_test

import (
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Ids of another environment are not found under this one: reads do not
// answer defaults or empty pages for them, and deletes are not silent
// no-ops (J9 tenant isolation).
func TestForeignIDsAreNotFound(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	grant := e.Must("PUT", e.Base+"/grants", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": bob, "resource_id": e.Res, "permissions": []string{"invoices:read"}}, 200).JSON["id"].(string)
	account := e.Must("POST", e.Base+"/service-accounts", e.Owner, fiber.Map{"name": "worker", "application_id": e.Client, "resource_id": e.Res, "permissions": []string{"invoices:read"}}, 201).JSON["id"].(string)
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON["id"].(string)

	project := e.ID("POST", "/management/v1/projects", fiber.Map{"name": "Other"})
	other := "/management/v1/environments/" + e.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "staging"})
	const unknown = "00000000-0000-4000-8000-000000000000"

	for _, path := range []string{
		"/organizations/" + e.Org + "/members",
		"/applications/" + e.Client + "/resources",
		"/login-settings/clients/" + client + "/sign-in",
		"/login-settings/organizations/" + e.Org,
		"/login-settings/clients/" + client + "/texts/en",
		"/login-settings/organizations/" + e.Org + "/texts/en",
	} {
		e.Must("GET", e.Base+path, e.Owner, nil, 200)
		e.Must("GET", other+path, e.Owner, nil, 404)
	}
	e.Must("GET", e.Base+"/federation-connections/"+unknown+"/identities", e.Owner, nil, 404)

	// Within one environment: another organization's unit and a non-member.
	globex := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	unit := e.ID("POST", e.Base+"/organizations/"+globex+"/org-units", fiber.Map{"name": "Sales", "kind": "team"})
	for _, view := range []string{"ancestors", "descendants", "delete-impact"} {
		e.Must("GET", e.Base+"/organizations/"+globex+"/org-units/"+unit+"/"+view, e.Owner, nil, 200)
		e.Must("GET", e.Base+"/organizations/"+e.Org+"/org-units/"+unit+"/"+view, e.Owner, nil, 404)
	}
	e.Must("GET", e.Base+"/organizations/"+e.Org+"/members/"+bob+"/groups", e.Owner, nil, 200)
	e.Must("GET", e.Base+"/organizations/"+globex+"/members/"+bob+"/groups", e.Owner, nil, 404)

	e.Must("DELETE", other+"/organizations/"+e.Org+"/members/"+bob, e.Owner, nil, 404)
	e.Must("DELETE", other+"/grants/"+grant, e.Owner, nil, 404)
	e.Must("DELETE", other+"/service-accounts/"+account, e.Owner, nil, 404)
	if !contains(e.Members(e.Org), bob) {
		t.Fatal("membership removed through another environment")
	}

	// In their own environment the deletes work; repeating a revocation is a no-op.
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+bob, e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/grants/"+grant, e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/grants/"+grant, e.Owner, nil, 404)
	e.Must("DELETE", e.Base+"/service-accounts/"+account, e.Owner, nil, 204)
	e.Must("DELETE", e.Base+"/service-accounts/"+account, e.Owner, nil, 204)
}
