package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestHostedBranding covers themes, per-client styles and previews: a
// client's own style replaces the environment default on its sign-in pages,
// invitations keep the default, and every change is audited.
func TestHostedBranding(t *testing.T) {
	e := newEnv(t)
	client := e.hostedClient()
	other := e.hostedClient()
	settings := e.Base + "/login-settings"
	styles := settings + "/clients"

	// Environment default with a theme.
	e.Must("PUT", settings, e.Owner, fiber.Map{"theme": fiber.Map{"mode": "sepia"}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"theme": fiber.Map{"light": fiber.Map{"background": "#fff;}body{display:none"}}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"theme": fiber.Map{"footer": fiber.Map{"links": []fiber.Map{{"label": "x", "url": "javascript:alert(1)"}}}}}, 400)
	saved := e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "accent_color": "#FF6600", "theme": fiber.Map{
		"mode": "adaptive", "radius": 4, "favicon_url": "https://cdn.example/f.ico",
		"dark":   fiber.Map{"primary": "#FFAA00"},
		"footer": fiber.Map{"text": "© Acme", "links": []fiber.Map{{"label": "Privacy", "url": "https://acme.example/privacy"}}},
	}}, 200).JSON
	theme := saved["theme"].(map[string]any)
	if theme["mode"] != "adaptive" || theme["light"].(map[string]any)["primary"] != "#ff6600" || theme["dark"].(map[string]any)["primary"] != "#ffaa00" || saved["accent_color"] != "#ff6600" {
		t.Fatalf("saved = %v", saved)
	}
	if e.audited("PUT", "/management/v1/environments/"+e.EnvID+"/login-settings") != 1 {
		t.Fatal("default branding not audited")
	}
	page := e.browser().authorize(client).Body
	for _, want := range []string{"<title>Sign in · Acme</title>", `<div class="brand">Acme</div>`, `href="https://cdn.example/f.ico"`, "--radius:4px", "@media (prefers-color-scheme: dark)", "--accent:#ffaa00", `href="https://acme.example/privacy"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("default theme missing %q:\n%s", want, page)
		}
	}

	// A client style: validated, scoped to the environment's clients.
	if e.Must("GET", styles, e.Owner, nil, 200).JSON["page"].(map[string]any)["total"].(float64) != 0 {
		t.Fatal("no client styles yet")
	}
	e.Must("GET", styles+"/"+client, e.Owner, nil, 404)
	e.Must("PUT", styles+"/not-a-uuid", e.Owner, fiber.Map{}, 400)
	e.Must("PUT", styles+"/"+e.ID("POST", e.Base+"/applications", fiber.Map{"name": "Unrelated"}), e.Owner, fiber.Map{}, 404)
	e.Must("PUT", styles+"/"+client, e.Owner, fiber.Map{"theme": fiber.Map{"radius": 99}}, 400)
	style := e.Must("PUT", styles+"/"+client, e.Owner, fiber.Map{"display_name": "Billing", "theme": fiber.Map{"mode": "dark", "dark": fiber.Map{"primary": "#00cc88", "card": "#101010"}, "header": fiber.Map{"show": true}, "logo_position": "header"}}, 200).JSON
	if style["client_id"] != client || style["theme"].(map[string]any)["mode"] != "dark" {
		t.Fatalf("style = %v", style)
	}
	if e.audited("PUT", "/management/v1/environments/"+e.EnvID+"/login-settings/clients/"+client) != 1 {
		t.Fatal("client style not audited")
	}
	listed := e.Must("GET", styles, e.Owner, nil, 200).JSON["items"].([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["client_id"] != client {
		t.Fatalf("listed = %v", listed)
	}

	// Its pages use it; the other client keeps the default.
	page = e.browser().authorize(client).Body
	if !strings.Contains(page, "<title>Sign in · Billing</title>") || !strings.Contains(page, "--accent:#00cc88") || !strings.Contains(page, "--card:#101010") ||
		!strings.Contains(page, `<header class="top">`) || strings.Contains(page, "@media") || strings.Contains(page, "acme.example/privacy") {
		t.Fatalf("client style not rendered:\n%s", page)
	}
	if page = e.browser().authorize(other).Body; !strings.Contains(page, "<title>Sign in · Acme</title>") {
		t.Fatalf("other client lost the default:\n%s", page)
	}

	// Invitations have no client: the environment default.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "brand@elsewhere.example"}, 201).JSON
	if p := e.browser().get("/hosted/invite?token=" + inv["token"].(string)); !strings.Contains(p.Body, "· Acme</title>") || strings.Contains(p.Body, "Billing") {
		t.Fatalf("invite branding:\n%s", p.Body)
	}

	// Previews: saved (any operator) and draft (writers), sample data only.
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	saw := e.Must("GET", settings+"/preview?page=password&scheme=light&client="+client, viewer, nil, 200).JSON["html"].(string)
	if !strings.Contains(saw, "· Billing</title>") || !strings.Contains(saw, "jane@example.com") || !strings.Contains(saw, "color-scheme:light") {
		t.Fatalf("saved preview:\n%s", saw)
	}
	e.Must("GET", settings+"/preview?page=admin", e.Owner, nil, 400)
	e.Must("GET", settings+"/preview?scheme=sepia", e.Owner, nil, 400)
	draft := e.Must("POST", settings+"/preview", e.Owner, fiber.Map{"page": "enroll", "scheme": "dark", "settings": fiber.Map{"display_name": "Draft <x>", "theme": fiber.Map{"dark": fiber.Map{"primary": "#abcdef"}}}}, 200).JSON["html"].(string)
	if !strings.Contains(draft, "Draft &lt;x&gt;") || !strings.Contains(draft, "--accent:#abcdef") || !strings.Contains(draft, `class="qr"`) {
		t.Fatalf("draft preview:\n%s", draft)
	}
	e.Must("POST", settings+"/preview", e.Owner, fiber.Map{"settings": fiber.Map{"accent_color": "red"}}, 400)
	e.Must("POST", settings+"/preview", viewer, fiber.Map{}, 403)
	e.Must("PUT", styles+"/"+client, viewer, fiber.Map{}, 403)
	e.Must("DELETE", styles+"/"+client, viewer, nil, 403)
	if e.Must("GET", settings, e.Owner, nil, 200).JSON["display_name"] != "Acme" {
		t.Fatal("draft preview changed the saved branding")
	}

	// Reset returns the client to the default.
	e.Must("DELETE", styles+"/"+client, e.Owner, nil, 204)
	e.Must("DELETE", styles+"/"+client, e.Owner, nil, 404)
	if e.audited("DELETE", "/management/v1/environments/"+e.EnvID+"/login-settings/clients/"+client) != 1 {
		t.Fatal("reset not audited")
	}
	if page = e.browser().authorize(client).Body; !strings.Contains(page, "<title>Sign in · Acme</title>") {
		t.Fatalf("reset client still styled:\n%s", page)
	}

	// Deleting a client drops its style.
	unused := e.hostedClient()
	e.Must("PUT", styles+"/"+unused, e.Owner, fiber.Map{"display_name": "Other"}, 200)
	var n int
	if _, err := e.DB.Exec(`DELETE FROM oauth_clients WHERE id=$1`, unused); err != nil {
		t.Fatal(err)
	}
	if err := e.DB.Get(&n, `SELECT count(*) FROM client_login_settings WHERE client_id=$1`, unused); err != nil || n != 0 {
		t.Fatalf("style of a deleted client kept: %d %v", n, err)
	}
}
