package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestEmailTemplates covers customized email wording: the purpose ×
// language grid, editing (normalized, validated, audited), reset, previews
// of saved and draft wording, and permissions.
func TestEmailTemplates(t *testing.T) {
	e := newEnv(t)
	path := e.Base + "/delivery/templates"

	grid := e.Must("GET", path, e.Owner, nil, 200).JSON["items"].([]any)
	if len(grid) != 10 {
		t.Fatalf("grid = %d items", len(grid))
	}
	for _, item := range grid {
		if item.(map[string]any)["customized"] != false {
			t.Fatalf("customized before any edit: %v", item)
		}
	}

	view := e.Must("GET", path+"/login/es", e.Owner, nil, 200).JSON
	defaults := view["defaults"].(map[string]any)
	if view["customized"] != false || defaults["subject"] == "" || defaults["action"] != "" || view["template"].(map[string]any)["subject"] != "" {
		t.Fatalf("default view = %v", view)
	}
	if ph, ok := view["placeholders"].([]any); !ok || len(ph) == 0 {
		t.Fatalf("placeholders = %v", view["placeholders"])
	}

	// Save: trimmed, CRLF normalized, returned as GET returns it.
	saved := e.Must("PUT", path+"/login/es", e.Owner, fiber.Map{"subject": "  Código {{code}} para {{app_name}} ", "body": "Hola {{email}}\r\n\r\nExpira en {{expires_in}} min."}, 200).JSON
	tpl := saved["template"].(map[string]any)
	if saved["customized"] != true || tpl["subject"] != "Código {{code}} para {{app_name}}" || tpl["body"] != "Hola {{email}}\n\nExpira en {{expires_in}} min." || tpl["heading"] != "" {
		t.Fatalf("saved = %v", saved)
	}
	if n := e.audited("email_template.updated", "/environments/"+e.EnvID+"/delivery/templates/login/es"); n != 1 {
		t.Fatalf("audited updates = %d", n)
	}
	customized := 0
	for _, item := range e.Must("GET", path, e.Owner, nil, 200).JSON["items"].([]any) {
		if item.(map[string]any)["customized"] == true {
			customized++
		}
	}
	if customized != 1 {
		t.Fatalf("customized = %d", customized)
	}

	// Rejected wording names the problem and stores nothing.
	for body, want := range map[string]fiber.Map{
		"unknown placeholder {{link}}": {"subject": "{{link}}"},
		"action is not used":           {"action": "Go"},
		"subject must be one line":     {"subject": "a\nb"},
		"body must be at most 2000":    {"body": strings.Repeat("x", 2001)},
	} {
		if r := e.Must("PUT", path+"/login/es", e.Owner, want, 400); !strings.Contains(r.Body, body) {
			t.Fatalf("%v: %s", want, r.Body)
		}
	}
	e.Must("PUT", path+"/welcome/es", e.Owner, fiber.Map{"subject": "x"}, 400)
	e.Must("PUT", path+"/login/fr", e.Owner, fiber.Map{"subject": "x"}, 400)
	e.Must("GET", path+"/login/es-MX", e.Owner, nil, 400)

	// The saved wording is what previews (and sends) use; a draft overrides it.
	p := e.Must("GET", e.Base+"/delivery/preview?purpose=login&locale=es", e.Owner, nil, 200).JSON
	if !strings.HasPrefix(p["subject"].(string), "Código 123456 para ") || !strings.Contains(p["text"].(string), "Expira en 5 min.") {
		t.Fatalf("saved preview = %v", p)
	}
	p = e.Must("POST", e.Base+"/delivery/preview", e.Owner, fiber.Map{"purpose": "login", "locale": "es", "template": fiber.Map{"subject": "Borrador {{code}}"}}, 200).JSON
	if p["subject"] != "Borrador 123456" {
		t.Fatalf("draft preview = %v", p)
	}
	e.Must("POST", e.Base+"/delivery/preview", e.Owner, fiber.Map{"purpose": "login", "template": fiber.Map{"subject": "{{organization}}"}}, 400)
	// An unsaved brand name previews in the header and {{app_name}}; nothing is stored.
	p = e.Must("POST", e.Base+"/delivery/preview", e.Owner, fiber.Map{"purpose": "login", "locale": "es", "template": fiber.Map{"subject": "{{app_name}}"}, "app_name": "Globex Ñ"}, 200).JSON
	if p["subject"] != "Globex Ñ" || !strings.Contains(p["html"].(string), "Globex Ñ") {
		t.Fatalf("draft name preview = %v", p)
	}
	e.Must("POST", e.Base+"/delivery/preview", e.Owner, fiber.Map{"purpose": "login", "app_name": strings.Repeat("x", 101)}, 400)
	if p = e.Must("POST", e.Base+"/delivery/preview", e.Owner, fiber.Map{"purpose": "login", "template": fiber.Map{"subject": "{{app_name}}"}}, 200).JSON; p["subject"] == "Globex Ñ" {
		t.Fatal("a draft name was stored")
	}
	if r := e.Must("GET", e.Base+"/delivery/preview?purpose=login&locale=es&format=html", e.Owner, nil, 200); !strings.Contains(r.Body, "Código 123456") {
		t.Fatalf("html preview = %s", r.Body)
	}

	// Invitations may relabel their button.
	inv := e.Must("PUT", path+"/invitation/en", e.Owner, fiber.Map{"action": "Join {{organization}}"}, 200).JSON
	if inv["template"].(map[string]any)["action"] != "Join {{organization}}" {
		t.Fatalf("invitation = %v", inv)
	}
	if r := e.Must("GET", e.Base+"/delivery/preview?purpose=invitation&locale=en&format=html", e.Owner, nil, 200); !strings.Contains(r.Body, "Join Acme") {
		t.Fatalf("invitation preview = %s", r.Body)
	}

	// Viewers read but cannot change wording.
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "tpl-viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	e.Must("GET", path, viewer, nil, 200)
	e.Must("GET", path+"/login/es", viewer, nil, 200)
	e.Must("PUT", path+"/login/es", viewer, fiber.Map{"subject": "x"}, 403)
	e.Must("DELETE", path+"/login/es", viewer, nil, 403)

	// Reset (idempotent); empty wording resets too.
	e.Must("DELETE", path+"/login/es", e.Owner, nil, 204)
	e.Must("DELETE", path+"/login/es", e.Owner, nil, 204)
	if n := e.audited("email_template.reset", "/environments/"+e.EnvID+"/delivery/templates/login/es"); n != 2 {
		t.Fatalf("audited resets = %d", n)
	}
	if v := e.Must("GET", path+"/login/es", e.Owner, nil, 200).JSON; v["customized"] != false {
		t.Fatalf("after reset = %v", v)
	}
	if v := e.Must("PUT", path+"/invitation/en", e.Owner, fiber.Map{"action": "  "}, 200).JSON; v["customized"] != false {
		t.Fatalf("empty wording kept = %v", v)
	}
	p = e.Must("GET", e.Base+"/delivery/preview?purpose=login&locale=es", e.Owner, nil, 200).JSON
	if strings.HasPrefix(p["subject"].(string), "Código 123456 para ") {
		t.Fatalf("reset wording still used: %v", p)
	}
}

// TestScopedDeliveryPermissions checks the /api/v1 delivery routes: reads
// (including the saved preview) need iam:delivery:read, every change and the
// draft preview need iam:delivery:write.
func TestScopedDeliveryPermissions(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	token := func(permissions ...string) string {
		sa := e.Must("POST", e.Base+"/service-accounts", e.Owner, fiber.Map{"name": "delivery-" + strings.Join(permissions, "-"), "application_id": e.Client, "resource_id": iam, "permissions": permissions}, 201).JSON
		return e.Must("POST", "/identity/v1/machine-token", sa["secret"].(string), nil, 200).JSON["access_token"].(string)
	}
	reader, writer := token("iam:delivery:read"), token("iam:delivery:read", "iam:delivery:write")
	base := "/api/v1/environments/" + e.EnvID + "/delivery"
	wording := fiber.Map{"subject": "Your code {{code}}"}
	draft := fiber.Map{"purpose": "login", "locale": "en", "template": wording}

	e.Must("GET", base, reader, nil, 404) // nothing configured yet
	for _, path := range []string{"/status", "/preview?purpose=login&locale=en", "/templates", "/templates/login/en"} {
		e.Must("GET", base+path, reader, nil, 200)
	}
	e.Must("PUT", base+"/templates/login/en", reader, wording, 403)
	e.Must("DELETE", base+"/templates/login/en", reader, nil, 403)
	e.Must("POST", base+"/preview", reader, draft, 403)
	e.Must("PUT", base, reader, fiber.Map{"webhook_url": "https://hook.example", "webhook_token": "t"}, 403)
	e.Must("DELETE", base, reader, nil, 403)

	e.Must("PUT", base+"/templates/login/en", writer, wording, 200)
	if p := e.Must("POST", base+"/preview", writer, draft, 200).JSON; !strings.HasPrefix(p["subject"].(string), "Your code 123456") {
		t.Fatalf("draft preview = %v", p)
	}
	if p := e.Must("GET", base+"/preview?purpose=login&locale=en", reader, nil, 200).JSON; !strings.HasPrefix(p["subject"].(string), "Your code 123456") {
		t.Fatalf("saved preview = %v", p)
	}
	e.Must("DELETE", base+"/templates/login/en", writer, nil, 204)
	e.Must("GET", base+"/templates", token("iam:users:read"), nil, 403)
}
