package e2e_test

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// scopeNames lists the names of a payload's scopes[] (objects with name,
// display_name and description since D40).
func scopeNames(v any) []any {
	out := []any{}
	items, _ := v.([]any)
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m["name"])
		}
	}
	return out
}

func scopeByName(t *testing.T, v any, name string) map[string]any {
	t.Helper()
	items, _ := v.([]any)
	for _, item := range items {
		if m, ok := item.(map[string]any); ok && m["name"] == name {
			return m
		}
	}
	t.Fatalf("scope %s not in %v", name, v)
	return nil
}

// consentWords opens the consent page of a fresh authorization in language.
func (e *Env) consentWords(client, language string) page {
	e.t.Helper()
	extra := url.Values{"prompt": {"consent"}}
	if language != "" {
		extra.Set("ui_locales", language)
	}
	return e.startConsent(client, loopback, extra).Page()
}

// TestPermissionDescriptions is D40: a resource's permissions carry a
// display name and a sentence, with translations, that the hosted consent
// page, the consent ticket payload and the connected apps use; they fall
// back to the permission's name, and go with the permission.
func TestPermissionDescriptions(t *testing.T) {
	e := newEnv(t)
	_, protected, resource := e.mcpServer(fiber.Map{})
	e.openServer(protected)
	descriptions := e.Base + "/resources/" + resource + "/permission-descriptions"
	api := "/api/v1/environments/" + e.EnvID + "/resources/" + resource + "/permission-descriptions"

	// Without descriptions the page names the permission itself.
	if p := e.consentWords(claudeCodeID, ""); p.Status != 200 || !strings.Contains(p.Body, "mcp:tools:read") || strings.Contains(p.Body, `class="muted detail"`) {
		t.Fatalf("page without descriptions: %d %s", p.Status, p.Body)
	}
	if got := e.Must("GET", descriptions, e.Owner, nil, 200).JSON["items"].([]any); len(got) != 0 {
		t.Fatalf("descriptions before any: %v", got)
	}

	// Validation: not in the catalog, unknown locale, too long, control
	// characters, duplicates.
	for name, items := range map[string][]fiber.Map{
		"not in the catalog": {{"permission": "mcp:nope", "display_name": "x"}},
		"unknown locale":     {{"permission": "mcp:tools:read", "locale": "xx", "display_name": "x"}},
		"long name":          {{"permission": "mcp:tools:read", "display_name": strings.Repeat("a", 81)}},
		"long description":   {{"permission": "mcp:tools:read", "description": strings.Repeat("a", 301)}},
		"control characters": {{"permission": "mcp:tools:read", "display_name": "a\nb"}},
		"duplicate":          {{"permission": "mcp:tools:read", "display_name": "a"}, {"permission": "mcp:tools:read", "display_name": "b"}},
		"empty":              {{"permission": "mcp:tools:read"}},
	} {
		if r := e.Do("PUT", descriptions, e.Owner, fiber.Map{"items": items}); r.Status != 400 && r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	e.Must("PUT", e.Base+"/resources/"+resource+"/permission-descriptions", e.scopedToken("iam:resources:read"), fiber.Map{"items": []fiber.Map{}}, 401)
	e.Must("PUT", api, e.scopedToken("iam:resources:read"), fiber.Map{"items": []fiber.Map{}}, 403)
	e.Must("GET", api, e.scopedToken(), nil, 403)

	// Set (default + Spanish + a regional Spanish with the name only).
	set := []fiber.Map{
		{"permission": "mcp:tools:read", "display_name": "Read your data", "description": "Lets the app look at your data."},
		{"permission": "mcp:tools:read", "locale": "es", "display_name": "Leer tus datos", "description": "Permite que la app consulte tus datos."},
		{"permission": "mcp:tools:write", "display_name": "Change your data", "description": "Lets the app make changes."},
	}
	e.Must("PUT", api, e.scopedToken("iam:resources:read", "iam:resources:write"), fiber.Map{"items": set}, 204)
	e.Must("PUT", descriptions, e.Owner, fiber.Map{"items": set}, 204) // idempotent
	if got := e.Must("GET", api, e.scopedToken("iam:resources:read"), nil, 200).JSON["items"].([]any); len(got) != 3 {
		t.Fatalf("stored descriptions = %v", got)
	}
	if ev := e.eventData("resource.descriptions_updated"); ev == nil {
		t.Fatal("no resource.descriptions_updated event")
	}
	if n := e.count(`SELECT count(*) FROM events WHERE type='resource.descriptions_updated' AND subject_id=$1`, resource); n < 1 {
		t.Fatalf("event subject is not the resource: %d", n)
	}

	// English page (default text), with the raw name beside it.
	en := e.consentWords(claudeCodeID, "en")
	if !strings.Contains(en.Body, "Read your data") || !strings.Contains(en.Body, "Lets the app look at your data.") || !strings.Contains(en.Body, "<code>mcp:tools:read</code>") {
		t.Fatalf("english page: %s", en.Body)
	}
	// Spanish page, and a regional tag falls to the base language.
	for _, language := range []string{"es", "es-PE"} {
		es := e.consentWords(claudeCodeID, language)
		if !strings.Contains(es.Body, "Leer tus datos") || !strings.Contains(es.Body, "Permite que la app consulte tus datos.") || strings.Contains(es.Body, "Read your data") {
			t.Fatalf("%s page: %s", language, es.Body)
		}
	}
	// A language with no translation shows the default text.
	if fr := e.consentWords(claudeCodeID, "fr"); !strings.Contains(fr.Body, "Read your data") {
		t.Fatalf("french page: %s", fr.Body)
	}

	// Connected apps carry the words in the reader's language.
	e.redeem(claudeCodeID, codeOf(t, e.startConsent(claudeCodeID, loopback, nil).Decide(true), loopback))
	alice := e.Login(e.AliceEmail)
	me := "?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
	apps := e.Must("GET", "/identity/v1/me/connected-apps"+me+"&locale=es-MX", alice, nil, 200).JSON["items"].([]any)
	if len(apps) != 1 {
		t.Fatalf("connected apps = %v", apps)
	}
	scope := scopeByName(t, apps[0].(map[string]any)["scopes"], "mcp:tools:read")
	if scope["display_name"] != "Leer tus datos" || scope["description"] != "Permite que la app consulte tus datos." {
		t.Fatalf("connected app scope (es) = %v", scope)
	}
	apps = e.Must("GET", "/identity/v1/me/connected-apps"+me, alice, nil, 200).JSON["items"].([]any)
	if scope = scopeByName(t, apps[0].(map[string]any)["scopes"], "mcp:tools:read"); scope["display_name"] != "Read your data" {
		t.Fatalf("connected app scope (default) = %v", scope)
	}
	ops := e.Must("GET", e.Base+"/users/"+e.Alice+"/connected-apps", e.Owner, nil, 200).JSON["items"].([]any)
	if scope = scopeByName(t, ops[0].(map[string]any)["scopes"], "mcp:tools:read"); scope["display_name"] != "Read your data" {
		t.Fatalf("operator connected app scope = %v", scope)
	}

	// Removing a permission from the catalog deletes its descriptions.
	e.Must("PUT", e.Base+"/resources/"+resource, e.Owner, fiber.Map{"name": "MCP", "audience": mcpURI, "permissions": []string{"mcp:tools:read"}}, 204)
	left := e.Must("GET", descriptions, e.Owner, nil, 200).JSON["items"].([]any)
	if len(left) != 2 {
		t.Fatalf("descriptions after removing mcp:tools:write = %v", left)
	}
	if n := e.count(`SELECT count(*) FROM permission_descriptions WHERE resource_id=$1 AND permission='mcp:tools:write'`, resource); n != 0 {
		t.Fatalf("%d descriptions outlived their permission", n)
	}
	// Describing the removed permission is refused; the stored set is
	// replaced whole, and an empty set clears it.
	if r := e.Do("PUT", descriptions, e.Owner, fiber.Map{"items": set}); r.Status != 400 && r.Status != 422 {
		t.Fatalf("describing a removed permission: %d %s", r.Status, r.Body)
	}
	e.Must("PUT", descriptions, e.Owner, fiber.Map{"items": []fiber.Map{}}, 204)
	if n := e.count(`SELECT count(*) FROM permission_descriptions WHERE resource_id=$1`, resource); n != 0 {
		t.Fatalf("%d descriptions after clearing", n)
	}
	// Back to the permission's name.
	if p := e.consentWords(claudeCodeID, "es"); !strings.Contains(p.Body, "mcp:tools:read") || strings.Contains(p.Body, "Leer tus datos") {
		t.Fatalf("page after clearing: %s", p.Body)
	}
}

// TestPermissionDescriptionsCustomUI: GET /identity/v1/authorize/:ticket
// words consent.scopes[] for the reader's Accept-Language.
func TestPermissionDescriptionsCustomUI(t *testing.T) {
	e := newEnv(t)
	_, _, resource := e.mcpServer(fiber.Map{})
	e.Must("PUT", e.Base+"/resources/"+resource+"/permission-descriptions", e.Owner, fiber.Map{"items": []fiber.Map{
		{"permission": "mcp:tools:read", "display_name": "Read your data", "description": "Lets the app look at your data."},
		{"permission": "mcp:tools:read", "locale": "es", "display_name": "Leer tus datos"},
	}}, 204)
	e.Must("PUT", e.Base+"/protected-resource-policy", e.Owner, fiber.Map{"max_idle_ttl_seconds": 2592000, "max_lifetime_ttl_seconds": 7776000, "consent_ui": "custom"}, 200)

	const origin = "https://login.example.com"
	ui := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "allowed_origins": []string{origin}, "consent_policy": "required"}, 201).JSON["client_id"].(string)
	b := e.browser()
	begin := b.get(resourceAuthorize(ui, nil))
	var started map[string]any
	json.Unmarshal([]byte(begin.Body), &started)
	ticket, _ := started["authorization_ticket"].(string)
	if begin.Status != 200 || ticket == "" {
		t.Fatalf("authorize: %d %s", begin.Status, begin.Body)
	}
	login := e.LoginBody(e.AliceEmail, e.Pass)
	login["resource_id"] = resource
	token := e.Must("POST", "/identity/v1/login", "", login, 200).JSON["access_token"].(string)
	body, _ := json.Marshal(fiber.Map{"authorization_ticket": ticket, "approve": true})
	req := httptest.NewRequest("POST", "/oauth/authorize/complete", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", origin)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	res, err := e.App.Test(req, 10000)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("complete: %d", res.StatusCode)
	}
	for _, tc := range []struct{ language, name, description string }{
		{"es-PE,es;q=0.9", "Leer tus datos", "Lets the app look at your data."},
		{"en", "Read your data", "Lets the app look at your data."},
		{"", "Read your data", "Lets the app look at your data."},
	} {
		b.acceptLanguage = tc.language
		info := b.get("/identity/v1/authorize/" + url.PathEscape(ticket))
		var body struct {
			Consent struct {
				Scopes []struct {
					Name        string `json:"name"`
					DisplayName string `json:"display_name"`
					Description string `json:"description"`
				} `json:"scopes"`
			} `json:"consent"`
		}
		if err := json.Unmarshal([]byte(info.Body), &body); err != nil || len(body.Consent.Scopes) != 1 {
			t.Fatalf("%q: %v %s", tc.language, err, info.Body)
		}
		s := body.Consent.Scopes[0]
		if s.Name != "mcp:tools:read" || s.DisplayName != tc.name || s.Description != tc.description {
			t.Fatalf("%q: scope = %+v", tc.language, s)
		}
	}
}
