package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// TestSignInTexts: operators reword any hosted page text per language for
// the environment, a client or an organization; pages resolve each key
// organization › client › environment › catalog, the editor previews
// drafts, every change is audited with its own event type, and deleting a
// scope's texts returns it to the inherited ones.
func TestSignInTexts(t *testing.T) {
	e := newEnv(t)
	client := e.hostedClient()
	settings := e.Base + "/login-settings"
	page := func(extra url.Values) string {
		t.Helper()
		b := e.browser()
		start := b.authorizeWith(client, extra)
		if start.Status != 303 {
			t.Fatalf("authorize %v: %d %s", extra, start.Status, start.Body)
		}
		return b.get(start.Location).Body
	}

	// The catalog of customizable texts, per language.
	catalog := e.Must("GET", settings+"/texts/catalog?locale=es", e.Owner, nil, 200).JSON
	if catalog["locale"] != "es" || len(catalog["items"].([]any)) < 50 {
		t.Fatalf("catalog = %v", catalog)
	}
	e.Must("GET", settings+"/texts/catalog?locale=xx", e.Owner, nil, 400)

	// None yet; validation names the key.
	if got := e.Must("GET", settings+"/texts/en", e.Owner, nil, 200).JSON; len(got["texts"].(map[string]any)) != 0 || got["locale"] != "en" {
		t.Fatalf("empty texts = %v", got)
	}
	for _, bad := range []fiber.Map{
		{"texts": fiber.Map{"email.login.subject": "x"}},
		{"texts": fiber.Map{"hosted.notice.code_sent": "No placeholder"}},
		{"texts": fiber.Map{"hosted.title.sign_in": strings.Repeat("a", 500)}},
		{"texts": fiber.Map{}},
	} {
		e.Must("PUT", settings+"/texts/en", e.Owner, bad, 400)
	}
	e.Must("PUT", settings+"/texts/xx", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.title.sign_in": "Hi"}}, 400)
	e.Must("PUT", settings+"/clients/"+uuid.NewString()+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.title.sign_in": "Hi"}}, 404)
	e.Must("PUT", settings+"/organizations/"+uuid.NewString()+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.title.sign_in": "Hi"}}, 404)
	e.Must("DELETE", settings+"/texts/en", e.Owner, nil, 404)

	// Environment texts reword the pages (escaped), in their language only.
	saved := e.Must("PUT", settings+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{
		"hosted.title.sign_in": "Welcome <back>", "hosted.form.continue": "Next", "hosted.form.login": "Work email",
	}}, 200).JSON
	if saved["locale"] != "en" || saved["texts"].(map[string]any)["hosted.form.continue"] != "Next" || saved["updated_at"] == nil {
		t.Fatalf("saved = %v", saved)
	}
	p := page(nil)
	if !strings.Contains(p, "<title>Welcome &lt;back&gt;") || !strings.Contains(p, ">Next<") || !strings.Contains(p, ">Work email<") {
		t.Fatalf("environment texts:\n%s", p)
	}
	if es := page(url.Values{"ui_locales": {"es"}}); strings.Contains(es, "Welcome") || !strings.Contains(es, ">Continuar<") {
		t.Fatalf("other language reworded:\n%s", es)
	}

	// Client texts win over the environment's, organization texts over both.
	e.Must("PUT", settings+"/clients/"+client+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.form.continue": "Go"}}, 200)
	e.Must("PUT", settings+"/organizations/"+e.Org+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.title.sign_in": "Acme sign-in"}}, 200)
	if p = page(nil); !strings.Contains(p, ">Go<") || !strings.Contains(p, "<title>Welcome &lt;back&gt;") {
		t.Fatalf("client texts:\n%s", p)
	}
	if p = page(url.Values{"organization_id": {e.Org}}); !strings.Contains(p, ">Go<") || !strings.Contains(p, "<title>Acme sign-in") || !strings.Contains(p, ">Work email<") {
		t.Fatalf("organization texts:\n%s", p)
	}

	// Error messages too.
	e.Must("PUT", settings+"/texts/en", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.error.credentials": "Nope, try again."}}, 200)
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	if r := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"wrong-password-1"}}); !strings.Contains(r.Body, "Nope, try again.") {
		t.Fatalf("custom error: %d %s", r.Status, r.Body)
	}

	// The list, previews of saved and draft texts.
	list := e.Must("GET", settings+"/texts", e.Owner, nil, 200).JSON
	if list["page"].(map[string]any)["total"].(float64) != 3 {
		t.Fatalf("list = %v", list)
	}
	saw := e.Must("GET", settings+"/preview?page=password&organization="+e.Org, e.Owner, nil, 200).JSON["html"].(string)
	if !strings.Contains(saw, "Acme sign-in") {
		t.Fatalf("saved preview:\n%s", saw)
	}
	draft := e.Must("POST", settings+"/texts/preview", e.Owner, fiber.Map{"page": "identify", "locale": "es", "client_id": client, "texts": fiber.Map{"hosted.form.continue": "Seguir"}}, 200).JSON["html"].(string)
	if !strings.Contains(draft, ">Seguir<") || !strings.Contains(draft, `<html lang="es" dir="ltr">`) {
		t.Fatalf("draft preview:\n%s", draft)
	}
	e.Must("POST", settings+"/texts/preview", e.Owner, fiber.Map{"page": "code", "texts": fiber.Map{"hosted.notice.code_sent": "none"}}, 400)

	// Audited, with sign_in_texts.* events.
	if e.audited("PUT", "/management/v1/environments/"+e.EnvID+"/login-settings/organizations/"+e.Org+"/texts/en") != 1 {
		t.Fatal("organization texts not audited")
	}
	var events int
	if err := e.DB.Get(&events, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='sign_in_texts.updated'`, e.EnvID); err != nil || events != 4 {
		t.Fatalf("events = %d %v", events, err)
	}

	// Deleting returns the scope to the inherited texts; deleting the
	// organization drops its texts.
	e.Must("DELETE", settings+"/clients/"+client+"/texts/en", e.Owner, nil, 204)
	if p = page(nil); !strings.Contains(p, ">Continue<") {
		t.Fatalf("after delete:\n%s", p)
	}
	gone := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Gone"})
	e.Must("PUT", settings+"/organizations/"+gone+"/texts/es", e.Owner, fiber.Map{"texts": fiber.Map{"hosted.form.continue": "Adelante"}}, 200)
	if _, err := e.DB.Exec(`DELETE FROM organizations WHERE id=$1`, gone); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.DB.Get(&n, `SELECT count(*) FROM hosted_texts WHERE environment_id=$1`, e.EnvID); err != nil || n != 2 {
		t.Fatalf("texts left = %d %v", n, err)
	}
}
