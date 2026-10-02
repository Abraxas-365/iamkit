package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
)

// TestHostedLanguages: the environment's enabled languages bound every
// choice; ui_locales › organization › client › environment default ›
// browser; the organization's language also writes its invitation emails.
func TestHostedLanguages(t *testing.T) {
	smtp := newFakeSMTP(t)
	e := newEnv(t, loopbackMail(authmodule.Mail{}))
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "127.0.0.1", "smtp_port": smtp.Port}, 204)
	client := e.hostedClient()
	settings := e.Base + "/login-settings"
	orgStyle := settings + "/organizations/" + e.Org
	lang := func(extra url.Values) string {
		t.Helper()
		b := e.browser()
		start := b.authorizeWith(client, extra)
		if start.Status != 303 {
			t.Fatalf("authorize %v: %d %s", extra, start.Status, start.Body)
		}
		p := b.get(start.Location).Body
		for _, code := range []string{"en", "es"} {
			if strings.Contains(p, `<html lang="`+code+`" dir="ltr">`) {
				return code
			}
		}
		t.Fatalf("no language:\n%s", p)
		return ""
	}

	// Defaults reproduce today: every language, English without a hint.
	if s := e.Must("GET", settings, e.Owner, nil, 200).JSON; len(s["languages"].([]any)) != 0 {
		t.Fatalf("default languages = %v", s["languages"])
	}
	if got := lang(nil); got != "en" {
		t.Fatalf("default page = %s", got)
	}
	if got := lang(url.Values{"ui_locales": {"es-MX en"}}); got != "es" {
		t.Fatalf("ui_locales = %s", got)
	}

	// Enabled languages: validated, normalized, bound the default.
	e.Must("PUT", settings, e.Owner, fiber.Map{"languages": []string{"eo"}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"languages": []string{"es"}, "locale": "en"}, 400)
	s := e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "languages": []string{"ES", "es"}}, 200).JSON
	if l := s["languages"].([]any); len(l) != 1 || l[0] != "es" {
		t.Fatalf("languages = %v", s["languages"])
	}
	// Omitting languages keeps them; the default must still be enabled.
	e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "locale": "en"}, 400)
	if got := lang(url.Values{"ui_locales": {"en"}}); got != "es" {
		t.Fatalf("ui_locales outside the enabled languages = %s", got)
	}

	// A client style picks its own default among the enabled languages.
	e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "languages": []string{}}, 200)
	e.Must("PUT", settings+"/clients/"+client, e.Owner, fiber.Map{"display_name": "Billing", "locale": "eo"}, 400)
	e.Must("PUT", settings+"/clients/"+client, e.Owner, fiber.Map{"display_name": "Billing", "locale": "es"}, 200)
	if got := lang(nil); got != "es" {
		t.Fatalf("client language = %s", got)
	}
	if got := lang(url.Values{"ui_locales": {"en"}}); got != "en" {
		t.Fatalf("ui_locales over the client = %s", got)
	}
	e.Must("DELETE", settings+"/clients/"+client, e.Owner, nil, 204)

	// An organization's language: its pages and its invitation emails.
	e.Must("PUT", orgStyle, e.Owner, fiber.Map{"locale": "eo"}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "languages": []string{"en"}}, 200)
	e.Must("PUT", orgStyle, e.Owner, fiber.Map{"locale": "es"}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "languages": []string{}}, 200)
	if o := e.Must("PUT", orgStyle, e.Owner, fiber.Map{"locale": "es"}, 200).JSON; o["locale"] != "es" {
		t.Fatalf("organization = %v", o)
	}
	if got := lang(url.Values{"organization_id": {e.Org}}); got != "es" {
		t.Fatalf("organization language = %s", got)
	}
	if got := lang(nil); got != "en" {
		t.Fatalf("other sign-ins keep the environment language: %s", got)
	}
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "nuevo@elsewhere.example"}, 201).JSON
	if m := smtp.Last(); !strings.HasPrefix(m.Subject, "Te invitaron a unirte a") {
		t.Fatalf("invitation email subject = %q", m.Subject)
	}
	if p := e.browser().get("/hosted/invite?token=" + inv["token"].(string)).Body; !strings.Contains(p, `<html lang="es" dir="ltr">`) {
		t.Fatalf("invite page:\n%s", p)
	}
	// Inheriting again.
	e.Must("PUT", orgStyle, e.Owner, fiber.Map{"display_name": "Acme Corp"}, 200)
	if got := lang(url.Values{"organization_id": {e.Org}}); got != "en" {
		t.Fatalf("inherited organization language = %s", got)
	}
}
