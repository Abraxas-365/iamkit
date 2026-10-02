package e2e_test

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/gofiber/fiber/v2"
)

var htmlLang = regexp.MustCompile(`<html lang="([a-z-]+)"`)

// TestFeatureFlags: the registry with deployment values and per-environment
// overrides; beta_languages narrows the hosted languages, saml_idp unmounts
// the SAML identity provider.
func TestFeatureFlags(t *testing.T) {
	deployment, _, err := feature.ParseDeployment("saml_idp=false")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, bootstrap.WithFeatures(deployment))
	base := e.Base + "/features"

	list := e.Must("GET", base, e.Owner, nil, 200).JSON["items"].([]any)
	if len(list) != len(config.Flags) {
		t.Fatalf("features = %v", list)
	}
	saml := e.Must("GET", base+"/saml_idp", e.Owner, nil, 200).JSON
	if saml["enabled"] != false || saml["deployment"] != false || saml["scope"] != "deployment" || saml["environment"] != nil {
		t.Fatalf("saml_idp = %v", saml)
	}
	e.Must("GET", base+"/nope", e.Owner, nil, 404)
	e.Must("PUT", base+"/nope", e.Owner, fiber.Map{"enabled": true}, 404)
	e.Must("PUT", base+"/saml_idp", e.Owner, fiber.Map{"enabled": true}, 400)
	e.Must("PUT", base+"/beta_languages", e.Owner, fiber.Map{}, 400)

	// The SAML identity provider is not served at all.
	e.Must("GET", "/saml/"+e.EnvID+"/metadata", "", nil, 404)
	e.Must("GET", e.Base+"/saml/service-providers", e.Owner, nil, 404)

	client := e.hostedClient()
	lang := func(ui string) string {
		t.Helper()
		b := e.browser()
		start := b.authorizeWith(client, url.Values{"ui_locales": {ui}})
		m := htmlLang.FindStringSubmatch(b.get(start.Location).Body)
		if m == nil {
			t.Fatal("no language")
		}
		return m[1]
	}

	// Defaults reproduce today: every language.
	if got := lang("de"); got != "de" {
		t.Fatalf("default = %s", got)
	}
	off := e.Must("PUT", base+"/beta_languages", e.Owner, fiber.Map{"enabled": false}, 200).JSON
	if off["enabled"] != false || off["environment"] != false || off["updated_at"] == nil {
		t.Fatalf("override = %v", off)
	}
	if got := lang("de"); got != "en" {
		t.Fatalf("beta off = %s", got)
	}
	if got := lang("es"); got != "es" {
		t.Fatalf("stable language = %s", got)
	}
	// A chosen language stays offered; an explicit list wins over the flag.
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"locale": "fr"}, 200)
	if got := lang("de"); got != "fr" {
		t.Fatalf("chosen default = %s", got)
	}
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"locale": "en", "languages": []string{"en", "de"}}, 200)
	if got := lang("de"); got != "de" {
		t.Fatalf("explicit languages = %s", got)
	}
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"languages": []string{}}, 200)

	reset := e.Must("DELETE", base+"/beta_languages", e.Owner, nil, 200).JSON
	if reset["enabled"] != true || reset["environment"] != nil {
		t.Fatalf("reset = %v", reset)
	}
	if got := lang("de"); got != "de" {
		t.Fatalf("after reset = %s", got)
	}
	e.Must("DELETE", base+"/beta_languages", e.Owner, nil, 200) // idempotent

	// Audited as events, subject = the flag.
	events := e.Must("GET", e.Base+"/events?type=feature.*", e.Owner, nil, 200).JSON["items"].([]any)
	if len(events) != 2 {
		t.Fatalf("events = %v", events)
	}
	updated := events[1].(map[string]any)
	if updated["type"] != "feature.updated" || updated["subject"].(map[string]any)["id"] != "beta_languages" || updated["data"].(map[string]any)["enabled"] != false {
		t.Fatalf("updated = %v", updated)
	}

	// Another environment keeps its own state.
	project := e.ID("POST", "/management/v1/projects", fiber.Map{"name": "Other"})
	other := e.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "staging"})
	e.Must("PUT", base+"/beta_languages", e.Owner, fiber.Map{"enabled": false}, 200)
	if got := e.Must("GET", "/management/v1/environments/"+other+"/features/beta_languages", e.Owner, nil, 200).JSON; got["enabled"] != true {
		t.Fatalf("other environment = %v", got)
	}
}
