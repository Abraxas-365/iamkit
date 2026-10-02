package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestHostedLegalAndFonts: legal links (environment, inherited by client
// styles), fonts with their CSP and the embedded files, and sign-up terms
// acceptance recorded on the user.
func TestHostedLegalAndFonts(t *testing.T) {
	e := newEnv(t)
	settings := e.Base + "/login-settings"
	client := e.hostedClient()

	// Defaults reproduce today: no links, no fonts, no font-src.
	if s := e.Must("GET", settings, e.Owner, nil, 200).JSON; s["legal"] == nil {
		t.Fatalf("default legal = %v", s)
	}
	login := e.browser().authorize(client)
	if strings.Contains(login.Body, `class="legal"`) || strings.Contains(login.Header.Get("Content-Security-Policy"), "font-src") {
		t.Fatalf("defaults changed the page: %s", login.Header.Get("Content-Security-Policy"))
	}

	// Validation.
	e.Must("PUT", settings, e.Owner, fiber.Map{"legal": fiber.Map{"privacy_url": "http://acme.io/privacy"}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"legal": fiber.Map{"support_email": "nope"}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"theme": fiber.Map{"font": fiber.Map{"family": "comic-sans"}}}, 400)
	e.Must("PUT", settings, e.Owner, fiber.Map{"theme": fiber.Map{"font": fiber.Map{"family": "custom", "url": "https://cdn.acme.io/a.ttf"}}}, 400)

	s := e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme",
		"legal": fiber.Map{"privacy_url": "https://acme.io/privacy", "terms_url": "https://acme.io/terms", "support_email": "Help@Acme.io"},
		"theme": fiber.Map{"font": fiber.Map{"family": "Inter"}, "heading_font": fiber.Map{"family": "custom", "url": "https://cdn.acme.io/brand.woff2"}}}, 200).JSON
	legal := s["legal"].(map[string]any)
	if legal["support_email"] != "help@acme.io" || s["theme"].(map[string]any)["font"].(map[string]any)["family"] != "inter" {
		t.Fatalf("saved = %v", s)
	}
	// Omitting legal keeps it.
	if s = e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Acme", "theme": s["theme"]}, 200).JSON; s["legal"].(map[string]any)["terms_url"] != "https://acme.io/terms" {
		t.Fatalf("legal not kept = %v", s["legal"])
	}

	b := e.browser()
	login = b.authorize(client)
	csp := login.Header.Get("Content-Security-Policy")
	for _, want := range []string{`<a href="https://acme.io/privacy"`, `href="mailto:help@acme.io"`, `url("/hosted/fonts/inter-latin.woff2")`, `url("https://cdn.acme.io/brand.woff2")`} {
		if !strings.Contains(login.Body, want) {
			t.Fatalf("missing %q in\n%s", want, login.Body)
		}
	}
	if !strings.Contains(csp, "font-src 'self' https:") {
		t.Fatalf("csp = %s", csp)
	}
	font := b.get("/hosted/fonts/inter-latin.woff2")
	if font.Status != 200 || !strings.HasPrefix(font.Body, "wOF2") || font.Header.Get("Content-Type") != "font/woff2" {
		t.Fatalf("font: %d %s", font.Status, font.Header.Get("Content-Type"))
	}
	if b.get("/hosted/fonts/OFL.txt").Status != 404 {
		t.Fatal("non-font file served")
	}

	// A client style inherits the links it leaves empty.
	e.Must("PUT", settings+"/clients/"+client, e.Owner, fiber.Map{"display_name": "Billing", "legal": fiber.Map{"terms_url": "https://billing.acme.io/terms"}}, 200)
	login = e.browser().authorize(client)
	if !strings.Contains(login.Body, `href="https://billing.acme.io/terms"`) || !strings.Contains(login.Body, `href="https://acme.io/privacy"`) {
		t.Fatalf("client legal\n%s", login.Body)
	}
	e.Must("DELETE", settings+"/clients/"+client, e.Owner, nil, 204)

	// Terms acceptance: off by default; once required, sign-up refuses
	// without it and records when it was accepted.
	policy := e.Base + "/sign-in-policy"
	base := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}
	if p := e.Must("PUT", policy, e.Owner, base, 200).JSON; p["require_terms"] != false {
		t.Fatalf("default require_terms = %v", p["require_terms"])
	}
	signup := func(email string, accept bool) Response {
		return e.Do("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": email, "name": "Terms", "password": "a long enough password", "accept_terms": accept})
	}
	verify := func(r Response) string {
		m, ok := e.Mail.Last("email_verification")
		if !ok {
			t.Fatal("no verification email")
		}
		done := e.Must("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": r.JSON["challenge_id"], "code": m.Code}, 201).JSON
		return done["user_id"].(string)
	}
	free := verify(e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "free@example.com", "name": "Free", "password": "a long enough password"}, 202))
	if u := e.Must("GET", e.Base+"/users/"+free, e.Owner, nil, 200).JSON; u["terms_accepted_at"] != nil {
		t.Fatalf("terms recorded without the policy: %v", u)
	}

	with := withTerms(base)
	e.Must("PUT", policy, e.Owner, with, 200)
	// Omitting require_terms keeps it.
	if p := e.Must("PUT", policy, e.Owner, base, 200).JSON; p["require_terms"] != true {
		t.Fatalf("require_terms not kept = %v", p)
	}
	if r := signup("terms@example.com", false); r.Status != 400 || errorOf(r)["code"] != "TERMS_REQUIRED" {
		t.Fatalf("without acceptance: %d %s", r.Status, r.Body)
	}
	user := verify(e.Must("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "terms@example.com", "name": "Terms", "password": "a long enough password", "accept_terms": true}, 202))
	if u := e.Must("GET", e.Base+"/users/"+user, e.Owner, nil, 200).JSON; u["terms_accepted_at"] == nil {
		t.Fatalf("terms not recorded: %v", u)
	}

	// Hosted sign-up: the checkbox links the terms; the form needs it.
	b = e.browser()
	tk := b.authorize(client).field("ticket")
	form := b.get("/hosted/signup?ticket=" + url.QueryEscape(tk))
	if !strings.Contains(form.Body, `name="accept_terms" required`) || !strings.Contains(form.Body, `href="https://acme.io/terms"`) {
		t.Fatalf("signup form\n%s", form.Body)
	}
	fields := url.Values{"ticket": {tk}, "email": {"hosted-terms@example.com"}, "name": {"Hosted"}, "password": {"a long enough password"}}
	if p := b.post("/hosted/signup", fields); p.Status != 400 || !strings.Contains(p.Body, "Accept the terms") {
		t.Fatalf("hosted without acceptance: %d %s", p.Status, p.Body)
	}
	fields.Set("accept_terms", "on")
	step := b.post("/hosted/signup", fields)
	if step.Status != 200 || step.field("challenge_id") == "" {
		t.Fatalf("hosted signup: %d %s", step.Status, step.Body)
	}
	m, _ := e.Mail.Last("email_verification")
	b.post("/hosted/signup/verify", url.Values{"ticket": {tk}, "challenge_id": {step.field("challenge_id")}, "code": {m.Code}})
	if count(t, e.DB, `SELECT count(*) FROM users WHERE email='hosted-terms@example.com' AND terms_accepted_at IS NOT NULL`) != 1 {
		t.Fatal("hosted terms not recorded")
	}
}

// withTerms copies a policy body with require_terms set.
func withTerms(m fiber.Map) fiber.Map {
	out := fiber.Map{"require_terms": true}
	for k, v := range m {
		out[k] = v
	}
	return out
}
