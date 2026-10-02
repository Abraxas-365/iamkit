package hostedhttp

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

func TestPagesRenderAndEscape(t *testing.T) {
	connection := identity.NewConnectionID()
	v := view{
		Nonce: "n0nce", Title: "Sign in", Error: `<script>alert(1)</script>`,
		Brand:  brandOf(hosted.Settings{DisplayName: `Acme "Corp"`, LogoURL: "https://cdn.example/logo.png", AccentColor: "#ff0000"}, ""),
		Ticket: "ik_authorize_x", Email: "a@example.com", Connection: &connection,
		Connections:   []federation.ConnectionSummary{{ID: connection, Name: "Google"}},
		Challenge:     identity.NewChallengeID(),
		Organizations: []authentication.Organization{{ID: identity.NewOrganizationID(), Name: "Org <b>"}},
		Account:       authentication.Profile{Email: "a@example.com", Name: "Ada <i>", AvatarURL: "https://cdn.example/ada.png"},
		Token:         "ik_invite_x", Invite: &invitation.Preview{Email: "a***@example.com", PasswordRequired: true},
		Post: &PostForm{Action: `https://sp.example/acs"><script>`, Fields: [][2]string{{"SAMLResponse", `"><script>x`}}},
	}
	for name, page := range pages {
		var out bytes.Buffer
		if err := page.ExecuteTemplate(&out, "layout", v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		html := out.String()
		if strings.Contains(html, "<script>") {
			t.Fatalf("%s: error message not escaped", name)
		}
		if !strings.Contains(html, `nonce="n0nce"`) || !strings.Contains(html, "--accent:#ff0000") {
			t.Fatalf("%s: missing nonce or accent", name)
		}
	}
	var out bytes.Buffer
	_ = pages["invite"].ExecuteTemplate(&out, "layout", view{Token: "t", Name: "Ada <i>", Invite: &invitation.Preview{PasswordRequired: true}})
	if !strings.Contains(out.String(), `name="name" value="Ada &lt;i&gt;"`) {
		t.Fatal("invitation page keeps the typed name, escaped, after an error")
	}
	out.Reset()
	_ = pages["organization"].ExecuteTemplate(&out, "layout", v)
	if !strings.Contains(out.String(), "Org &lt;b&gt;") {
		t.Fatal("organization name not escaped")
	}
	if !strings.Contains(out.String(), `src="https://cdn.example/ada.png"`) || !strings.Contains(out.String(), "Ada &lt;i&gt;") {
		t.Fatal("chooser shows the account with its avatar, escaped")
	}
}

// The page shows only the methods the client offers, with provider logos.
func TestSignInOptionsRender(t *testing.T) {
	google := federation.ConnectionSummary{ID: identity.NewConnectionID(), Name: "Google", Provider: federation.ProviderGoogle}
	render := func(page string, s hosted.SignIn) string {
		v := view{Ticket: "t", Email: "a@example.com", SignIn: s, Connections: []federation.ConnectionSummary{google}}
		out, err := document(page, &v)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	all := hosted.DefaultSignIn(identity.EnvironmentID{}, identity.ClientID{})
	html := render("identify", all)
	if !strings.Contains(html, `name="email"`) || !strings.Contains(html, "<svg") || !strings.Contains(html, "Continue with Google") {
		t.Fatal("default identify page must show the email form and the Google logo")
	}
	html = render("identify", hosted.SignIn{AllConnections: true})
	if strings.Contains(html, `name="email"`) || strings.Contains(html, ">or<") {
		t.Fatal("connections-only client must not ask for the email")
	}
	html = render("password", hosted.SignIn{EmailCode: true})
	if strings.Contains(html, `name="password"`) || strings.Contains(html, "Forgot password") || !strings.Contains(html, "Email me a code") {
		t.Fatal("code-only client must not show the password")
	}
	html = render("password", hosted.SignIn{Password: true, PasswordReset: true})
	if strings.Contains(html, "Email me a code") || !strings.Contains(html, "Forgot password") {
		t.Fatal("password-only client must not offer the code")
	}
	html = render("password", hosted.SignIn{Password: true})
	if !strings.Contains(html, `name="password"`) || strings.Contains(html, "Forgot password") {
		t.Fatal("an environment without password reset must hide the link")
	}
}

func TestBrandDefaults(t *testing.T) {
	b := brandOf(hosted.Settings{}, "")
	if b.Name != "" || b.Accent != defaultAccent || b.Logo != "" || b.Header || len(b.Links) != 0 {
		t.Fatalf("unexpected defaults %+v", b)
	}
	css := string(b.Vars)
	if !strings.Contains(css, "--accent:#2563eb") || !strings.Contains(css, "--radius:12px") || strings.Contains(css, "prefers-color-scheme") {
		t.Fatalf("default css %s", css)
	}
}

func theme(s hosted.Settings) hosted.Settings {
	if err := s.Validate(); err != nil {
		panic(err)
	}
	return s
}

func TestBrandModes(t *testing.T) {
	base := hosted.Settings{DisplayName: "Acme", LogoURL: "https://cdn.example/l.png", Theme: hosted.Theme{
		LogoDarkURL: "https://cdn.example/d.png",
		Light:       hosted.Palette{Primary: "#ffcc00", Background: "#fafafa"},
		Dark:        hosted.Palette{Primary: "#ff6600", Card: "#111111"},
	}}
	light := brandOf(theme(base), "")
	if !strings.Contains(string(light.Vars), "--accent:#ffcc00;--on-accent:#000000") || strings.Contains(string(light.Vars), "#ff6600") || light.LogoDark != "" {
		t.Fatalf("light %+v", light)
	}

	dark := base
	dark.Theme.Mode = hosted.ModeDark
	b := brandOf(theme(dark), "")
	if !strings.Contains(string(b.Vars), "--accent:#ff6600") || !strings.Contains(string(b.Vars), "--card:#111111") || b.Logo != "https://cdn.example/d.png" {
		t.Fatalf("dark %+v", b)
	}

	adaptive := base
	adaptive.Theme.Mode = hosted.ModeAdaptive
	b = brandOf(theme(adaptive), "")
	css := string(b.Vars)
	if !strings.Contains(css, "@media (prefers-color-scheme: dark){:root{color-scheme:dark;--accent:#ff6600") || b.LogoDark != "https://cdn.example/d.png" {
		t.Fatalf("adaptive %s %+v", css, b)
	}
	// A preview can force either scheme of an adaptive style.
	if forced := brandOf(theme(adaptive), hosted.ModeDark); strings.Contains(string(forced.Vars), "@media") || !strings.Contains(string(forced.Vars), "--accent:#ff6600") {
		t.Fatalf("forced dark %s", forced.Vars)
	}

	// Dark primary follows the light one when unset.
	follow := hosted.Settings{AccentColor: "#123456", Theme: hosted.Theme{Mode: hosted.ModeDark}}
	if b = brandOf(theme(follow), ""); !strings.Contains(string(b.Vars), "--accent:#123456;--on-accent:#ffffff") {
		t.Fatalf("follow %s", b.Vars)
	}
}

func TestLayoutThemeParts(t *testing.T) {
	radius := 0
	s := theme(hosted.Settings{DisplayName: "Acme <Billing>", LogoURL: "https://cdn.example/l.png", Theme: hosted.Theme{
		Radius: &radius, Spacing: "compact", Align: "left", FaviconURL: "https://cdn.example/f.ico",
		Header: hosted.Header{Show: true}, LogoPosition: "header",
		Footer: hosted.Footer{Text: "© Acme <Inc>", Links: []hosted.Link{{Label: "Privacy", URL: "https://acme.example/privacy"}, {Label: "Help", URL: "mailto:help@acme.example"}}},
	}})
	v := view{Title: "Sign in", Brand: brandOf(s, "")}
	out, err := document("identify", &v)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{
		`<title>Sign in · Acme &lt;Billing&gt;</title>`,
		`<link rel="icon" href="https://cdn.example/f.ico">`,
		`<header class="top"><img src="https://cdn.example/l.png" alt=""><div class="brand">Acme &lt;Billing&gt;</div></header>`,
		`--radius:0px`, `--pad:24px`, `--align:flex-start`,
		`<span>© Acme &lt;Inc&gt;</span>`,
		`<a href="https://acme.example/privacy" target="_blank" rel="noopener noreferrer">Privacy</a>`,
		`href="mailto:help@acme.example"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q in\n%s", want, html)
		}
	}
	if strings.Count(html, `class="brand"`) != 1 {
		t.Fatal("brand shown in the header and the card")
	}

	// Default layout: the name sits under the logo in the card.
	v = view{Title: "Sign in", Brand: brandOf(theme(hosted.Settings{DisplayName: "Acme"}), "")}
	out, _ = document("identify", &v)
	if html = string(out); !strings.Contains(html, `<div class="brand">Acme</div>`) || strings.Contains(html, "<footer") || strings.Contains(html, `class="top"`) {
		t.Fatalf("default layout\n%s", html)
	}
}

func TestPreviewSamples(t *testing.T) {
	for _, page := range []string{"identify", "password", "code", "reset", "organization", "mfa", "enroll", "recovery", "invite", "message", "signup", "signup-code"} {
		for _, lang := range i18n.Codes() {
			v, ok := sample(page, lang, nil)
			if !ok {
				t.Fatalf("no sample for %s", page)
			}
			v.Brand = brandOf(hosted.Settings{}, hosted.ModeDark)
			out, err := document(page, &v)
			if err != nil {
				t.Fatalf("%s: %v", page, err)
			}
			// Every page text comes from the catalog: none is left as a key.
			if html := string(out); strings.Contains(html, "hosted.") || !strings.Contains(html, `<html lang="`+lang+`" dir="`+i18n.Dir(lang)+`">`) {
				t.Fatalf("%s/%s: untranslated\n%s", page, lang, html)
			}
		}
	}
	if _, ok := sample("admin", "en", nil); ok {
		t.Fatal("unknown page previewed")
	}
}

// Pages speak the page language: titles, labels, buttons and the errors
// people can fix; the browser language applies when nothing else does.
func TestLocalizedPages(t *testing.T) {
	v, _ := sample("identify", "es", nil)
	out, _ := document("identify", &v)
	html := string(out)
	for _, want := range []string{"<title>Iniciar sesión", ">Correo electrónico o usuario<", ">Continuar<", `class="divider">o<`, "Continuar con Google"} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q in\n%s", want, html)
		}
	}
	v, _ = sample("password", "es", nil)
	out, _ = document("password", &v)
	if html = string(out); !strings.Contains(html, "¿Olvidaste tu contraseña?") || !strings.Contains(html, "Envíame un código") {
		t.Fatalf("password page\n%s", html)
	}

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		lang := language(c, c.Query("preferred"))
		_, text := failed(c, view{Lang: lang}, errx.Unauthorized("invalid credentials or access token"))
		return c.SendString(lang + "|" + text)
	})
	for _, tc := range []struct{ preferred, accept, want string }{
		{"", "es-MX,es;q=0.9,en;q=0.8", "es|Correo, usuario o contraseña incorrectos."},
		{"", "eo", "en|Incorrect email, username or password."},
		{"", "fr-FR,fr;q=0.9", "fr|Adresse e-mail, nom d’utilisateur ou mot de passe incorrect."},
		{"en", "es", "en|Incorrect email, username or password."},
		{"es", "", "es|Correo, usuario o contraseña incorrectos."},
	} {
		req := httptest.NewRequest("GET", "/?preferred="+tc.preferred, nil)
		req.Header.Set("Accept-Language", tc.accept)
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		if string(body) != tc.want {
			t.Fatalf("preferred %q accept %q: got %q, want %q", tc.preferred, tc.accept, body, tc.want)
		}
	}

	// Only enabled languages are used: the browser's Spanish is ignored
	// when the environment enables English only, and an environment with
	// Spanish only answers in Spanish whatever the browser asks.
	for _, tc := range []struct {
		languages []string
		accept    string
		want      string
	}{
		{[]string{"en"}, "es-MX", "en"},
		{[]string{"es"}, "en-US", "es"},
		{nil, "es-MX", "es"},
	} {
		app := fiber.New()
		settings := hosted.Settings{Languages: tc.languages}
		app.Get("/", func(c *fiber.Ctx) error { return c.SendString(environmentLanguage(c, settings)) })
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Language", tc.accept)
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		if body, _ := io.ReadAll(res.Body); string(body) != tc.want {
			t.Fatalf("languages %v accept %q: %q", tc.languages, tc.accept, body)
		}
	}
}

func TestBackgroundImage(t *testing.T) {
	s := hosted.Settings{Theme: hosted.Theme{Mode: hosted.ModeAdaptive, BackgroundImageURL: "https://cdn.example/bg.jpg?v=2", BackgroundOverlay: 40}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	css := string(brandOf(s, "").Vars)
	if !strings.Contains(css, `html>body{background:linear-gradient(color-mix(in srgb,var(--bg) 40%,transparent),color-mix(in srgb,var(--bg) 40%,transparent)),url("https://cdn.example/bg.jpg?v=2") center/cover no-repeat fixed,var(--bg)}`) {
		t.Fatalf("background css %s", css)
	}
	if css = string(brandOf(hosted.Settings{}, "").Vars); strings.Contains(css, "url(") {
		t.Fatalf("no image, still a background: %s", css)
	}
	for name, theme := range map[string]hosted.Theme{
		"http":     {BackgroundImageURL: "http://cdn.example/bg.jpg"},
		"quote":    {BackgroundImageURL: `https://cdn.example/a");}body{color:red`},
		"paren":    {BackgroundImageURL: "https://cdn.example/a)b.jpg"},
		"backlash": {BackgroundImageURL: `https://cdn.example/a\b.jpg`},
		"overlay":  {BackgroundImageURL: "https://cdn.example/bg.jpg", BackgroundOverlay: 91},
		"negative": {BackgroundOverlay: -1},
	} {
		s := hosted.Settings{Theme: theme}
		if err := s.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestPreviewMethods(t *testing.T) {
	render := func(page string, m Methods) (string, error) {
		v, _ := sample(page, "en", nil)
		if err := m.apply(&v); err != nil {
			return "", err
		}
		v.Brand = brandOf(hosted.Settings{}, "")
		out, err := document(page, &v)
		return string(out), err
	}
	// Email form, passkey and buttons: one visible "or", not one per section.
	v, _ := sample("identify", "en", nil)
	v.Brand = brandOf(hosted.Settings{}, "")
	if !v.SignIn.Passkey || !v.SignIn.EmailForm() || len(v.Connections) == 0 {
		t.Fatalf("sample offers %+v with %d buttons", v.SignIn, len(v.Connections))
	}
	out, _ := document("identify", &v)
	if n := strings.Count(string(out), `class="divider"`); n != 1 || !strings.Contains(string(out), `class="divider">or<`) {
		t.Fatalf("%d dividers\n%s", n, out)
	}
	// Email form and passkey only: the "or" stays hidden until the script
	// shows the passkey button (browsers without WebAuthn never do).
	v.Connections = nil
	out, _ = document("identify", &v)
	if !strings.Contains(string(out), `class="divider" data-webauthn-reveal hidden`) {
		t.Fatalf("passkey divider shown\n%s", out)
	}
	// Social only: no email form, no "or" divider, the listed buttons.
	html, err := render("identify", Methods{Connections: []Button{{Name: "GitHub", Provider: "github"}, {Name: "Okta <Corp>", Provider: "oidc"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, `name="email"`) || strings.Contains(html, `class="divider"`) || !strings.Contains(html, "Continue with GitHub") || !strings.Contains(html, "Continue with Okta &lt;Corp&gt;") || strings.Contains(html, "Google") {
		t.Fatalf("social only\n%s", html)
	}
	// Email only: the form without buttons.
	if html, _ = render("identify", Methods{EmailCode: true}); !strings.Contains(html, `name="email"`) || strings.Contains(html, "Continue with") {
		t.Fatalf("email only\n%s", html)
	}
	// Code only: the password step offers just the code.
	if html, _ = render("password", Methods{EmailCode: true}); strings.Contains(html, `type="password"`) || !strings.Contains(html, "Email me a code") {
		t.Fatalf("code only\n%s", html)
	}
	for name, m := range map[string]Methods{
		"nothing":  {},
		"provider": {Connections: []Button{{Name: "X", Provider: "facebook"}}},
		"name":     {Password: true, Connections: []Button{{Name: " ", Provider: "google"}}},
	} {
		if _, err := render("identify", m); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestFailedMessages(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		text   string
	}{
		{"client error keeps its message", errx.Unauthorized("invalid credentials"), 401, "invalid credentials"},
		{"provider outage is explained", federation.ErrProviderUnavailable(errors.New("dial tcp: no such host")), 502, "single sign-on provider is not responding"},
		{"other failures stay generic", errx.Internal("database down"), 500, "Something went wrong"},
		{"plain errors stay generic", errors.New("boom"), 500, "Something went wrong"},
		{"hosted codes are translated", hosted.Problem(errx.Validation, hosted.CodeChooseOrganization, "choose an organization"), 400, "Choose an organization."},
		{"wrong code counts down", hosted.ErrWrongCode(1), 401, "That code is not valid. Try again. 1 attempt left."},
		{"password length names its bounds", authentication.PasswordRejected(authentication.RuleLength, 14), 400, "The password must be 14 to 72 characters long."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/", func(c *fiber.Ctx) error {
				status, text := failed(c, view{Lang: "en"}, tc.err)
				return c.Status(status).SendString(text)
			})
			res, err := app.Test(httptest.NewRequest("GET", "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.status || !strings.Contains(string(body), tc.text) {
				t.Fatalf("got %d %q", res.StatusCode, body)
			}
			if strings.Contains(string(body), "no such host") || strings.Contains(string(body), "database") {
				t.Fatal("cause leaked to the page")
			}
		})
	}
}
