package hostedhttp

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/gofiber/fiber/v2"
)

func TestFonts(t *testing.T) {
	// No font: the system stack and no font-src.
	b := brandOf(theme(hosted.Settings{}), "")
	if b.FontSrc != "" || strings.Contains(string(b.Vars), "@font-face") || !strings.Contains(string(b.Vars), "--font:system-ui") {
		t.Fatalf("default font %q %s", b.FontSrc, b.Vars)
	}

	// An embedded font loads from IAMKit itself; the heading follows it.
	b = brandOf(theme(hosted.Settings{Theme: hosted.Theme{Font: hosted.Font{Family: "Inter"}}}), "")
	css := string(b.Vars)
	if b.FontSrc != "'self'" || strings.Count(css, "@font-face") != 2 || !strings.Contains(css, `url("/hosted/fonts/inter-latin.woff2")`) ||
		!strings.Contains(css, `--font:"Inter",system-ui`) || !strings.Contains(css, "--heading-font:var(--font)") {
		t.Fatalf("inter %q %s", b.FontSrc, css)
	}

	// A custom heading font adds https: and its own face.
	b = brandOf(theme(hosted.Settings{Theme: hosted.Theme{Font: hosted.Font{Family: "lora"}, HeadingFont: hosted.Font{Family: "custom", URL: "https://cdn.example/brand.woff2?v=1"}}}), "")
	css = string(b.Vars)
	if b.FontSrc != "'self' https:" || !strings.Contains(css, `@font-face{font-family:"IAMKit Heading";src:url("https://cdn.example/brand.woff2?v=1") format("woff2")`) ||
		!strings.Contains(css, `--heading-font:"IAMKit Heading",`) {
		t.Fatalf("custom %q %s", b.FontSrc, css)
	}

	// A custom family drops a stray URL on built-in families.
	s := theme(hosted.Settings{Theme: hosted.Theme{Font: hosted.Font{Family: "roboto", URL: "https://cdn.example/x.woff2"}}})
	if s.Theme.Font.URL != "" {
		t.Fatalf("url kept %+v", s.Theme.Font)
	}
	for name, f := range map[string]hosted.Font{
		"family":  {Family: "comic-sans"},
		"missing": {Family: "custom"},
		"http":    {Family: "custom", URL: "http://cdn.example/a.woff2"},
		"ttf":     {Family: "custom", URL: "https://cdn.example/a.ttf"},
		"quote":   {Family: "custom", URL: `https://cdn.example/a".woff2`},
		"paren":   {Family: "custom", URL: "https://cdn.example/a).woff2"},
		"space":   {Family: "custom", URL: "https://cdn.example/a b.woff2"},
	} {
		s := hosted.Settings{Theme: hosted.Theme{HeadingFont: f}}
		if err := s.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// The pages' CSP allows fonts only when the theme sets one.
	app := fiber.New()
	app.Get("/:family", func(c *fiber.Ctx) error {
		return render(c, 200, "message", view{Title: "x", Brand: brandOf(theme(hosted.Settings{Theme: hosted.Theme{Font: hosted.Font{Family: c.Params("family")}}}), "")})
	})
	for family, want := range map[string]string{"system": "", "inter": "; font-src 'self'"} {
		res, err := app.Test(httptest.NewRequest("GET", "/"+family, nil))
		if err != nil {
			t.Fatal(err)
		}
		csp := res.Header.Get("Content-Security-Policy")
		if (want == "") == strings.Contains(csp, "font-src") || !strings.Contains(csp, want) {
			t.Fatalf("%s: %s", family, csp)
		}
	}
}

func TestFontFiles(t *testing.T) {
	h := &Handler{}
	app := fiber.New()
	app.Get("/hosted/fonts/:file", h.font)
	for _, family := range hosted.Fonts {
		for _, subset := range fontSubsets {
			res, err := app.Test(httptest.NewRequest("GET", fontPath+family+"-"+subset.suffix+".woff2", nil))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != 200 || res.Header.Get("Content-Type") != "font/woff2" || string(body[:4]) != "wOF2" {
				t.Fatalf("%s-%s: %d %s", family, subset.suffix, res.StatusCode, res.Header.Get("Content-Type"))
			}
		}
		if builtinFonts[family].name == "" {
			t.Fatalf("%s has no face", family)
		}
	}
	for _, path := range []string{"OFL.txt", "comic-latin.woff2", "inter-latin.ttf", "..%2Fhandler.go"} {
		res, err := app.Test(httptest.NewRequest("GET", fontPath+path, nil))
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 404 {
			t.Fatalf("%s: %d", path, res.StatusCode)
		}
	}
}

func TestLegalLinks(t *testing.T) {
	legal := &hosted.Legal{PrivacyURL: " https://acme.example/privacy ", TermsURL: "https://acme.example/terms", SupportEmail: "Help@Acme.example"}
	s := theme(hosted.Settings{Legal: legal})
	if s.Legal.PrivacyURL != "https://acme.example/privacy" || s.Legal.SupportEmail != "help@acme.example" {
		t.Fatalf("normalized %+v", s.Legal)
	}
	v, _ := sample("identify", "en", nil)
	v.Brand = brandOf(s, "")
	out, err := document("identify", &v)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{`<nav class="legal">`, `<a href="https://acme.example/privacy" target="_blank" rel="noopener noreferrer">Privacy policy</a>`, `>Terms of service</a>`, `<a href="mailto:help@acme.example">Contact support</a>`} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q in\n%s", want, html)
		}
	}
	if strings.Contains(html, ">Help</a>") {
		t.Fatal("unset help link shown")
	}

	// Sign-up asks to accept the terms when required, linking them.
	v, _ = sample("signup", "es", nil)
	v.Brand, v.SignIn.Terms = brandOf(s, ""), true
	out, _ = document("signup", &v)
	if html = string(out); !strings.Contains(html, `name="accept_terms" required`) || !strings.Contains(html, `Acepto los <a href="https://acme.example/terms"`) || !strings.Contains(html, `>Política de privacidad</a>`) {
		t.Fatalf("terms checkbox\n%s", html)
	}
	v.SignIn.Terms = false
	out, _ = document("signup", &v)
	if strings.Contains(string(out), "accept_terms") {
		t.Fatal("terms asked without the policy")
	}

	for name, l := range map[string]hosted.Legal{
		"http":  {PrivacyURL: "http://acme.example/privacy"},
		"js":    {HelpURL: "javascript:alert(1)"},
		"email": {SupportEmail: "not an email"},
	} {
		s := hosted.Settings{Legal: &l}
		if err := s.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// A client's empty links inherit the environment's.
	got := hosted.Legal{TermsURL: "https://app.example/terms"}.Over(hosted.Legal{PrivacyURL: "https://acme.example/privacy", TermsURL: "https://acme.example/terms"})
	if got.TermsURL != "https://app.example/terms" || got.PrivacyURL != "https://acme.example/privacy" {
		t.Fatalf("over %+v", got)
	}
}
