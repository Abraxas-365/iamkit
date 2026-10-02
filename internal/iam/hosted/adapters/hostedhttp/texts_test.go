package hostedhttp

import (
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// Custom texts replace the catalog's words on the page, in titles, labels,
// buttons and error messages, and are escaped like any text.
func TestCustomTexts(t *testing.T) {
	texts := i18n.Texts{
		"hosted.title.sign_in":    "Welcome to <Acme>",
		"hosted.form.continue":    "Next",
		"hosted.error.generic":    "Our bad.",
		"hosted.notice.code_sent": "Look in %s",
	}
	v, _ := sample("identify", "en", texts)
	v.Brand = brandOf(hosted.Settings{}, "")
	out, err := document("identify", &v)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{"Welcome to &lt;Acme&gt;", ">Next<", "Email or username"} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q in\n%s", want, html)
		}
	}
	if strings.Contains(html, "<Acme>") || strings.Contains(html, ">Continue<") {
		t.Fatalf("catalog text or unescaped custom text\n%s", html)
	}

	v, _ = sample("code", "en", texts)
	if v.Notice != "Look in jane@example.com" {
		t.Fatalf("notice %q", v.Notice)
	}

	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(c)
	if _, text := failed(c, view{Lang: "en", Texts: texts}, errx.Internal("boom")); text != "Our bad." {
		t.Fatalf("error text %q", text)
	}
}
