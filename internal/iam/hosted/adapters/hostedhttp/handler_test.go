package hostedhttp

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
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
		Brand:  brandOf(hosted.Settings{DisplayName: `Acme "Corp"`, LogoURL: "https://cdn.example/logo.png", AccentColor: "#ff0000"}),
		Ticket: "ik_authorize_x", Email: "a@example.com", Connection: &connection,
		Connections:   []federation.ConnectionSummary{{ID: connection, Name: "Google"}},
		Challenge:     identity.NewChallengeID(),
		Organizations: []authentication.Organization{{ID: identity.NewOrganizationID(), Name: "Org <b>"}},
		Token:         "ik_invite_x", Invite: &invitation.Preview{Email: "a***@example.com", PasswordRequired: true},
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
	_ = pages["organization"].ExecuteTemplate(&out, "layout", v)
	if !strings.Contains(out.String(), "Org &lt;b&gt;") {
		t.Fatal("organization name not escaped")
	}
}

func TestBrandDefaults(t *testing.T) {
	b := brandOf(hosted.Settings{})
	if b.Name == "" || b.Accent != defaultAccent || b.Logo != "" {
		t.Fatalf("unexpected defaults %+v", b)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/", func(c *fiber.Ctx) error {
				status, text := failed(c, tc.err)
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
