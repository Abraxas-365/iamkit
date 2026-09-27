package hostedhttp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
