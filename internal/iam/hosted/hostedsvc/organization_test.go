package hostedsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func text(s string) *string { return &s }

// The page brand is env ← client ← organization, field by field; the
// organization is the hint, the chosen one, or the email's verified domain.
func TestPageOrganizationBranding(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepository{saved: map[string]hosted.Login{}}
	locale := "es"
	repo.branding = hosted.Settings{DisplayName: "Env", Locale: &locale}
	repo.styles = map[identity.ClientID]hosted.Settings{client: {DisplayName: "Billing", LogoURL: "https://cdn.example/billing.png"}}
	repo.orgs = map[identity.OrganizationID]hosted.OrganizationSettings{orgA: {DisplayName: text("Acme")}}
	repo.domains = map[string]identity.OrganizationID{"acme.com": orgA}

	page := func(form, email string) hosted.Page {
		t.Helper()
		s := New(repo, hashSecrets{}, fakeAuthorizations{hosted: true, form: form}, &fakeAuthenticator{}, nil, &fakeFederation{}, nil)
		out, err := s.Page(ctx, request, email)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if p := page("", ""); p.Settings.DisplayName != "Billing" {
		t.Fatalf("no organization: client style, got %q", p.Settings.DisplayName)
	}
	p := page("organization_id="+orgA.String(), "")
	if p.Settings.DisplayName != "Acme" || p.Settings.LogoURL != "https://cdn.example/billing.png" || p.Language != "es" {
		t.Fatalf("hint: organization name over client logo, env language; got %+v %q", p.Settings, p.Language)
	}
	if p = page("scope=openid+urn:iamkit:org:id:"+orgA.String(), ""); p.Settings.DisplayName != "Acme" {
		t.Fatalf("scope hint: got %q", p.Settings.DisplayName)
	}
	if p = page("", "ada@ACME.com"); p.Settings.DisplayName != "Acme" {
		t.Fatalf("verified domain: got %q", p.Settings.DisplayName)
	}
	if p = page("", "ada@other.com"); p.Settings.DisplayName != "Billing" {
		t.Fatalf("unverified domain: got %q", p.Settings.DisplayName)
	}
	repo.saved[string(hashSecrets{}.Hash(request.Ticket))] = hosted.Login{Chosen: orgA}
	if p = page("", ""); p.Settings.DisplayName != "Acme" {
		t.Fatalf("chosen organization: got %q", p.Settings.DisplayName)
	}
}

// A hinted authorization signs in to that organization only: no chooser,
// and none when the user is not a member.
func TestOrganizationHintNarrows(t *testing.T) {
	ctx := context.Background()
	_, auth, repo, fed := setup(orgA, orgB)
	s := New(repo, hashSecrets{}, fakeAuthorizations{hosted: true, form: "organization_id=" + orgB.String()}, auth, nil, fed, nil)
	out, err := s.Password(ctx, request, "a@example.com", "right")
	if err != nil || out.Login == nil || out.Login.Organization != orgB {
		t.Fatalf("hint must skip the chooser into orgB: %+v %v", out, err)
	}
	other := identity.NewOrganizationID()
	s = New(repo, hashSecrets{}, fakeAuthorizations{hosted: true, form: "organization_id=" + other.String()}, auth, nil, fed, nil)
	if _, err = s.Password(ctx, request, "a@example.com", "right"); err == nil {
		t.Fatal("a hint for an organization the user cannot enter must fail")
	}
}

func TestOrganizationOverridesValidated(t *testing.T) {
	s, _, _, _ := setup(orgA)
	bad := hosted.OrganizationSettings{AccentColor: text("red")}
	if _, err := s.SaveOrganizationSettings(context.Background(), hosted.Mutation{Environment: env}, orgA, bad); err == nil {
		t.Fatal("invalid accent color must be refused")
	}
	if _, err := s.DraftOrganization(context.Background(), env, hosted.OrganizationSettings{LogoURL: text("http://x.example/a.png")}); err == nil {
		t.Fatal("non-https logo must be refused")
	}
}
