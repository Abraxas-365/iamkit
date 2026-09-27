package authmail

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

type fixedBrand struct {
	brand authentication.Brand
	err   error
}

func (b fixedBrand) Brand(context.Context, identity.EnvironmentID) (authentication.Brand, error) {
	return b.brand, b.err
}

type fixedTemplates struct {
	copy authentication.Copy
	ok   bool
	err  error
	got  []string
}

func (t *fixedTemplates) Copy(_ context.Context, _ identity.EnvironmentID, purpose, locale string) (authentication.Copy, bool, error) {
	t.got = append(t.got, purpose+"/"+locale)
	return t.copy, t.ok, t.err
}

var (
	testEnvironment = identity.MustParseEnvironmentID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	testExpires     = time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC)
	acme            = authentication.Brand{Name: "Acme", LogoURL: "https://acme.io/logo.png", Accent: "#0F766E"}
)

func sample(purpose string) authentication.Message {
	m := authentication.Message{Email: "ana@example.com", Purpose: purpose, Environment: testEnvironment}
	switch purpose {
	case authentication.PurposeInvitation:
		m.Token, m.Link, m.Organization, m.Inviter, m.ExpiresAt = "ik_inv_token", "https://app.acme.io/invite?token=ik_inv_token", "Acme Corp", "Bob", &testExpires
	case authentication.PurposeTest:
	default:
		m.Code = "12345678"
	}
	return m
}

// Golden files pin IAMKit's default emails; run with -update after an
// intended change and review the diff.
func TestRenderGolden(t *testing.T) {
	r := Renderer{Branding: fixedBrand{brand: acme}}
	for _, locale := range i18n.Locales() {
		for _, purpose := range authentication.PreviewPurposes {
			m := sample(purpose)
			m.Locale = locale.Code
			email, err := r.Render(context.Background(), m, nil)
			if err != nil {
				t.Fatalf("%s/%s: %v", purpose, locale.Code, err)
			}
			name := purpose + "." + locale.Code
			golden(t, name+".html", email.HTML)
			golden(t, name+".txt", "Subject: "+email.Subject+"\n\n"+email.Text)
			if strings.Contains(email.HTML+email.Text+email.Subject, "{{") {
				t.Errorf("%s: unfilled placeholder", name)
			}
		}
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from golden file (run go test -update and review the diff)\n--- got ---\n%s", name, got)
	}
}

func TestRenderContent(t *testing.T) {
	ctx := context.Background()
	r := Renderer{Branding: fixedBrand{brand: acme}}
	email, err := r.Render(ctx, sample(authentication.PurposeLogin), nil)
	if err != nil {
		t.Fatal(err)
	}
	if email.To != "ana@example.com" || email.Subject != "Your sign-in code for Acme" || email.From != "" {
		t.Fatalf("email %+v", email)
	}
	for _, want := range []string{"12345678", "expires in 5 minutes", `src="https://acme.io/logo.png"`, `lang="en"`} {
		if !strings.Contains(email.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if !strings.Contains(email.Text, "12345678") {
		t.Error("text lacks the code")
	}

	invite, _ := r.Render(ctx, sample(authentication.PurposeInvitation), nil)
	for _, want := range []string{`href="https://app.acme.io/invite?token=ik_inv_token"`, "background:#0f766e", "color:#ffffff", "Bob invited you to join Acme Corp on Acme.", "October 4, 2026", "Accept invitation"} {
		if !strings.Contains(invite.HTML, want) {
			t.Errorf("invitation html lacks %q", want)
		}
	}
}

// Without a usable link the invitation shows the token instead of a button.
func TestRenderInvitationWithoutLink(t *testing.T) {
	for _, link := range []string{"", "javascript:alert(1)", "/relative", "ftp://x.io/a"} {
		m := sample(authentication.PurposeInvitation)
		m.Link, m.Inviter = link, ""
		email, err := Renderer{}.Render(context.Background(), m, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(email.HTML, "<a href") || strings.Contains(email.HTML, "javascript") || !strings.Contains(email.HTML, "ik_inv_token") || !strings.Contains(email.Text, "Invitation code: ik_inv_token") {
			t.Errorf("link %q:\n%s", link, email.HTML)
		}
		if !strings.Contains(email.Text, "Someone invited you") {
			t.Errorf("missing inviter fallback: %s", email.Text)
		}
	}
}

// User-controlled values are escaped in HTML and can never add header
// lines to the subject.
func TestRenderEscapingAndInjection(t *testing.T) {
	m := sample(authentication.PurposeInvitation)
	m.Organization = "<script>alert(1)</script>\r\nBcc: evil@x.io"
	m.Inviter = `"><img src=x onerror=alert(1)>`
	r := Renderer{Branding: fixedBrand{brand: authentication.Brand{Name: "A<b>c\nme", LogoURL: "http://insecure.io/l.png", Accent: "red;background:url(x)"}}}
	email, err := r.Render(context.Background(), m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(email.Subject, "\r\n") {
		t.Errorf("subject has a line break: %q", email.Subject)
	}
	for _, bad := range []string{"<script>", "<img src=x", "insecure.io", "url(x)", "<b>c"} {
		if strings.Contains(email.HTML, bad) {
			t.Errorf("html contains %q", bad)
		}
	}
	if !strings.Contains(email.HTML, "background:#2563eb") {
		t.Error("invalid accent must fall back to the default")
	}
}

func TestRenderLocale(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ request, brand, deployment, want string }{
		{"", "", "", "en"},
		{"", "", "es", "es"},
		{"", "es", "en", "es"},
		{"en", "es", "es", "en"},
		{"es-MX", "", "", "es"},
		{"fr", "", "", "en"},
	} {
		templates := &fixedTemplates{}
		r := Renderer{Branding: fixedBrand{brand: authentication.Brand{Locale: tc.brand}}, Templates: templates, Locale: tc.deployment}
		m := sample(authentication.PurposeLogin)
		m.Locale = tc.request
		email, err := r.Render(ctx, m, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(email.HTML, `lang="`+tc.want+`"`) || templates.got[0] != "login/"+tc.want {
			t.Errorf("%+v: templates asked %v", tc, templates.got)
		}
	}
}

func TestRenderOverrides(t *testing.T) {
	ctx := context.Background()
	saved := &fixedTemplates{ok: true, copy: authentication.Copy{
		Subject: "{{code}} is your {{app_name}} code",
		Body:    "Hi {{email}},\nuse the code below.\n\n<b>Thanks</b> {{nope}}",
	}}
	r := Renderer{Branding: fixedBrand{brand: acme}, Templates: saved}
	email, err := r.Render(ctx, sample(authentication.PurposeLogin), nil)
	if err != nil {
		t.Fatal(err)
	}
	if email.Subject != "12345678 is your Acme code" {
		t.Errorf("subject %q", email.Subject)
	}
	for _, want := range []string{"Hi ana@example.com,<br>use the code below.", "&lt;b&gt;Thanks&lt;/b&gt; {{nope}}", "Your sign-in code</h1>", "12345678</td>"} {
		if !strings.Contains(email.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}

	// A draft replaces saved wording and is not looked up.
	saved.got = nil
	email, _ = r.Render(ctx, sample(authentication.PurposeLogin), &authentication.Copy{Heading: "Draft heading"})
	if len(saved.got) != 0 || !strings.Contains(email.HTML, "Draft heading</h1>") || email.Subject != "Your sign-in code for Acme" {
		t.Errorf("draft: asked %v, subject %q", saved.got, email.Subject)
	}

	// An action override on a purpose without a button is ignored.
	saved.copy = authentication.Copy{Action: "Click"}
	email, _ = r.Render(ctx, sample(authentication.PurposeLogin), nil)
	if strings.Contains(email.HTML, "Click") {
		t.Error("login must not render an action")
	}
}

// Missing branding or wording never fails a send.
func TestRenderDegradesToDefaults(t *testing.T) {
	r := Renderer{Branding: fixedBrand{err: errors.New("db down")}, Templates: &fixedTemplates{err: errors.New("db down")}}
	email, err := r.Render(context.Background(), sample(authentication.PurposeLogin), nil)
	if err != nil || email.Subject != "Your sign-in code for IAMKit" {
		t.Fatalf("got %q %v", email.Subject, err)
	}
	if _, err := r.Render(context.Background(), authentication.Message{Purpose: "nope"}, nil); err == nil {
		t.Fatal("unknown purpose must fail")
	}
}

type recordingMailer struct{ got []authentication.Email }

func (m *recordingMailer) Deliver(_ context.Context, e authentication.Email) error {
	m.got = append(m.got, e)
	return nil
}

func TestRenderedSend(t *testing.T) {
	mailer := &recordingMailer{}
	d := Rendered{Renderer: Renderer{}, Mailer: mailer, From: "no-reply@acme.io", FromName: "Acme", ReplyTo: "help@acme.io"}
	if err := d.Send(context.Background(), sample(authentication.PurposeLogin)); err != nil {
		t.Fatal(err)
	}
	e := mailer.got[0]
	if e.From != "no-reply@acme.io" || e.FromName != "Acme" || e.ReplyTo != "help@acme.io" || e.To != "ana@example.com" || e.HTML == "" || e.Text == "" {
		t.Fatalf("email %+v", e)
	}
}
