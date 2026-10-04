package authsvc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// memDelivery is an in-memory DeliveryConfigRepository.
type memDelivery struct {
	cfg      *authentication.DeliveryConfig
	secret   authentication.DeliverySecret
	attempts []authentication.Attempt
}

func (r *memDelivery) GetDeliveryConfig(context.Context, identity.EnvironmentID) (authentication.DeliveryConfig, authentication.DeliverySecret, error) {
	if r.cfg == nil {
		return authentication.DeliveryConfig{}, authentication.DeliverySecret{}, errx.NotFound("delivery config not found")
	}
	return *r.cfg, r.secret, nil
}
func (r *memDelivery) SetDeliveryConfig(_ context.Context, m authentication.Mutation, in authentication.DeliveryConfigInput, sealed string) error {
	r.cfg = &authentication.DeliveryConfig{EnvironmentID: m.Environment, Provider: in.Provider, WebhookURL: in.WebhookURL, HasToken: in.WebhookToken != "",
		FromEmail: in.FromEmail, SMTPHost: in.SMTPHost, SMTPPort: in.SMTPPort, SMTPUsername: in.SMTPUsername, SMTPTLS: in.SMTPTLS, HasSecret: sealed != ""}
	r.secret = authentication.DeliverySecret{WebhookToken: in.WebhookToken, Sealed: sealed}
	return nil
}
func (r *memDelivery) DeleteDeliveryConfig(context.Context, authentication.Mutation) error {
	r.cfg = nil
	return nil
}
func (r *memDelivery) RecordAttempt(_ context.Context, _ identity.EnvironmentID, a authentication.Attempt) error {
	r.attempts = append(r.attempts, a)
	return nil
}
func (r *memDelivery) Activity(context.Context, identity.EnvironmentID) (authentication.Activity, error) {
	return authentication.Activity{}, nil
}
func (r *memDelivery) Audit(context.Context, authentication.Mutation) error { return nil }

// prefixCipher "seals" by prefixing, which is enough to see what was stored.
type prefixCipher struct{}

func (prefixCipher) Seal(plain []byte) (string, error) { return "sealed:" + string(plain), nil }
func (prefixCipher) Open(sealed string) ([]byte, error) {
	plain, ok := strings.CutPrefix(sealed, "sealed:")
	if !ok {
		return nil, errors.New("bad seal")
	}
	return []byte(plain), nil
}

type recordingDelivery struct{ got []authentication.Message }

func (d *recordingDelivery) Send(_ context.Context, m authentication.Message) error {
	d.got = append(d.got, m)
	return nil
}

func deliveryMutation() authentication.Mutation {
	return authentication.Mutation{Environment: identity.NewEnvironmentID(), Actor: "op"}
}

func TestSetDeliveryConfigSecrets(t *testing.T) {
	repo := &memDelivery{}
	s := NewDeliveryService(repo, nil, nil, prefixCipher{}, "")
	m := deliveryMutation()
	ctx := context.Background()
	smtp := authentication.DeliveryConfigInput{Provider: "smtp", FromEmail: "no-reply@acme.io", SMTPHost: "smtp.acme.io", SMTPUsername: "apikey"}

	if err := s.SetDeliveryConfig(ctx, m, smtp); err == nil || !strings.Contains(err.Error(), "smtp_password is required") {
		t.Fatalf("first smtp save without password: %v", err)
	}
	smtp.SMTPPassword = "pw1"
	if err := s.SetDeliveryConfig(ctx, m, smtp); err != nil {
		t.Fatal(err)
	}
	if repo.secret.Sealed != "sealed:pw1" || repo.cfg.SMTPPort != 587 || repo.cfg.SMTPTLS != "starttls" {
		t.Fatalf("stored %+v %+v", repo.cfg, repo.secret)
	}
	// D3: blank password on the same provider keeps the stored one.
	smtp.SMTPPassword = ""
	if err := s.SetDeliveryConfig(ctx, m, smtp); err != nil || repo.secret.Sealed != "sealed:pw1" {
		t.Fatalf("keep: %v %q", err, repo.secret.Sealed)
	}
	// Sender fields may change without re-entering the password…
	smtp.FromName = "Acme"
	if err := s.SetDeliveryConfig(ctx, m, smtp); err != nil || repo.secret.Sealed != "sealed:pw1" {
		t.Fatalf("keep on sender change: %v %q", err, repo.secret.Sealed)
	}
	// …but the stored password never follows a different server or account.
	for name, change := range map[string]func(*authentication.DeliveryConfigInput){
		"host":     func(in *authentication.DeliveryConfigInput) { in.SMTPHost = "smtp.evil.example" },
		"port":     func(in *authentication.DeliveryConfigInput) { in.SMTPPort = 2525 },
		"tls":      func(in *authentication.DeliveryConfigInput) { in.SMTPPort, in.SMTPTLS = 587, "tls" },
		"username": func(in *authentication.DeliveryConfigInput) { in.SMTPUsername = "other" },
	} {
		moved := smtp
		change(&moved)
		if err := s.SetDeliveryConfig(ctx, m, moved); err == nil || !strings.Contains(err.Error(), "smtp_password is required when changing") {
			t.Fatalf("%s change kept the password: %v", name, err)
		}
		if repo.cfg.SMTPHost != "smtp.acme.io" || repo.secret.Sealed != "sealed:pw1" {
			t.Fatalf("%s change stored: %+v %q", name, repo.cfg, repo.secret.Sealed)
		}
		moved.SMTPPassword = "pw2"
		if err := s.SetDeliveryConfig(ctx, m, moved); err != nil || repo.secret.Sealed != "sealed:pw2" {
			t.Fatalf("%s change with password: %v %q", name, err, repo.secret.Sealed)
		}
		smtp.SMTPPassword = "pw1"
		if err := s.SetDeliveryConfig(ctx, m, smtp); err != nil {
			t.Fatal(err)
		}
		smtp.SMTPPassword = ""
	}
	// Dropping authentication drops the secret.
	smtp.SMTPUsername = ""
	if err := s.SetDeliveryConfig(ctx, m, smtp); err != nil || repo.secret.Sealed != "" {
		t.Fatalf("no auth: %v %q", err, repo.secret.Sealed)
	}

	// Switching provider never carries the other provider's secret.
	repo.secret.Sealed = "sealed:pw1"
	resend := authentication.DeliveryConfigInput{Provider: "resend", FromEmail: "no-reply@acme.io"}
	if err := s.SetDeliveryConfig(ctx, m, resend); err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("resend without key after smtp: %v", err)
	}
	resend.APIKey = "re_1"
	if err := s.SetDeliveryConfig(ctx, m, resend); err != nil || repo.secret.Sealed != "sealed:re_1" {
		t.Fatalf("resend: %v %q", err, repo.secret.Sealed)
	}
	resend.APIKey = ""
	if err := s.SetDeliveryConfig(ctx, m, resend); err != nil || repo.secret.Sealed != "sealed:re_1" {
		t.Fatalf("resend keep: %v %q", err, repo.secret.Sealed)
	}

	// Webhook requires its token, sealed when a key is configured.
	if err := s.SetDeliveryConfig(ctx, m, authentication.DeliveryConfigInput{WebhookURL: "https://hook.acme.io"}); err == nil || !strings.HasSuffix(err.Error(), "] webhook_token is required") {
		t.Fatalf("webhook without token: %v", err)
	}
	if err := s.SetDeliveryConfig(ctx, m, authentication.DeliveryConfigInput{WebhookURL: "https://hook.acme.io", WebhookToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if repo.cfg.Provider != "webhook" || repo.secret.Sealed != "sealed:t" || repo.secret.WebhookToken != "" {
		t.Fatalf("webhook: %+v %+v", repo.cfg, repo.secret)
	}
}

func TestSetDeliveryConfigNeedsCipherForSecrets(t *testing.T) {
	s := NewDeliveryService(&memDelivery{}, nil, nil, nil, "")
	err := s.SetDeliveryConfig(context.Background(), deliveryMutation(), authentication.DeliveryConfigInput{Provider: "resend", FromEmail: "a@acme.io", APIKey: "re_1"})
	var e *errx.Error
	if !errx.As(err, &e) || e.Type != errx.TypeBusiness || !strings.Contains(e.Message, "IAMKIT_ENCRYPTION_KEY") {
		t.Fatalf("got %v", err)
	}
	// Webhook needs no key, as before.
	if err := s.SetDeliveryConfig(context.Background(), deliveryMutation(), authentication.DeliveryConfigInput{WebhookURL: "https://hook.acme.io", WebhookToken: "t"}); err != nil {
		t.Fatal(err)
	}
}

// A stored configuration that cannot be built fails the attempt with its
// reason and does not fall back to the global delivery.
func TestDeliverFactoryFailureDoesNotFallBack(t *testing.T) {
	repo := &memDelivery{cfg: &authentication.DeliveryConfig{Provider: "resend"}, secret: authentication.DeliverySecret{Sealed: "garbage"}}
	global := &recordingDelivery{}
	factory := func(authentication.DeliveryConfig, authentication.DeliverySecret) (authentication.Delivery, error) {
		return nil, authentication.DeliveryFailure(errors.New("open"), authentication.CodeDeliveryCredential)
	}
	s := NewDeliveryService(repo, global, factory, prefixCipher{}, "")
	attempt, err := s.deliver(context.Background(), identity.NewEnvironmentID(), authentication.Message{Email: "a@acme.io", Purpose: "login"})
	if err == nil || attempt.Delivered || attempt.Source != authentication.SourceEnvironment || attempt.Reason != "stored credential could not be decrypted" {
		t.Fatalf("attempt %+v err %v", attempt, err)
	}
	if len(global.got) != 0 {
		t.Fatal("fell back to the global delivery")
	}
}

// The message handed to a delivery carries its environment.
func TestDeliverStampsEnvironment(t *testing.T) {
	global := &recordingDelivery{}
	s := NewDeliveryService(&memDelivery{}, global, nil, nil, "")
	env := identity.NewEnvironmentID()
	if err := s.Send(context.Background(), env, authentication.Message{Email: "a@acme.io", Purpose: "login", Locale: "es"}); err != nil {
		t.Fatal(err)
	}
	if len(global.got) != 1 || global.got[0].Environment != env || global.got[0].Locale != "es" {
		t.Fatalf("got %+v", global.got)
	}
}

func TestDeliveryStatusProvider(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	s := NewDeliveryService(&memDelivery{}, nil, nil, nil, "")
	if st, _ := s.DeliveryStatus(ctx, env); st.Source != authentication.SourceNone || st.Provider != "" {
		t.Fatalf("none: %+v", st)
	}
	s = NewDeliveryService(&memDelivery{}, &recordingDelivery{}, nil, nil, "")
	if st, _ := s.DeliveryStatus(ctx, env); st.Source != authentication.SourceGlobal || st.Provider != "webhook" {
		t.Fatalf("global default: %+v", st)
	}
	s.SetGlobalProvider("smtp")
	if st, _ := s.DeliveryStatus(ctx, env); st.Provider != "smtp" {
		t.Fatalf("global smtp: %+v", st)
	}
	s = NewDeliveryService(&memDelivery{cfg: &authentication.DeliveryConfig{Provider: "resend"}}, &recordingDelivery{}, nil, nil, "")
	if st, _ := s.DeliveryStatus(ctx, env); st.Source != authentication.SourceEnvironment || st.Provider != "resend" {
		t.Fatalf("environment: %+v", st)
	}
}

// Without an invitation page, every provider (and no delivery at all) links
// to the hosted one.
func TestInvitationURL(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	const issuer = "https://id.acme.io"
	hosted := issuer + "/hosted/invite"
	for _, tc := range []struct {
		name   string
		cfg    *authentication.DeliveryConfig
		global string // "" = no global delivery
		want   string
	}{
		{"none", nil, "", hosted},
		{"global webhook", nil, "webhook", hosted},
		{"global smtp", nil, "smtp", hosted},
		{"webhook", &authentication.DeliveryConfig{Provider: "webhook"}, "", hosted},
		{"resend", &authentication.DeliveryConfig{Provider: "resend"}, "", hosted},
		{"own page", &authentication.DeliveryConfig{Provider: "smtp", InvitationURL: "https://app.acme.io/join"}, "", "https://app.acme.io/join"},
		{"own page over webhook", &authentication.DeliveryConfig{Provider: "webhook", InvitationURL: "https://app.acme.io/join"}, "smtp", "https://app.acme.io/join"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var global authentication.Delivery
			if tc.global != "" {
				global = &recordingDelivery{}
			}
			s := NewDeliveryService(&memDelivery{cfg: tc.cfg}, global, nil, nil, issuer+"/")
			if tc.global != "" {
				s.SetGlobalProvider(tc.global)
			}
			got, err := s.InvitationURL(ctx, env)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

type recordingRenderer struct {
	m     authentication.Message
	draft authentication.Draft
}

func (r *recordingRenderer) Render(_ context.Context, m authentication.Message, draft authentication.Draft) (authentication.Email, error) {
	r.m, r.draft = m, draft
	return authentication.Email{Subject: "s:" + m.Purpose, HTML: "<p>h</p>", Text: "t"}, nil
}

func TestPreview(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &memDelivery{}
	s := NewDeliveryService(repo, nil, nil, nil, "https://id.acme.io")
	if _, err := s.Preview(ctx, env, authentication.PreviewInput{Purpose: "login"}); err == nil {
		t.Fatal("previewed without a renderer")
	}
	r := &recordingRenderer{}
	s.SetRenderer(r)

	out, err := s.Preview(ctx, env, authentication.PreviewInput{Purpose: "login", Locale: "es-MX"})
	if err != nil || out.Subject != "s:login" || out.HTML != "<p>h</p>" || out.Text != "t" {
		t.Fatalf("got %+v, %v", out, err)
	}
	if r.m.Environment != env || r.m.Code == "" || r.m.Locale != "es" || r.draft != (authentication.Draft{}) {
		t.Fatalf("message %+v", r.m)
	}
	if _, err = s.Preview(ctx, env, authentication.PreviewInput{Purpose: "login", Locale: "eo"}); err != nil || r.m.Locale != "" {
		t.Fatalf("unsupported locale: %q, %v", r.m.Locale, err)
	}

	// Invitations link to the hosted page unless the environment has its own.
	if _, err = s.Preview(ctx, env, authentication.PreviewInput{Purpose: "invitation"}); err != nil {
		t.Fatal(err)
	}
	if r.m.Code != "" || r.m.Organization == "" || r.m.Inviter == "" || r.m.ExpiresAt == nil || !strings.HasPrefix(r.m.Link, "https://id.acme.io/hosted/invite?token=") {
		t.Fatalf("invitation %+v", r.m)
	}
	repo.cfg = &authentication.DeliveryConfig{Provider: "webhook", InvitationURL: "https://app.acme.io/join"}
	if _, err = s.Preview(ctx, env, authentication.PreviewInput{Purpose: "invitation"}); err != nil || !strings.HasPrefix(r.m.Link, "https://app.acme.io/join?token=") {
		t.Fatalf("own page %q, %v", r.m.Link, err)
	}

	draft, name := &authentication.Copy{Subject: "Hola {{code}}"}, "Globex"
	if _, err = s.Preview(ctx, env, authentication.PreviewInput{Purpose: "login", Template: draft, AppName: &name}); err != nil || r.draft.Copy != draft || r.draft.AppName != &name {
		t.Fatalf("draft %+v, %v", r.draft, err)
	}
	long := strings.Repeat("é", authentication.MaxAppName+1)
	for _, bad := range []authentication.PreviewInput{
		{Purpose: "nope"},
		{Purpose: "login", Template: &authentication.Copy{Subject: "{{link}}"}},
		{Purpose: "login", Template: &authentication.Copy{Action: "Go"}},
		{Purpose: "login", AppName: &long},
	} {
		if _, err = s.Preview(ctx, env, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if len(repo.attempts) != 0 {
		t.Fatal("a preview recorded an attempt")
	}
}
