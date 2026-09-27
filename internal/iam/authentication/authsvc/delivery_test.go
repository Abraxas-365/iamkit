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

	// Webhook stores no sealed secret and still requires its token.
	if err := s.SetDeliveryConfig(ctx, m, authentication.DeliveryConfigInput{WebhookURL: "https://hook.acme.io"}); err == nil || !strings.HasSuffix(err.Error(), "] webhook_token is required") {
		t.Fatalf("webhook without token: %v", err)
	}
	if err := s.SetDeliveryConfig(ctx, m, authentication.DeliveryConfigInput{WebhookURL: "https://hook.acme.io", WebhookToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if repo.cfg.Provider != "webhook" || repo.secret.Sealed != "" || repo.secret.WebhookToken != "t" {
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
