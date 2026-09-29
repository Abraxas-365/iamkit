package authsvc

import (
	"context"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type memSMS struct {
	cfg      *authentication.SMSConfig
	sealed   string
	attempts []authentication.Attempt
	audits   []authentication.Mutation
}

func (m *memSMS) GetSMSConfig(context.Context, identity.EnvironmentID) (authentication.SMSConfig, string, error) {
	if m.cfg == nil {
		return authentication.SMSConfig{}, "", errx.NotFound("SMS configuration not found")
	}
	return *m.cfg, m.sealed, nil
}

func (m *memSMS) SetSMSConfig(_ context.Context, mu authentication.Mutation, in authentication.SMSConfigInput, sealed string) error {
	m.cfg = &authentication.SMSConfig{EnvironmentID: mu.Environment, Provider: in.Provider, AccountSID: in.AccountSID, FromNumber: in.FromNumber, WebhookURL: in.WebhookURL, HasSecret: sealed != ""}
	m.sealed = sealed
	m.audits = append(m.audits, mu)
	return nil
}

func (m *memSMS) DeleteSMSConfig(_ context.Context, mu authentication.Mutation) error {
	if m.cfg == nil {
		return errx.NotFound("SMS configuration not found")
	}
	m.cfg, m.sealed = nil, ""
	m.audits = append(m.audits, mu)
	return nil
}

func (m *memSMS) RecordSMSAttempt(_ context.Context, _ identity.EnvironmentID, a authentication.Attempt) error {
	m.attempts = append(m.attempts, a)
	return nil
}

func (m *memSMS) SMSActivity(context.Context, identity.EnvironmentID) (authentication.Activity, error) {
	if len(m.attempts) == 0 {
		return authentication.Activity{}, nil
	}
	return authentication.Activity{Last: &m.attempts[len(m.attempts)-1]}, nil
}

func (m *memSMS) Audit(_ context.Context, mu authentication.Mutation) error {
	m.audits = append(m.audits, mu)
	return nil
}

type recordSMS struct {
	sent   []authentication.SMS
	secret string
	err    error
}

func (r *recordSMS) factory(_ authentication.SMSConfig, secret string) (authentication.SMSDelivery, error) {
	r.secret = secret
	return r, nil
}

func (r *recordSMS) SendSMS(_ context.Context, m authentication.SMS) error {
	r.sent = append(r.sent, m)
	return r.err
}

// twilioSID is a syntactically valid fake, built at run time so secret
// scanners do not flag it.
var twilioSID = "AC" + strings.Repeat("0123456789abcdef", 2)

func TestSMSConfig(t *testing.T) {
	repo, sender := &memSMS{}, &recordSMS{}
	s := NewSMSService(repo, sender.factory, prefixCipher{}, nil, "en")
	ctx, m := context.Background(), authentication.Mutation{Environment: identity.NewEnvironmentID(), Actor: "op"}

	if err := s.SetSMSConfig(ctx, m, authentication.SMSConfigInput{Provider: "twilio", AccountSID: twilioSID, FromNumber: "+15550001111"}); err == nil {
		t.Fatal("twilio without an auth token accepted")
	}
	if err := s.SetSMSConfig(ctx, m, authentication.SMSConfigInput{Provider: " Twilio ", AccountSID: twilioSID, AuthToken: "tok", FromNumber: "+15550001111"}); err != nil {
		t.Fatal(err)
	}
	if repo.sealed != "sealed:tok" || repo.audits[0].Action != authentication.ActionSMSUpdate {
		t.Fatalf("stored %q %+v", repo.sealed, repo.audits)
	}
	// Blank token on the same provider keeps the stored one.
	if err := s.SetSMSConfig(ctx, m, authentication.SMSConfigInput{Provider: "twilio", AccountSID: twilioSID, MessagingServiceSID: "MG0123456789abcdef0123456789abcdef"}); err != nil || repo.sealed != "sealed:tok" {
		t.Fatalf("keep secret: %v %q", err, repo.sealed)
	}
	// Switching provider needs the new provider's secret.
	if err := s.SetSMSConfig(ctx, m, authentication.SMSConfigInput{Provider: "webhook", WebhookURL: "https://sms.example.com"}); err == nil {
		t.Fatal("webhook without a token accepted")
	}
	for _, bad := range []authentication.SMSConfigInput{
		{Provider: "fax"},
		{Provider: "twilio", AccountSID: "nope", AuthToken: "x", FromNumber: "+15550001111"},
		{Provider: "twilio", AccountSID: twilioSID, AuthToken: "x", FromNumber: "555"},
		{Provider: "twilio", AccountSID: twilioSID, AuthToken: "x"},
		{Provider: "webhook", WebhookURL: "http://sms.example.com", WebhookToken: "x"},
		{Provider: "webhook", WebhookURL: "https://sms.example.com", WebhookToken: "x", AccountSID: twilioSID},
	} {
		if err := s.SetSMSConfig(ctx, m, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	st, err := s.SMSStatus(ctx, m.Environment)
	if err != nil || !st.Configured || st.Provider != "twilio" {
		t.Fatalf("status %+v %v", st, err)
	}
	if err := s.DeleteSMSConfig(ctx, m); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.SMSStatus(ctx, m.Environment); st.Configured {
		t.Fatal("still configured")
	}
}

func TestSendSMS(t *testing.T) {
	env := identity.NewEnvironmentID()
	repo := &memSMS{cfg: &authentication.SMSConfig{EnvironmentID: env, Provider: "twilio"}, sealed: "sealed:tok"}
	sender := &recordSMS{}
	s := NewSMSService(repo, sender.factory, prefixCipher{}, nil, "es")
	ctx := context.Background()
	if err := s.SendSMS(ctx, env, "+15551234567", authentication.SMSPurposeMFA, "123456"); err != nil {
		t.Fatal(err)
	}
	got := sender.sent[0]
	if sender.secret != "tok" || got.Code != "123456" || !strings.HasPrefix(got.Body, "123456 es tu código") || !strings.Contains(got.Body, "IAMKit") {
		t.Fatalf("sent %+v (secret %q)", got, sender.secret)
	}
	if a := repo.attempts[0]; !a.Delivered || a.Purpose != "mfa" || a.Source != authentication.SourceEnvironment {
		t.Fatalf("attempt %+v", a)
	}
	if err := s.SendSMS(ctx, env, "+15551234567", "login", "1"); err == nil {
		t.Fatal("email purpose texted")
	}

	sender.err = authentication.SMSRejected(400)
	if err := s.SendSMS(ctx, env, "+15551234567", authentication.SMSPurposePhone, "654321"); err == nil {
		t.Fatal("rejection swallowed")
	}
	if a := repo.attempts[1]; a.Delivered || a.Reason != "SMS provider rejected the request" || a.Status == nil || *a.Status != 400 {
		t.Fatalf("failed attempt %+v", a)
	}

	// Test sends are audited and return the attempt, delivered or not.
	sender.err = nil
	m := authentication.Mutation{Environment: env, Actor: "op"}
	if _, err := s.TestSMS(ctx, m, authentication.SMSTestInput{Phone: "555"}); err == nil {
		t.Fatal("bad phone accepted")
	}
	a, err := s.TestSMS(ctx, m, authentication.SMSTestInput{Phone: "+15551234567"})
	if err != nil || !a.Delivered || repo.audits[len(repo.audits)-1].Action != authentication.ActionSMSTest {
		t.Fatalf("test %+v %v", a, err)
	}

	repo.cfg = nil
	var e *errx.Error
	if err := s.SendSMS(ctx, env, "+15551234567", "mfa", "1"); !errx.As(err, &e) || e.Code != authentication.CodeSMSUnavailable {
		t.Fatalf("unconfigured: %v", err)
	}
}
