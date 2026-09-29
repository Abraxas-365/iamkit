package bootstrap

import (
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
)

var mailEnv = []string{"EMAIL_PROVIDER", "EMAIL_WEBHOOK_URL", "EMAIL_WEBHOOK_TOKEN", "EMAIL_FROM", "EMAIL_FROM_NAME", "EMAIL_REPLY_TO", "EMAIL_LOCALE",
	"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_TLS", "RESEND_API_KEY", "IAMKIT_ALLOW_PRIVATE_DELIVERY"}

func setMailEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range mailEnv {
		t.Setenv(k, env[k])
	}
}

func TestMailFromEnvWebhook(t *testing.T) {
	setMailEnv(t, nil)
	delivery, mail, err := mailFromEnv()
	if err != nil || delivery != nil || mail.Global != nil {
		t.Fatalf("unset: %v %v %+v", delivery, err, mail)
	}

	// Unchanged: a URL alone (no token) is a webhook.
	setMailEnv(t, map[string]string{"EMAIL_WEBHOOK_URL": "https://mail.acme.io/hook", "EMAIL_LOCALE": "ES"})
	delivery, mail, err = mailFromEnv()
	if err != nil || mail.Global != nil || mail.Locale != "es" {
		t.Fatalf("webhook: %v %+v", err, mail)
	}
	if w, ok := delivery.(authmail.WebhookDelivery); !ok || w.URL != "https://mail.acme.io/hook" {
		t.Fatalf("webhook delivery %#v", delivery)
	}

	setMailEnv(t, map[string]string{"EMAIL_WEBHOOK_URL": "http://mail.acme.io/hook"})
	if _, _, err = mailFromEnv(); err == nil {
		t.Fatal("accepted a plain-HTTP webhook")
	}
}

func TestMailFromEnvProviders(t *testing.T) {
	setMailEnv(t, map[string]string{"EMAIL_PROVIDER": "smtp", "EMAIL_FROM": "no-reply@acme.io", "EMAIL_FROM_NAME": "Acme",
		"SMTP_HOST": "smtp.internal", "SMTP_PORT": "587", "SMTP_TLS": "starttls", "SMTP_USERNAME": "u", "SMTP_PASSWORD": "p"})
	delivery, mail, err := mailFromEnv()
	if err != nil || delivery != nil || mail.Global == nil {
		t.Fatalf("smtp: %v %v %+v", delivery, err, mail)
	}
	smtp, ok := mail.Global.Mailer.(authmail.SMTP)
	if !ok || mail.Global.Provider != "smtp" || mail.Global.From != "no-reply@acme.io" || mail.Global.FromName != "Acme" ||
		smtp.Host != "smtp.internal" || smtp.Port != 587 || smtp.Password != "p" || smtp.Dial == nil {
		t.Fatalf("smtp sender %+v", mail.Global)
	}

	setMailEnv(t, map[string]string{"EMAIL_PROVIDER": "resend", "EMAIL_FROM": "no-reply@acme.io", "RESEND_API_KEY": "re_123"})
	if _, mail, err = mailFromEnv(); err != nil || mail.Global == nil || mail.Global.Provider != "resend" {
		t.Fatalf("resend: %v %+v", err, mail)
	}
	if r, ok := mail.Global.Mailer.(authmail.Resend); !ok || r.APIKey != "re_123" || r.Transport == nil {
		t.Fatalf("resend sender %#v", mail.Global.Mailer)
	}
}

func TestMailFromEnvErrors(t *testing.T) {
	smtp := map[string]string{"EMAIL_PROVIDER": "smtp", "EMAIL_FROM": "no-reply@acme.io", "SMTP_HOST": "smtp.acme.io", "SMTP_PORT": "587", "SMTP_TLS": "starttls"}
	with := func(k, v string) map[string]string {
		out := map[string]string{}
		for key, val := range smtp {
			out[key] = val
		}
		out[k] = v
		return out
	}
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"EMAIL_PROVIDER": "sendgrid"}, "EMAIL_PROVIDER"},
		{map[string]string{"EMAIL_LOCALE": "xx"}, "EMAIL_LOCALE"},
		{with("SMTP_PORT", "abc"), "SMTP_PORT"},
		{with("SMTP_PORT", "70000"), "SMTP_PORT"},
		{with("SMTP_HOST", "smtp://x"), "SMTP_HOST"},
		{with("EMAIL_FROM", ""), "EMAIL_FROM"},
		{with("SMTP_USERNAME", "u"), "SMTP_PASSWORD"},
		{map[string]string{"EMAIL_PROVIDER": "resend", "EMAIL_FROM": "no-reply@acme.io"}, "RESEND_API_KEY"},
		{map[string]string{"IAMKIT_ALLOW_PRIVATE_DELIVERY": "maybe"}, "IAMKIT_ALLOW_PRIVATE_DELIVERY"},
	} {
		setMailEnv(t, tc.env)
		_, _, err := mailFromEnv()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: got %v, want mention of %s", tc.env, err, tc.want)
		}
	}
}

// IAMKIT_ALLOW_PRIVATE_DELIVERY replaces the guarded dialer/transport of
// environment webhooks and SMTP servers; off (the default) keeps them.
func TestMailFromEnvAllowPrivate(t *testing.T) {
	for v, on := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true, "TRUE": true} {
		setMailEnv(t, map[string]string{"IAMKIT_ALLOW_PRIVATE_DELIVERY": v})
		_, mail, err := mailFromEnv()
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if (mail.WebhookClient != nil) != on || (mail.Dial != nil) != on || mail.ResendClient != nil {
			t.Fatalf("%q: webhook=%v dial=%v resend=%v, want private=%v", v, mail.WebhookClient != nil, mail.Dial != nil, mail.ResendClient != nil, on)
		}
	}
	// Combined with a global provider, both apply.
	setMailEnv(t, map[string]string{"IAMKIT_ALLOW_PRIVATE_DELIVERY": "true", "EMAIL_PROVIDER": "resend", "EMAIL_FROM": "no-reply@acme.io", "RESEND_API_KEY": "re_1"})
	if _, mail, err := mailFromEnv(); err != nil || mail.Global == nil || mail.WebhookClient == nil {
		t.Fatalf("with global: %v %+v", err, mail)
	}
}
