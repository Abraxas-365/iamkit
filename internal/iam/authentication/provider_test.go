package authentication

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Rendering hints never reach the webhook payload.
func TestMessageRenderingFieldsNotSerialized(t *testing.T) {
	raw, err := json.Marshal(Message{Email: "a@b.example", Purpose: "login", Code: "1", Environment: identity.NewEnvironmentID(), Locale: "es"})
	if err != nil || string(raw) != `{"email":"a@b.example","purpose":"login","code":"1"}` {
		t.Fatalf("payload = %s %v", raw, err)
	}
}

func TestDeliveryConfigNormalize(t *testing.T) {
	if got := (DeliveryConfigInput{}).Normalize(); got.Provider != ProviderWebhook || got.SMTPPort != 0 || got.SMTPTLS != "" {
		t.Errorf("empty: %+v", got)
	}
	got := DeliveryConfigInput{Provider: " SMTP ", FromEmail: " No-Reply@Acme.io ", SMTPHost: "Smtp.Acme.io "}.Normalize()
	if got.Provider != ProviderSMTP || got.FromEmail != "no-reply@acme.io" || got.SMTPHost != "smtp.acme.io" || got.SMTPPort != 587 || got.SMTPTLS != SMTPStartTLS {
		t.Errorf("smtp defaults: %+v", got)
	}
	if got := (DeliveryConfigInput{Provider: "smtp", SMTPPort: 465}).Normalize(); got.SMTPTLS != SMTPImplicitTLS {
		t.Errorf("port 465 must default to implicit TLS: %q", got.SMTPTLS)
	}
	if got := (DeliveryConfigInput{Provider: "resend"}).Normalize(); got.SMTPPort != 0 || got.SMTPTLS != "" {
		t.Errorf("resend gets no SMTP defaults: %+v", got)
	}
}

func with(d DeliveryConfigInput, change func(*DeliveryConfigInput)) DeliveryConfigInput {
	change(&d)
	return d
}

func TestDeliveryConfigValidate(t *testing.T) {
	smtp := DeliveryConfigInput{Provider: "smtp", FromEmail: "no-reply@acme.io", SMTPHost: "smtp.acme.io"}.Normalize()
	resend := DeliveryConfigInput{Provider: "resend", FromEmail: "no-reply@acme.io", APIKey: "re_123"}.Normalize()
	for name, in := range map[string]DeliveryConfigInput{
		"smtp":                smtp,
		"smtp ip host":        with(smtp, func(d *DeliveryConfigInput) { d.SMTPHost = "203.0.113.5" }),
		"smtp sender name":    with(smtp, func(d *DeliveryConfigInput) { d.FromName, d.ReplyTo = "Acme Accounts", "help@acme.io" }),
		"smtp auth":           with(smtp, func(d *DeliveryConfigInput) { d.SMTPUsername, d.SMTPPassword = "apikey", "s3cret" }),
		"smtp invitation url": with(smtp, func(d *DeliveryConfigInput) { d.InvitationURL = "https://app.acme.io/join" }),
		"resend":              resend,
		"resend blank key":    with(resend, func(d *DeliveryConfigInput) { d.APIKey = "" }), // kept from storage, checked by the service
	} {
		if err := in.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for _, tc := range []struct {
		name string
		in   DeliveryConfigInput
		want string
	}{
		{"unknown provider", DeliveryConfigInput{Provider: "ses"}, "provider must be one of webhook, smtp, resend"},
		{"webhook url", DeliveryConfigInput{Provider: "webhook", WebhookURL: "http://x.io", WebhookToken: "t"}, "webhook_url must use HTTPS"},
		{"webhook token", DeliveryConfigInput{Provider: "webhook", WebhookURL: "https://x.io"}, "webhook_token is required"},
		{"webhook with sender", DeliveryConfigInput{Provider: "webhook", WebhookURL: "https://x.io", WebhookToken: "t", FromEmail: "a@x.io"}, "from_email is not used by provider webhook"},
		{"sender", with(smtp, func(d *DeliveryConfigInput) { d.FromEmail = "not-an-email" }), "from_email must be a valid address"},
		{"sender display form", with(smtp, func(d *DeliveryConfigInput) { d.FromEmail = "Acme <a@x.io>" }), "from_email must be a valid address"},
		{"sender name newline", with(smtp, func(d *DeliveryConfigInput) { d.FromName = "Acme\r\nBcc: x@evil.io" }), "from_name must be at most 100 characters on one line"},
		{"sender name long", with(smtp, func(d *DeliveryConfigInput) { d.FromName = strings.Repeat("á", 101) }), "from_name must be at most 100"},
		{"reply to", with(smtp, func(d *DeliveryConfigInput) { d.ReplyTo = "nope" }), "reply_to must be a valid address"},
		{"smtp host scheme", with(smtp, func(d *DeliveryConfigInput) { d.SMTPHost = "smtp://smtp.acme.io" }), "smtp_host must be a host name"},
		{"smtp host port", with(smtp, func(d *DeliveryConfigInput) { d.SMTPHost = "smtp.acme.io:587" }), "smtp_host must be a host name"},
		{"smtp host missing", with(smtp, func(d *DeliveryConfigInput) { d.SMTPHost = "" }), "smtp_host must be a host name"},
		{"smtp port", with(smtp, func(d *DeliveryConfigInput) { d.SMTPPort = 70000 }), "smtp_port must be between 1 and 65535"},
		{"smtp tls", with(smtp, func(d *DeliveryConfigInput) { d.SMTPTLS = "none" }), "smtp_tls must be starttls or tls"},
		{"smtp password newline", with(smtp, func(d *DeliveryConfigInput) { d.SMTPPassword = "a\nb" }), "smtp_password must be at most 1024"},
		{"smtp with api key", with(smtp, func(d *DeliveryConfigInput) { d.APIKey = "re_1" }), "api_key is not used by provider smtp"},
		{"smtp with webhook", with(smtp, func(d *DeliveryConfigInput) { d.WebhookURL = "https://x.io" }), "webhook_url is not used by provider smtp"},
		{"smtp invitation url", with(smtp, func(d *DeliveryConfigInput) { d.InvitationURL = "http://app.acme.io" }), "invitation_url must use HTTPS"},
		{"resend key spaces", with(resend, func(d *DeliveryConfigInput) { d.APIKey = "re 1" }), "api_key must be at most 1024 characters without spaces"},
		{"resend with smtp", with(resend, func(d *DeliveryConfigInput) { d.SMTPHost = "smtp.acme.io" }), "smtp_host is not used by provider resend"},
		{"resend sender", with(resend, func(d *DeliveryConfigInput) { d.FromEmail = "" }), "from_email must be a valid address"},
	} {
		err := tc.in.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestDeliveryConfigInputSecret(t *testing.T) {
	in := DeliveryConfigInput{WebhookToken: "w", SMTPPassword: "p", APIKey: "k"}
	for provider, want := range map[string]string{ProviderWebhook: "", ProviderSMTP: "p", ProviderResend: "k"} {
		in.Provider = provider
		if got := in.Secret(); got != want {
			t.Errorf("%s: %q", provider, got)
		}
	}
}

func TestPreviewInputValidate(t *testing.T) {
	for _, purpose := range PreviewPurposes {
		if err := (PreviewInput{Purpose: purpose, Locale: "es-MX"}).Validate(); err != nil {
			t.Errorf("%s: %v", purpose, err)
		}
	}
	if (PreviewInput{Purpose: "signup"}).Validate() == nil {
		t.Error("unknown purpose accepted")
	}
	if (PreviewInput{Purpose: "login", Locale: strings.Repeat("x", 36)}).Validate() == nil {
		t.Error("long locale accepted")
	}
}

// Webhook reasons are an API contract; provider reasons never leak causes.
func TestDescribe(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1:25: secret-host.internal refused")
	for _, tc := range []struct {
		err    error
		status int
		reason string
	}{
		{DeliveryRejected(503), 503, "webhook rejected the request"},
		{ErrDeliveryNotConfigured(), 0, "no webhook configured"},
		{DeliveryFailure(cause, CodeDeliveryTimeout), 0, "webhook did not respond in time"},
		{DeliveryFailure(cause, CodeDeliveryUnreachable), 0, "webhook could not be reached"},
		{DeliveryFailure(cause, CodeWebhookAddress), 0, "webhook address is not allowed"},
		{ProviderRejected(422), 422, "email provider rejected the request"},
		{ProviderRejected(0), 0, "email provider rejected the request"},
		{DeliveryFailure(cause, CodeProviderAuth), 0, "email provider rejected the credentials"},
		{DeliveryFailure(cause, CodeProviderTimeout), 0, "email provider did not respond in time"},
		{DeliveryFailure(cause, CodeProviderUnreachable), 0, "email provider could not be reached"},
		{DeliveryFailure(cause, CodeSMTPRejected), 0, "SMTP server rejected the message"},
		{DeliveryFailure(cause, CodeDeliveryCredential), 0, "stored credential could not be decrypted"},
		{DeliveryFailure(cause, CodeDeliveryAddress), 0, "email provider address is not allowed"},
		{cause, 0, "delivery failed"},
	} {
		status, reason := Describe(tc.err)
		if reason != tc.reason || (tc.status == 0) != (status == nil) || (status != nil && *status != tc.status) {
			t.Errorf("Describe(%v) = %v %q, want %d %q", tc.err, status, reason, tc.status, tc.reason)
		}
		if strings.Contains(reason, "secret-host") {
			t.Errorf("reason leaks cause: %q", reason)
		}
	}
}
