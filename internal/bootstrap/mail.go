package bootstrap

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// WithMail configures emails IAMKit renders: the deployment default
// language, a deployment-wide SMTP/Resend sender (replacing the delivery
// passed to New), and, for tests, how environment providers are reached.
func WithMail(m authmodule.Mail) Option { return func(o *options) { o.mail = m } }

// mailFromEnv reads the deployment-wide email settings. EMAIL_PROVIDER
// defaults to webhook (EMAIL_WEBHOOK_URL/TOKEN, returned as the delivery);
// smtp and resend send email IAMKit renders. Every value is checked like
// an environment's configuration, so a typo fails at start.
func mailFromEnv() (authentication.Delivery, authmodule.Mail, error) {
	raw := strings.TrimSpace(os.Getenv("EMAIL_LOCALE"))
	mail := authmodule.Mail{Locale: i18n.Match(raw)} // "es-MX" → "es"
	if raw != "" && mail.Locale == "" {
		return nil, mail, errx.Validation("EMAIL_LOCALE must be one of the available languages")
	}
	private, err := allowPrivateDelivery()
	if err != nil {
		return nil, mail, err
	}
	if private {
		// Development only: environment webhooks and SMTP servers may be on
		// loopback or a private network (reopens SSRF from delivery settings).
		mail.Dial = (&net.Dialer{Timeout: config.ExternalHTTPTimeout}).DialContext
		mail.WebhookClient = http.DefaultTransport
		mail.SMSClient = http.DefaultTransport
		slog.Warn("IAMKIT_ALLOW_PRIVATE_DELIVERY is on: environment email/SMS webhooks, event webhooks and SMTP servers may reach localhost and private networks. Development only — never enable it in production")
	}
	port := 0
	if v := strings.TrimSpace(os.Getenv("SMTP_PORT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, mail, errx.Validation("SMTP_PORT must be a number")
		}
		port = n
	}
	input := authentication.DeliveryConfigInput{
		Provider:     os.Getenv("EMAIL_PROVIDER"),
		WebhookURL:   os.Getenv("EMAIL_WEBHOOK_URL"),
		WebhookToken: os.Getenv("EMAIL_WEBHOOK_TOKEN"),
		FromEmail:    os.Getenv("EMAIL_FROM"),
		FromName:     os.Getenv("EMAIL_FROM_NAME"),
		ReplyTo:      os.Getenv("EMAIL_REPLY_TO"),
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     port,
		SMTPUsername: os.Getenv("SMTP_USERNAME"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		SMTPTLS:      os.Getenv("SMTP_TLS"),
		APIKey:       os.Getenv("RESEND_API_KEY"),
	}.Normalize()

	if input.Provider == authentication.ProviderWebhook {
		// Unchanged behavior: no webhook URL means no global delivery; the
		// token was never required here.
		if input.WebhookURL == "" {
			return nil, mail, nil
		}
		// The deployment's own webhook may reach private hosts.
		webhook := authmail.WebhookDelivery{URL: input.WebhookURL, Token: input.WebhookToken, Transport: http.DefaultTransport}
		if err := webhook.Validate(); err != nil {
			return nil, mail, err
		}
		return webhook, mail, nil
	}
	if err := input.Validate(); err != nil {
		return nil, mail, envError(err)
	}
	sender := &authmodule.Sender{Provider: input.Provider, From: input.FromEmail, FromName: input.FromName, ReplyTo: input.ReplyTo}
	switch input.Provider {
	case authentication.ProviderSMTP:
		if input.SMTPUsername != "" && input.SMTPPassword == "" {
			return nil, mail, errx.Validation("SMTP_PASSWORD is required with SMTP_USERNAME")
		}
		// The deployment's own server may be internal: dial any address.
		sender.Mailer = authmail.SMTP{Host: input.SMTPHost, Port: input.SMTPPort, TLS: input.SMTPTLS, Username: input.SMTPUsername, Password: input.SMTPPassword, Dial: (&net.Dialer{}).DialContext}
	case authentication.ProviderResend:
		if input.APIKey == "" {
			return nil, mail, errx.Validation("RESEND_API_KEY is required")
		}
		sender.Mailer = authmail.Resend{APIKey: input.APIKey, Transport: http.DefaultTransport}
	}
	mail.Global = sender
	return nil, mail, nil
}

// allowPrivateDelivery reads IAMKIT_ALLOW_PRIVATE_DELIVERY (a boolean,
// default false).
func allowPrivateDelivery() (bool, error) {
	v := strings.TrimSpace(os.Getenv("IAMKIT_ALLOW_PRIVATE_DELIVERY"))
	if v == "" {
		return false, nil
	}
	on, err := strconv.ParseBool(v)
	if err != nil {
		return false, errx.Validation("IAMKIT_ALLOW_PRIVATE_DELIVERY must be true or false")
	}
	return on, nil
}

// envNames maps configuration fields to their environment variables.
var envNames = map[string]string{
	"provider": "EMAIL_PROVIDER", "webhook_url": "EMAIL_WEBHOOK_URL", "webhook_token": "EMAIL_WEBHOOK_TOKEN",
	"from_email": "EMAIL_FROM", "from_name": "EMAIL_FROM_NAME", "reply_to": "EMAIL_REPLY_TO",
	"smtp_host": "SMTP_HOST", "smtp_port": "SMTP_PORT", "smtp_username": "SMTP_USERNAME",
	"smtp_password": "SMTP_PASSWORD", "smtp_tls": "SMTP_TLS", "api_key": "RESEND_API_KEY",
}

// envError names environment variables instead of API fields.
func envError(err error) error {
	var e *errx.Error
	if !errx.As(err, &e) {
		return err
	}
	msg := e.Message
	for field, name := range envNames {
		msg = strings.ReplaceAll(msg, field+" ", name+" ")
	}
	return errx.Validation(msg)
}

// branding reads an environment's email brand from its hosted login
// branding (the environment default, not client styles), with an
// organization's overrides for invitations into it.
type branding struct{ queries hosted.Queries }

func (b branding) Brand(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (authentication.Brand, error) {
	s, err := b.queries.Branded(ctx, environment, identity.ClientID{}, organization)
	if err != nil {
		return authentication.Brand{}, err
	}
	out := authentication.Brand{Name: s.DisplayName, LogoURL: s.LogoURL, Accent: s.Theme.Light.Primary, Languages: s.Languages}
	if out.Accent == "" {
		out.Accent = s.AccentColor
	}
	if s.Locale != nil {
		out.Locale = *s.Locale
	}
	return out, nil
}
