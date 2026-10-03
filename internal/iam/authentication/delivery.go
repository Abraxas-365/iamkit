package authentication

import (
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Message is what the mail webhook receives. Challenge messages carry a
// Code; invitation messages carry the Token, and a Link when the
// environment configured an invitation_url. Empty fields are omitted so the
// challenge payload stays {email,purpose,code}. Environment and Locale are
// for providers that render the email and never reach the webhook.
type Message struct {
	Email        string     `json:"email"`
	Purpose      string     `json:"purpose"`
	Code         string     `json:"code,omitempty"`
	Token        string     `json:"token,omitempty"`
	Link         string     `json:"link,omitempty"`
	Organization string     `json:"organization,omitempty"`
	Inviter      string     `json:"inviter,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`

	Environment identity.EnvironmentID `json:"-"`
	Locale      string                 `json:"-"` // requested language; "" = environment default
	// OrganizationID brands the email with the organization's overrides
	// (invitations into it); zero keeps the environment brand.
	OrganizationID identity.OrganizationID `json:"-"`
}

// Delivery providers: who sends an environment's email. The webhook
// receives the Message and writes the email itself; SMTP and Resend send
// an email IAMKit renders.
const (
	ProviderWebhook = "webhook"
	ProviderSMTP    = "smtp"
	ProviderResend  = "resend"
)

// SMTP transport security: STARTTLS upgrade (port 587) or implicit TLS
// (port 465). Plaintext is never configurable.
const (
	SMTPStartTLS    = "starttls"
	SMTPImplicitTLS = "tls"
)

// DeliveryConfig is a per-environment delivery configuration for challenge
// codes and invitations. When set, it overrides the global delivery for
// that environment. Secrets are never returned: HasToken reports the
// webhook token, HasSecret the SMTP password or Resend API key.
type DeliveryConfig struct {
	EnvironmentID identity.EnvironmentID `json:"environment_id"`
	Provider      string                 `json:"provider"`
	WebhookURL    string                 `json:"webhook_url"`
	HasToken      bool                   `json:"has_token"`
	InvitationURL string                 `json:"invitation_url"`
	FromEmail     string                 `json:"from_email"`
	FromName      string                 `json:"from_name"`
	ReplyTo       string                 `json:"reply_to"`
	SMTPHost      string                 `json:"smtp_host"`
	SMTPPort      int                    `json:"smtp_port"`
	SMTPUsername  string                 `json:"smtp_username"`
	SMTPTLS       string                 `json:"smtp_tls"`
	HasSecret     bool                   `json:"has_secret"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// DeliverySecret is the stored credential of a delivery configuration: the
// sealed SMTP password, Resend API key or webhook token, or a webhook token
// in plaintext (saved without IAMKIT_ENCRYPTION_KEY, or before it was sealed).
type DeliverySecret struct {
	WebhookToken string
	Sealed       string
}

// DeliveryConfigInput is the write payload for creating or updating a
// per-environment delivery configuration. Provider defaults to webhook.
// InvitationURL is optional for every provider: the page of the customer's
// app that accepts invitations; the token is added as the "token" query
// parameter. SMTPPassword and APIKey are write-only; left blank on an update
// that keeps the provider, the stored one is kept.
type DeliveryConfigInput struct {
	Provider      string `json:"provider"`
	WebhookURL    string `json:"webhook_url"`
	WebhookToken  string `json:"webhook_token"`
	InvitationURL string `json:"invitation_url"`
	FromEmail     string `json:"from_email"`
	FromName      string `json:"from_name"`
	ReplyTo       string `json:"reply_to"`
	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	SMTPUsername  string `json:"smtp_username"`
	SMTPPassword  string `json:"smtp_password"`
	SMTPTLS       string `json:"smtp_tls"`
	APIKey        string `json:"api_key"`
}

// Secret returns the provider secret of the input (SMTP password or Resend
// API key); the webhook token is not one of them.
func (d DeliveryConfigInput) Secret() string {
	switch d.Provider {
	case ProviderSMTP:
		return d.SMTPPassword
	case ProviderResend:
		return d.APIKey
	}
	return ""
}

// Email is a rendered email ready for a Mailer.
type Email struct {
	From     string // address
	FromName string
	ReplyTo  string
	To       string
	Subject  string
	HTML     string
	Text     string
}

// Brand is how an environment's rendered emails look and which language
// they default to (Locale "" = server default). Languages are the
// languages they may be written in (empty: every available one).
type Brand struct {
	Name      string
	LogoURL   string
	Accent    string
	Locale    string
	Languages []string
}

// Delivery sources: which webhook serves an environment.
const (
	SourceEnvironment = "environment" // the environment's own configuration
	SourceGlobal      = "global"      // EMAIL_WEBHOOK_URL fallback
	SourceNone        = "none"        // nothing can deliver
)

// PurposeTest marks a test message sent from the console; it carries no
// code or token.
const PurposeTest = "test"

// Mutation attributes an audited delivery change.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Attempt is the outcome of one delivery. Reason is a fixed, secret-free
// description; Status is the webhook's HTTP status when it answered.
type Attempt struct {
	Source    string    `json:"source"`
	Purpose   string    `json:"purpose"`
	Delivered bool      `json:"delivered"`
	Status    *int      `json:"status,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	LatencyMS int       `json:"latency_ms"`
	At        time.Time `json:"at"`
}

// Activity is the latest delivery attempt of an environment and the latest
// failure, which survives later successes.
type Activity struct {
	Last        *Attempt `json:"last_attempt"`
	LastFailure *Attempt `json:"last_failure"`
}

// DeliveryStatus says which configuration serves the environment and its
// provider ("" when none), never exposing the global settings or any
// secret. HostedInvitationURL is IAMKit's own invitation page, usable as
// invitation_url.
type DeliveryStatus struct {
	Source              string `json:"source"`
	Provider            string `json:"provider"`
	GlobalConfigured    bool   `json:"global_configured"`
	HostedInvitationURL string `json:"hosted_invitation_url"`
	Activity
}

// PreviewInput selects a sample email to render: its purpose and language
// ("" = environment default).
type PreviewInput struct {
	Purpose string `json:"purpose"`
	Locale  string `json:"locale"`
	// Template is unsaved wording to preview instead of the saved one.
	Template *Copy `json:"template,omitempty"`
	// AppName is an unsaved brand name ({{app_name}}, the email header) to
	// preview instead of the saved one; "" previews the default.
	AppName *string `json:"app_name,omitempty"`
}

// MaxAppName is the longest brand name, in characters (the hosted
// branding's display_name, where it is saved).
const MaxAppName = 100

// PreviewPurposes are the emails IAMKit renders.
var PreviewPurposes = []string{PurposeLogin, PurposePasswordReset, PurposeEmailVerification, PurposeInvitation, PurposeMFA, PurposeTest}

// Validate checks the purpose and draft wording; an unknown locale falls
// back like any other.
func (p PreviewInput) Validate() error {
	if !slices.Contains(PreviewPurposes, p.Purpose) {
		return errx.Validation("purpose must be one of " + strings.Join(PreviewPurposes, ", "))
	}
	if len(p.Locale) > 35 {
		return errx.Validation("locale is too long")
	}
	if p.AppName != nil && utf8.RuneCountInString(strings.TrimSpace(*p.AppName)) > MaxAppName {
		return errx.Validation("app_name must be at most 100 characters")
	}
	if p.Template != nil {
		return p.Template.Validate(p.Purpose)
	}
	return nil
}

// Draft is unsaved wording and brand name a preview renders instead of the
// saved ones; nil fields use the saved values.
type Draft struct {
	Copy    *Copy
	AppName *string
}

// Preview is a rendered sample email; nothing is sent.
type Preview struct {
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
}

// TestInput asks for a test message to Email.
type TestInput struct {
	Email string `json:"email"`
}

// Validate checks the recipient address.
func (t TestInput) Validate() error {
	if _, err := identity.Email(t.Email); err != nil {
		return errx.Validation("email must be a valid address")
	}
	return nil
}

// Delivery failure codes set by delivery adapters on their errors; Describe
// turns them into the stored reason.
const (
	CodeDeliveryRejected    = "DELIVERY_REJECTED"
	CodeDeliveryTimeout     = "DELIVERY_TIMEOUT"
	CodeDeliveryUnreachable = "DELIVERY_UNREACHABLE"
	CodeDeliveryUnavailable = "DELIVERY_NOT_CONFIGURED"
	CodeWebhookAddress      = "DELIVERY_WEBHOOK_ADDRESS"
	// Email providers (SMTP, Resend).
	CodeProviderRejected    = "DELIVERY_PROVIDER_REJECTED"
	CodeProviderAuth        = "DELIVERY_PROVIDER_AUTH"
	CodeProviderTimeout     = "DELIVERY_PROVIDER_TIMEOUT"
	CodeProviderUnreachable = "DELIVERY_PROVIDER_UNREACHABLE"
	CodeSMTPRejected        = "DELIVERY_SMTP_REJECTED"
	CodeDeliveryCredential  = "DELIVERY_CREDENTIAL"
	CodeDeliveryAddress     = "DELIVERY_ADDRESS"
)

// DeliveryRejected is a non-2xx webhook answer.
func DeliveryRejected(status int) error {
	e := errx.External("email delivery rejected").WithDetail("status", status)
	e.Code = CodeDeliveryRejected
	return e
}

// ErrDeliveryNotConfigured is returned when no webhook serves the environment.
func ErrDeliveryNotConfigured() error {
	e := errx.External("email delivery is not configured")
	e.Code = CodeDeliveryUnavailable
	return e
}

// ProviderRejected is a non-2xx answer of an email provider API; status 0
// means none is known.
func ProviderRejected(status int) error {
	e := errx.External("email provider rejected the request")
	if status != 0 {
		e = e.WithDetail("status", status)
	}
	e.Code = CodeProviderRejected
	return e
}

// DeliveryFailure is a provider failure of kind code (one of the Code*
// constants) wrapping cause, which Describe never exposes.
func DeliveryFailure(cause error, code string) error {
	e := errx.Wrap(cause, "email delivery failed", errx.TypeExternal)
	e.Code = code
	return e
}

// reasons are the fixed descriptions of delivery failure codes. Webhook
// reasons are part of the console and API contract: do not reword them.
var reasons = map[string]string{
	CodeDeliveryRejected:    "webhook rejected the request",
	CodeDeliveryTimeout:     "webhook did not respond in time",
	CodeDeliveryUnreachable: "webhook could not be reached",
	CodeDeliveryUnavailable: "no webhook configured",
	CodeWebhookAddress:      "webhook address is not allowed",
	CodeProviderRejected:    "email provider rejected the request",
	CodeProviderAuth:        "email provider rejected the credentials",
	CodeProviderTimeout:     "email provider did not respond in time",
	CodeProviderUnreachable: "email provider could not be reached",
	CodeSMTPRejected:        "SMTP server rejected the message",
	CodeDeliveryCredential:  "stored credential could not be decrypted",
	CodeDeliveryAddress:     "email provider address is not allowed",
	// SMS providers.
	CodeSMSUnavailable:         "no SMS provider configured",
	CodeSMSProviderRejected:    "SMS provider rejected the request",
	CodeSMSProviderAuth:        "SMS provider rejected the credentials",
	CodeSMSProviderTimeout:     "SMS provider did not respond in time",
	CodeSMSProviderUnreachable: "SMS provider could not be reached",
}

// Describe classifies a delivery error into a status (when the webhook or
// provider API answered) and a fixed reason that never contains the cause,
// which may include URLs, addresses or response details.
func Describe(err error) (*int, string) {
	var e *errx.Error
	if !errx.As(err, &e) {
		return nil, "delivery failed"
	}
	if reason, ok := reasons[e.Code]; ok {
		if status, ok := e.Details["status"].(int); ok {
			return &status, reason
		}
		return nil, reason
	}
	if e.Type == errx.TypeValidation {
		return nil, "webhook URL is not allowed"
	}
	return nil, "delivery failed"
}

// Normalize fills defaults: the webhook provider, trimmed settings, a
// lowercase sender, and for SMTP port 587 and the TLS mode that matches
// the port (465 implicit TLS, otherwise STARTTLS).
func (d DeliveryConfigInput) Normalize() DeliveryConfigInput {
	d.Provider = strings.ToLower(strings.TrimSpace(d.Provider))
	if d.Provider == "" {
		d.Provider = ProviderWebhook
	}
	d.FromEmail = strings.ToLower(strings.TrimSpace(d.FromEmail))
	d.FromName = strings.TrimSpace(d.FromName)
	d.ReplyTo = strings.ToLower(strings.TrimSpace(d.ReplyTo))
	d.SMTPHost = strings.ToLower(strings.TrimSpace(d.SMTPHost))
	d.SMTPUsername = strings.TrimSpace(d.SMTPUsername)
	d.SMTPTLS = strings.ToLower(strings.TrimSpace(d.SMTPTLS))
	if d.Provider == ProviderSMTP {
		if d.SMTPPort == 0 {
			d.SMTPPort = 587
		}
		if d.SMTPTLS == "" {
			d.SMTPTLS = SMTPStartTLS
			if d.SMTPPort == 465 {
				d.SMTPTLS = SMTPImplicitTLS
			}
		}
	}
	return d
}

// Validate checks structural invariants for the (normalized) delivery
// config input. Whether a provider secret is required depends on the
// stored configuration and is checked by the service.
func (d DeliveryConfigInput) Validate() error {
	switch d.Provider {
	case ProviderWebhook, "":
		return d.validateWebhook()
	case ProviderSMTP, ProviderResend:
		if d.InvitationURL != "" && !SecureURL(d.InvitationURL) {
			return errx.Validation("invitation_url must use HTTPS (HTTP allowed only on loopback)")
		}
		if d.Provider == ProviderSMTP {
			return d.validateSMTP()
		}
		return d.validateResend()
	}
	return errx.Validation("provider must be one of webhook, smtp, resend")
}

func (d DeliveryConfigInput) validateWebhook() error {
	if !SecureURL(d.WebhookURL) {
		return errx.Validation("webhook_url must use HTTPS (HTTP allowed only on loopback)")
	}
	if strings.TrimSpace(d.WebhookToken) == "" {
		return errx.Validation("webhook_token is required")
	}
	if d.InvitationURL != "" && !SecureURL(d.InvitationURL) {
		return errx.Validation("invitation_url must use HTTPS (HTTP allowed only on loopback)")
	}
	return d.unused(ProviderWebhook, map[string]bool{
		"from_email": d.FromEmail != "", "from_name": d.FromName != "", "reply_to": d.ReplyTo != "",
		"smtp_host": d.SMTPHost != "", "smtp_port": d.SMTPPort != 0, "smtp_username": d.SMTPUsername != "",
		"smtp_password": d.SMTPPassword != "", "smtp_tls": d.SMTPTLS != "", "api_key": d.APIKey != "",
	})
}

func (d DeliveryConfigInput) validateSMTP() error {
	if err := d.validateSender(); err != nil {
		return err
	}
	if !validHost(d.SMTPHost) {
		return errx.Validation("smtp_host must be a host name or IP address, without scheme or port")
	}
	if d.SMTPPort < 1 || d.SMTPPort > 65535 {
		return errx.Validation("smtp_port must be between 1 and 65535")
	}
	if d.SMTPTLS != SMTPStartTLS && d.SMTPTLS != SMTPImplicitTLS {
		return errx.Validation("smtp_tls must be starttls or tls")
	}
	if len(d.SMTPUsername) > 256 || hasControl(d.SMTPUsername) {
		return errx.Validation("smtp_username must be at most 256 characters on one line")
	}
	if len(d.SMTPPassword) > 1024 || hasControl(d.SMTPPassword) {
		return errx.Validation("smtp_password must be at most 1024 characters on one line")
	}
	if d.SMTPPassword != "" && d.SMTPUsername == "" {
		return errx.Validation("smtp_password requires smtp_username")
	}
	return d.unused(ProviderSMTP, map[string]bool{
		"webhook_url": d.WebhookURL != "", "webhook_token": d.WebhookToken != "", "api_key": d.APIKey != "",
	})
}

func (d DeliveryConfigInput) validateResend() error {
	if err := d.validateSender(); err != nil {
		return err
	}
	if len(d.APIKey) > 1024 || hasControl(d.APIKey) || strings.ContainsRune(d.APIKey, ' ') {
		return errx.Validation("api_key must be at most 1024 characters without spaces")
	}
	return d.unused(ProviderResend, map[string]bool{
		"webhook_url": d.WebhookURL != "", "webhook_token": d.WebhookToken != "",
		"smtp_host": d.SMTPHost != "", "smtp_port": d.SMTPPort != 0, "smtp_username": d.SMTPUsername != "",
		"smtp_password": d.SMTPPassword != "", "smtp_tls": d.SMTPTLS != "",
	})
}

func (d DeliveryConfigInput) validateSender() error {
	if email, err := identity.Email(d.FromEmail); err != nil || email != d.FromEmail {
		return errx.Validation("from_email must be a valid address")
	}
	if utf8.RuneCountInString(d.FromName) > 100 || hasControl(d.FromName) {
		return errx.Validation("from_name must be at most 100 characters on one line")
	}
	if d.ReplyTo != "" {
		if email, err := identity.Email(d.ReplyTo); err != nil || email != d.ReplyTo {
			return errx.Validation("reply_to must be a valid address")
		}
	}
	return nil
}

// unused rejects settings of other providers, in a stable field order.
func (d DeliveryConfigInput) unused(provider string, set map[string]bool) error {
	fields := make([]string, 0, len(set))
	for field, present := range set {
		if present {
			fields = append(fields, field)
		}
	}
	if len(fields) == 0 {
		return nil
	}
	slices.Sort(fields)
	return errx.Validation(fields[0] + " is not used by provider " + provider)
}

// validHost accepts a DNS name or an IP address literal.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// hasControl reports control characters (CR/LF would inject headers).
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// SecureURL reports whether raw is an absolute HTTPS URL, or HTTP on
// loopback, without credentials or fragment.
func SecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))
}

// InvitationLink appends the invitation token to an invitation_url; an
// empty base yields no link.
func InvitationLink(base, token string) string {
	u, err := url.Parse(base)
	if base == "" || err != nil {
		return ""
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String()
}
