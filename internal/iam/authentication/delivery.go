package authentication

import (
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Message is what the mail webhook receives. Challenge messages carry a
// Code; invitation messages carry the Token, and a Link when the
// environment configured an invitation_url. Empty fields are omitted so the
// challenge payload stays {email,purpose,code}.
type Message struct {
	Email        string     `json:"email"`
	Purpose      string     `json:"purpose"`
	Code         string     `json:"code,omitempty"`
	Token        string     `json:"token,omitempty"`
	Link         string     `json:"link,omitempty"`
	Organization string     `json:"organization,omitempty"`
	Inviter      string     `json:"inviter,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// DeliveryConfig is a per-environment webhook configuration for challenge
// code and invitation delivery. When set, it overrides the global
// EMAIL_WEBHOOK_URL for that environment.
type DeliveryConfig struct {
	EnvironmentID identity.EnvironmentID `json:"environment_id"`
	WebhookURL    string                 `json:"webhook_url"`
	HasToken      bool                   `json:"has_token"`
	InvitationURL string                 `json:"invitation_url"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// DeliveryConfigInput is the write payload for creating or updating a
// per-environment delivery configuration. InvitationURL is optional: the
// page of the customer's app that accepts invitations; the token is added
// as the "token" query parameter.
type DeliveryConfigInput struct {
	WebhookURL    string `json:"webhook_url"`
	WebhookToken  string `json:"webhook_token"`
	InvitationURL string `json:"invitation_url"`
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

// DeliveryStatus says which webhook serves the environment, never exposing
// the global URL or any token. HostedInvitationURL is IAMKit's own
// invitation page, usable as invitation_url.
type DeliveryStatus struct {
	Source              string `json:"source"`
	GlobalConfigured    bool   `json:"global_configured"`
	HostedInvitationURL string `json:"hosted_invitation_url"`
	Activity
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

// Describe classifies a delivery error into a status (when the webhook
// answered) and a fixed reason that never contains the cause, which may
// include URLs or response details.
func Describe(err error) (*int, string) {
	var e *errx.Error
	if !errx.As(err, &e) {
		return nil, "delivery failed"
	}
	switch e.Code {
	case CodeDeliveryRejected:
		if status, ok := e.Details["status"].(int); ok {
			return &status, "webhook rejected the request"
		}
		return nil, "webhook rejected the request"
	case CodeDeliveryTimeout:
		return nil, "webhook did not respond in time"
	case CodeDeliveryUnreachable:
		return nil, "webhook could not be reached"
	case CodeDeliveryUnavailable:
		return nil, "no webhook configured"
	}
	if e.Type == errx.TypeValidation {
		return nil, "webhook URL is not allowed"
	}
	return nil, "delivery failed"
}

// Validate checks structural invariants for the delivery config input.
func (d DeliveryConfigInput) Validate() error {
	if !SecureURL(d.WebhookURL) {
		return errx.Validation("webhook_url must use HTTPS (HTTP allowed only on loopback)")
	}
	if strings.TrimSpace(d.WebhookToken) == "" {
		return errx.Validation("webhook_token is required")
	}
	if d.InvitationURL != "" && !SecureURL(d.InvitationURL) {
		return errx.Validation("invitation_url must use HTTPS (HTTP allowed only on loopback)")
	}
	return nil
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
