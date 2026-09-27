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
