package authentication

import (
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// DeliveryConfig is a per-environment webhook configuration for challenge
// code delivery (OTP, password reset, email verification). When set, it
// overrides the global EMAIL_WEBHOOK_URL for that environment.
type DeliveryConfig struct {
	EnvironmentID identity.EnvironmentID `json:"environment_id"`
	WebhookURL    string                 `json:"webhook_url"`
	HasToken      bool                   `json:"has_token"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// DeliveryConfigInput is the write payload for creating or updating a
// per-environment delivery configuration.
type DeliveryConfigInput struct {
	WebhookURL   string `json:"webhook_url"`
	WebhookToken string `json:"webhook_token"`
}

// Validate checks structural invariants for the delivery config input.
func (d DeliveryConfigInput) Validate() error {
	u, err := url.Parse(d.WebhookURL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errx.Validation("webhook_url must be a valid HTTPS URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return errx.Validation("webhook_url must use HTTPS (HTTP allowed only on loopback)")
	}
	if strings.TrimSpace(d.WebhookToken) == "" {
		return errx.Validation("webhook_token is required")
	}
	return nil
}
