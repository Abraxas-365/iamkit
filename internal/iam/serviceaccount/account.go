package serviceaccount

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Input struct {
	Name        string                 `json:"name"`
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Permissions []string               `json:"permissions"`
	ExpiresIn   *string                `json:"expires_in,omitempty"`
	// ClientAuth is how the account authenticates at /oauth/token
	// (client_credentials); client_secret_basic by default.
	identity.ClientAuth
}

func (i Input) Validate() error {
	if strings.TrimSpace(i.Name) == "" {
		return errx.Validation("service account name is required")
	}
	if i.Application.IsZero() {
		return errx.Validation("application_id must be a valid UUID")
	}
	if i.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if err := identity.ValidatePermissions(i.Permissions, ""); err != nil {
		return err
	}
	return i.ClientAuth.WithDefaults(false).Validate(false)
}

// Mutation is an audited change to a service account.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

type Credential struct {
	ID      identity.AccountID `json:"id"`
	Secret  string             `json:"secret"`
	Expires time.Time          `json:"expires_at"`
}
type Account struct {
	ID              identity.AccountID     `json:"id" db:"id"`
	Name            string                 `json:"name" db:"name"`
	Application     identity.ApplicationID `json:"application_id" db:"application_id"`
	ApplicationName string                 `json:"application_name" db:"application_name"`
	Resource        identity.ResourceID    `json:"resource_id" db:"resource_id"`
	ResourceName    string                 `json:"resource_name" db:"resource_name"`
	Permissions     []string               `json:"permissions" db:"permissions"`
	Expires         time.Time              `json:"expires_at" db:"expires_at"`
	Revoked         *time.Time             `json:"revoked_at" db:"revoked_at"`
	// CanImpersonate lets the account exchange a user id for that user's
	// access token (token exchange); set only by workspace owners.
	CanImpersonate bool `json:"can_impersonate" db:"can_impersonate"`
	identity.ClientAuth
}
