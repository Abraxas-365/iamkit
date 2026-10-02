package user

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Kind tells people from machines. A machine user has no email, username,
// password, phone or second factor: no sign-in path can match it, and it
// authenticates only with personal access tokens.
type Kind string

const (
	KindHuman   Kind = "human"
	KindMachine Kind = "machine"
)

// Valid reports a known kind ("" is human).
func (k Kind) Valid() bool { return k == "" || k == KindHuman || k == KindMachine }

// AccessTokenPrefix starts every personal access token.
const AccessTokenPrefix = "ik_pat_"

// Audit actions of personal access tokens.
const (
	ActionAccessTokenCreated = "user.access_token_created"
	ActionAccessTokenRevoked = "user.access_token_revoked"
)

// AccessToken is a machine user's personal access token: it acts as the
// user in one organization for one application resource, with the
// permissions the user holds there when it is used. The secret is shown
// only once (IssuedAccessToken).
type AccessToken struct {
	ID           identity.AccessTokenID  `json:"id" db:"id"`
	User         identity.UserID         `json:"user_id" db:"user_id"`
	Organization identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Application  identity.ApplicationID  `json:"application_id" db:"application_id"`
	Resource     identity.ResourceID     `json:"resource_id" db:"resource_id"`
	Name         string                  `json:"name" db:"name"`
	ExpiresAt    time.Time               `json:"expires_at" db:"expires_at"`
	LastUsedAt   *time.Time              `json:"last_used_at" db:"last_used_at"`
	RevokedAt    *time.Time              `json:"revoked_at" db:"revoked_at"`
	CreatedAt    time.Time               `json:"created_at" db:"created_at"`
	// Names are filled when tokens are listed.
	OrganizationName string `json:"organization_name,omitempty" db:"organization_name"`
	ApplicationName  string `json:"application_name,omitempty" db:"application_name"`
	ResourceName     string `json:"resource_name,omitempty" db:"resource_name"`
}

// IssuedAccessToken is a new token with its secret, returned once.
type IssuedAccessToken struct {
	AccessToken
	Token string `json:"token"`
}

// NewAccessToken creates a personal access token. ExpiresIn is a Go
// duration from 1h to 8760h or "never" (default 24h, identity.ParseTTL).
type NewAccessToken struct {
	Name         string                  `json:"name"`
	Organization identity.OrganizationID `json:"organization_id"`
	Application  identity.ApplicationID  `json:"application_id"`
	Resource     identity.ResourceID     `json:"resource_id"`
	ExpiresIn    *string                 `json:"expires_in"`
}

func (n NewAccessToken) Validate() error {
	if strings.TrimSpace(n.Name) == "" {
		return errx.Validation("token name is required")
	}
	if len(n.Name) > 200 {
		return errx.Validation("token name must be at most 200 characters")
	}
	if n.Organization.IsZero() {
		return errx.Validation("organization_id is required")
	}
	if n.Application.IsZero() {
		return errx.Validation("application_id is required")
	}
	if n.Resource.IsZero() {
		return errx.Validation("resource_id is required")
	}
	_, err := identity.ParseTTL(n.ExpiresIn)
	return err
}
