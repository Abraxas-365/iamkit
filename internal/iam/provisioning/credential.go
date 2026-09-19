package provisioning

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type CredentialInput struct {
	Name         string                  `json:"name"`
	Organization identity.OrganizationID `json:"organization_id"`
	Connection   identity.ConnectionID   `json:"connection_id"`
	ExpiresIn    *string                 `json:"expires_in,omitempty"`
}

func (c CredentialInput) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("credential name is required")
	}
	if c.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if !c.Connection.IsZero() {
		// connection is optional; only validate format if provided
	}
	return nil
}

type Credential struct {
	ID         identity.CredentialID `json:"id"`
	Secret     string                `json:"secret"`
	Expires    time.Time             `json:"expires_at"`
	Connection identity.ConnectionID `json:"connection_id"`
}
type Link struct {
	Connection identity.ConnectionID `json:"connection_id"`
	User       identity.UserID       `json:"user_id"`
	External   string                `json:"external_id"`
}

func (l Link) Validate() error {
	if l.Connection.IsZero() {
		return errx.Validation("connection_id must be a valid UUID")
	}
	if l.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	if l.External == "" {
		return errx.Validation("external_id is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
type CredentialView struct {
	ID           identity.CredentialID   `json:"id"`
	Name         string                  `json:"name"`
	Organization identity.OrganizationID `json:"organization_id"`
	Connection   identity.ConnectionID   `json:"connection_id"`
	Expires      time.Time               `json:"expires_at"`
	Revoked      *time.Time              `json:"revoked_at"`
}
