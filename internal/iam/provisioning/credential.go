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
	// AdoptExistingMembers lets SCIM create link an existing member of the
	// organization with the same email instead of failing with 409. Applies
	// to the connection; nil keeps the current setting (default false).
	AdoptExistingMembers *bool `json:"adopt_existing_members,omitempty"`
	// AdoptScope restricts adoption: AdoptAny (default) or AdoptVerifiedDomains,
	// which only adopts members whose email is on one of the organization's
	// verified domains. nil keeps the current setting.
	AdoptScope *string `json:"adopt_scope,omitempty"`
}

// Adoption scopes for AdoptExistingMembers.
const (
	AdoptAny             = "any"
	AdoptVerifiedDomains = "verified_domains"
)

func (c CredentialInput) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("credential name is required")
	}
	if c.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if c.AdoptScope != nil && *c.AdoptScope != AdoptAny && *c.AdoptScope != AdoptVerifiedDomains {
		return errx.Validation("adopt_scope must be \"any\" or \"verified_domains\"")
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
	Adopt        bool                    `json:"adopt_existing_members"`
	AdoptScope   string                  `json:"adopt_scope"`
}
