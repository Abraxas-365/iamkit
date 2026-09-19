package provisioning

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type CredentialInput struct {
	Name         string  `json:"name"`
	Organization string  `json:"organization_id"`
	Connection   string  `json:"connection_id"`
	ExpiresIn    *string `json:"expires_in,omitempty"`
}

// Validate checks the structural invariants CredentialInput owns. Connection
// may be empty (meaning "create"), so it is validated only when non-empty.
func (c CredentialInput) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("credential name is required")
	}
	if !identity.ValidID(c.Organization) {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if c.Connection != "" && !identity.ValidID(c.Connection) {
		return errx.Validation("connection_id must be a valid UUID")
	}
	return nil
}

type Credential struct {
	ID         string    `json:"id"`
	Secret     string    `json:"secret"`
	Expires    time.Time `json:"expires_at"`
	Connection string    `json:"connection_id"`
}
type Link struct {
	Connection string `json:"connection_id"`
	User       string `json:"user_id"`
	External   string `json:"external_id"`
}

// Validate checks the structural invariants Link owns.
func (l Link) Validate() error {
	if !identity.ValidID(l.Connection) {
		return errx.Validation("connection_id must be a valid UUID")
	}
	if !identity.ValidID(l.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	if l.External == "" {
		return errx.Validation("external_id is required")
	}
	return nil
}

type Mutation struct{ Environment, Actor, Action, Target string }
type CredentialView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Organization string     `json:"organization_id"`
	Connection   string     `json:"connection_id"`
	Expires      time.Time  `json:"expires_at"`
	Revoked      *time.Time `json:"revoked_at"`
}
