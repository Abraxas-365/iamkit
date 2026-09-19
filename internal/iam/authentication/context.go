package authentication

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Context struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
}

// Validate reports whether every field of the boundary context is a valid UUID.
func (c Context) Validate() error {
	for _, pair := range []struct{ name, value string }{
		{"environment_id", c.EnvironmentID},
		{"organization_id", c.OrganizationID},
		{"application_id", c.ApplicationID},
		{"resource_id", c.ResourceID},
	} {
		if !identity.ValidID(pair.value) {
			return errx.Validation(pair.name + " must be a valid UUID")
		}
	}
	return nil
}

type Access struct {
	Audience    string
	Permissions []string
}
type Session struct {
	ID, User      string
	Expires       time.Time
	Used, Revoked bool
}
type Challenge struct {
	User     string
	Hash     []byte
	Attempts int
}
type Issued struct {
	Context                Context
	User, Session, Refresh string
	Access                 Access
}
