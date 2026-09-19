package authentication

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Context struct {
	EnvironmentID  identity.EnvironmentID  `json:"environment_id"`
	OrganizationID identity.OrganizationID `json:"organization_id"`
	ApplicationID  identity.ApplicationID  `json:"application_id"`
	ResourceID     identity.ResourceID     `json:"resource_id"`
}

// Validate reports whether every field of the boundary context is a valid UUID.
func (c Context) Validate() error {
	for _, id := range []interface{ IsZero() bool }{
		c.EnvironmentID, c.OrganizationID, c.ApplicationID, c.ResourceID,
	} {
		if id.IsZero() {
			return errx.Validation("boundary IDs must be valid UUIDs")
		}
	}
	return nil
}

type Access struct {
	Audience    string
	Permissions []string
}
type Session struct {
	ID      identity.SessionID
	User    identity.UserID
	Expires time.Time
	Used    bool
	Revoked bool
}
type Challenge struct {
	User     identity.UserID
	Hash     []byte
	Attempts int
}
type Issued struct {
	Context Context
	User    identity.UserID
	Session identity.SessionID
	Refresh string
	Access  Access
}
