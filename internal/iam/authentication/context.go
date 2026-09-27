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
	User        identity.UserID
	Environment identity.EnvironmentID
	Email       string
	Hash        []byte
	Attempts    int
}
type Issued struct {
	Context Context
	User    identity.UserID
	Session identity.SessionID
	Refresh string
	Access  Access
}

// Login methods of a verified user.
const (
	MethodPassword = "password"
	MethodCode     = "code"
	MethodSSO      = "sso"
)

// Verified is a user who proved their identity before the organization of
// the session was chosen (hosted login). Email is the address they signed in
// with; Organization is set when the method already fixed it (organization
// SSO).
type Verified struct {
	User         identity.UserID
	Email        string
	Method       string
	Organization identity.OrganizationID
}

// Target is the application and resource a hosted login signs in to; the
// organization is chosen after authentication.
type Target struct {
	Environment identity.EnvironmentID
	Application identity.ApplicationID
	Resource    identity.ResourceID
}

// Boundary completes the target with the chosen organization.
func (t Target) Boundary(organization identity.OrganizationID) Context {
	return Context{EnvironmentID: t.Environment, OrganizationID: organization, ApplicationID: t.Application, ResourceID: t.Resource}
}
