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
	AMR     []string
	// Authenticated is when the session signed in.
	Authenticated time.Time
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
	// AMR lists how the session was authenticated (pwd, email, fed, otp, mfa).
	AMR []string
	// Authenticated is when the session signed in (kept across refreshes).
	Authenticated time.Time
	// RecoveryCodes are shown once when this login enrolled the user's
	// first second factor.
	RecoveryCodes []string
}

// Result of a login step: a session, or — when a second factor applies —
// the token to complete the login with (MFA).
type Result struct {
	Issued Issued
	MFA    *MFA
}

// MFA is the answer of a login that needs a second factor. The login
// continues at /identity/v1/mfa/verify (and /mfa/enroll when the
// organization requires a factor the user does not have yet).
type MFA struct {
	Token              string   `json:"mfa_token"`
	Factors            []string `json:"factors"`
	EnrollmentRequired bool     `json:"enrollment_required"`
}

// Requirement says whether a login needs a second factor and whether the
// user must enroll one first.
type Requirement struct {
	Needed  bool
	Enroll  bool
	Factors []string
}

// Completed is a login whose second factor was verified.
type Completed struct {
	Boundary      Context
	User          identity.UserID
	AMR           []string
	RecoveryCodes []string
	// PasswordHash replaces the user's expired password now that the
	// second factor passed; "" keeps it.
	PasswordHash string
}

// Enrollment is a TOTP authenticator to add during a login.
type Enrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

// MethodAMR is the authentication method reference of a first factor.
func MethodAMR(method string) string {
	switch method {
	case MethodPassword:
		return "pwd"
	case MethodCode:
		return "email"
	case MethodSSO:
		return "fed"
	}
	return method
}

// HasMFA reports whether the method references include a second factor.
func HasMFA(amr []string) bool {
	for _, m := range amr {
		if m == "mfa" {
			return true
		}
	}
	return false
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
	// AMR holds the second-factor references proven so far (otp, mfa).
	AMR []string
	// PasswordExpired holds the session back until the user chose a new
	// password (Authenticator.ChangePassword).
	PasswordExpired bool
}

// Federated reports whether the user signed in with an organization's own
// single sign-on, whose identity provider organizations may trust for the
// second factor. Environment (social) connections do not count.
func (v Verified) Federated() bool { return v.Method == MethodSSO && !v.Organization.IsZero() }

// FederatedFor reports whether the login is the organization's own single
// sign-on: only then may its identity provider stand in for its second
// factor.
func (v Verified) FederatedFor(organization identity.OrganizationID) bool {
	return v.Federated() && v.Organization == organization
}

// Methods returns the session's method references: the first factor, then
// any second factor.
func (v Verified) Methods() []string {
	return append([]string{MethodAMR(v.Method)}, v.AMR...)
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
