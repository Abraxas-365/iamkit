// Package hosted serves IAMKit's own sign-in pages for OAuth clients that
// opt in (hosted_login). The pages authenticate the user first (password,
// email code or single sign-on), then choose the organization, then issue
// the session and finish the pending OAuth authorization.
package hosted

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Request identifies the pending authorization a hosted page acts on: the
// authorization ticket and the browser binding cookie issued with it.
type Request struct {
	Ticket  string
	Binding string
}

// Page is what the first sign-in page shows: the branding, the methods
// the client offers, and its environment connections.
type Page struct {
	Settings    Settings
	SignIn      SignIn
	Connections []federation.ConnectionSummary
}

// Route is where an identified email signs in: single sign-on (the browser
// goes to Redirect, with Binding as the federation cookie) or password,
// with SSO offered as an alternative when Connection is set.
type Route struct {
	Method     string
	Redirect   string
	Binding    string
	Connection *identity.ConnectionID
}

// Result of a verification step: the organizations to choose from, a
// second-factor step, or the login that finishes the authorization.
type Result struct {
	Organizations []authentication.Organization
	Login         *oauth.Login
	// SecondFactor asks for an authenticator or recovery code.
	SecondFactor bool
	// Enroll asks the user to add an authenticator the organization requires.
	Enroll *authentication.Enrollment
	// RecoveryCodes are shown once after enrolling; the user then continues.
	RecoveryCodes []string
}

// Login is a verified user parked between hosted steps.
type Login struct {
	Verified authentication.Verified
	Chosen   identity.OrganizationID
	Attempts int
}

// ErrLoginExpired is returned when the parked login is gone (expired, or
// out of second-factor attempts): the user signs in again.
func ErrLoginExpired() error {
	e := errx.Unauthorized("sign in again")
	e.Code = "LOGIN_EXPIRED"
	return e
}

// ErrNoAccess is returned when the verified user may not use the client's
// application in any organization.
func ErrNoAccess() error {
	return errx.Forbidden("your account does not have access to this application")
}
