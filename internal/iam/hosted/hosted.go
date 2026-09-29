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
	// Language is the page language: the application's ui_locales, else
	// the environment language; "" leaves it to the browser.
	Language string
}

// Route is where an identified email signs in: single sign-on (the browser
// goes to Redirect, with Binding as the federation cookie), the password of
// the organization's LDAP directory (Method "ldap", Connection set) or
// password, with SSO offered as an alternative when Connection is set.
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
	// SecondFactor asks for a second-factor or recovery code; Factors are
	// the kinds the login accepts (email and sms offer to send a code).
	SecondFactor bool
	Factors      []string
	// Sent says where a code just went.
	Sent *authentication.CodeSent
	// PasswordChange asks for a new password: the current one expired.
	PasswordChange bool
	// Enroll asks the user to add an authenticator the organization
	// requires; EnrollEmail offers the email address instead (Enroll is nil
	// when an authenticator app is not allowed).
	Enroll      *authentication.Enrollment
	EnrollEmail bool
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
	e := errx.Forbidden("your account does not have access to this application")
	e.Code = CodeNoAccess
	return e
}

// CodeNoAccess is the code of ErrNoAccess.
const CodeNoAccess = "NO_ACCESS"

// ErrSignedUpNoAccess is returned when a new account was created but its
// sign-up organization gives it no access to the application yet.
func ErrSignedUpNoAccess() error {
	e := errx.Forbidden("your account was created, but it does not have access to this application yet")
	e.Code = "SIGNED_UP_NO_ACCESS"
	return e
}
