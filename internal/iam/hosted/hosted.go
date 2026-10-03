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
	// the organization's, client's or environment language, each within
	// Settings.Languages; "" leaves it to the browser (Settings.Negotiate).
	Language string
	// Texts is who the page's custom texts come from: its client and the
	// organization it brands for.
	Texts TextScope
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
	// Account is who is choosing an organization (shown on the chooser;
	// zero when it could not be read).
	Account authentication.Profile
	Login   *oauth.Login
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

// Codes of the hosted journey's errors people can act on; the hosted pages
// show each in the page language (hostedhttp).
const (
	CodeLoginInvalid       = "LOGIN_INVALID"       // neither an email nor a username
	CodeSSOOnly            = "SSO_ONLY"            // a username where only SSO is offered
	CodeSSONotOffered      = "SSO_NOT_OFFERED"     // the organization's SSO is not offered here
	CodeSSOEmail           = "SSO_EMAIL"           // the email has no SSO and nothing else is offered
	CodePasswordRequired   = "PASSWORD_REQUIRED"   // empty password
	CodeChooseOrganization = "CHOOSE_ORGANIZATION" // no organization picked
	CodeOrganizationChosen = "ORGANIZATION_CHOSEN" // another organization was already picked
	CodeFactorRequired     = "FACTOR_REQUIRED"     // the second factor comes first
)

// Problem is an error with one of the codes above.
func Problem(status func(string) *errx.Error, code, message string) error {
	e := status(message)
	e.Code = code
	return e
}

// CodeWrongCode is the code of ErrWrongCode.
const CodeWrongCode = "WRONG_CODE"

// ErrWrongCode refuses a wrong second-factor code on the hosted pages,
// saying how many tries the login has left (details.remaining).
func ErrWrongCode(remaining int) error {
	e := errx.Unauthorized("invalid verification code").WithDetail("remaining", max(remaining, 0))
	e.Code, e.Public = CodeWrongCode, true
	return e
}

// CodeAttemptsUsed is the code of ErrAttemptsUsed.
const CodeAttemptsUsed = "MFA_ATTEMPTS_USED"

// ErrAttemptsUsed is returned for the wrong code that spends the parked
// login's last second-factor attempt: the login is gone, the user signs in
// again.
func ErrAttemptsUsed() error {
	e := errx.Unauthorized("too many wrong codes; sign in again")
	e.Code = CodeAttemptsUsed
	return e
}

// Restart reports whether err ends the parked login, so the hosted pages
// go back to the first step.
func Restart(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && (e.Code == "LOGIN_EXPIRED" || e.Code == CodeAttemptsUsed)
}

// ErrSignedUpNoAccess is returned when a new account was created but its
// sign-up organization gives it no access to the application yet.
func ErrSignedUpNoAccess() error {
	e := errx.Forbidden("your account was created, but it does not have access to this application yet")
	e.Code = "SIGNED_UP_NO_ACCESS"
	return e
}
