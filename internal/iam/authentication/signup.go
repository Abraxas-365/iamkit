package authentication

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// MaxSignupName bounds the name a person gives when signing up.
const MaxSignupName = 200

// Signup is a person asking for their own account. The account exists only
// once they entered the code emailed to them (CompleteSignup). Password is
// optional: without it the account signs in with email codes.
type Signup struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	Email       string                 `json:"email"`
	Name        string                 `json:"name"`
	Password    string                 `json:"password"`
	// Locale is the email language (a tag or list); optional.
	Locale string `json:"locale"`
	// AcceptTerms records that the person accepted the terms; required
	// when the sign-in policy's require_terms is set.
	AcceptTerms bool `json:"accept_terms"`
}

func (s Signup) Validate() error {
	if s.Environment.IsZero() {
		return errx.Validation("environment_id is required")
	}
	if _, err := identity.Email(s.Email); err != nil {
		return errx.Validation("email must be a valid address")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errx.Validation("name is required")
	}
	if utf8.RuneCountInString(s.Name) > MaxSignupName {
		return errx.Validation("name must be at most 200 characters long")
	}
	if len(s.Password) > config.PasswordMaxLength {
		return errx.Validation("password must be at most 72 characters long")
	}
	return nil
}

// PendingSignup is a sign-up waiting for its email code. PasswordHash is
// "" for an account that signs in with email codes.
type PendingSignup struct {
	ID           identity.ChallengeID
	Environment  identity.EnvironmentID
	Email        string
	Name         string
	PasswordHash string
	Hash         []byte
	Attempts     int
	Expires      time.Time
	// TermsAccepted is when the person accepted the terms (nil: not asked).
	TermsAccepted *time.Time
}

// Joining creates the account of a verified sign-up in the environment's
// sign-up organization (and group, when set).
type Joining struct {
	Signup        identity.ChallengeID
	User          identity.UserID
	Environment   identity.EnvironmentID
	Organization  identity.OrganizationID
	Group         identity.GroupID
	Email         string
	Name          string
	PasswordHash  string
	TermsAccepted *time.Time
}

// SignedUp is the account a completed sign-up created.
type SignedUp struct {
	User         identity.UserID         `json:"user_id"`
	Organization identity.OrganizationID `json:"organization_id"`
	Email        string                  `json:"email"`
	// Method is the first factor the account signs in with: password, or
	// email code for a passwordless account.
	Method string `json:"-"`
}

// Verified is the sign-in the sign-up proved: the email (by its code) and
// the password when one was chosen.
func (s SignedUp) Verified() Verified {
	return Verified{User: s.User, Email: s.Email, Method: s.Method}
}

// ActionSignup audits an account created by self-registration; the actor is
// the new user.
const ActionSignup = "user.signup"

// Error codes of self-registration.
const (
	CodeSignupDisabled = "SIGNUP_DISABLED"
	CodeAccountExists  = "ACCOUNT_EXISTS"
	CodeTermsRequired  = "TERMS_REQUIRED"
)

// ErrTermsRequired refuses a sign-up that did not accept the terms the
// sign-in policy requires.
func ErrTermsRequired() error {
	e := errx.Validation("accept_terms is required: accept the terms to sign up")
	e.Code = CodeTermsRequired
	return e
}

// ErrSignupDisabled refuses a sign-up the environment does not offer.
func ErrSignupDisabled() error {
	e := errx.Forbidden("sign-up is not available; ask an administrator for an invitation")
	e.Code = CodeSignupDisabled
	return e
}

// ErrAccountExists answers a verified sign-up whose email got an account in
// the meantime.
func ErrAccountExists() error {
	e := errx.Conflict("an account with this email already exists; sign in with it")
	e.Code = CodeAccountExists
	return e
}
