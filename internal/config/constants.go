// Package config centralizes security and protocol constants so they are
// defined in exactly one place and easy to audit before going live.
package config

import "time"

// Password constraints (bcrypt imposes the 72-byte ceiling).
const (
	PasswordMinLength = 12
	PasswordMaxLength = 72
)

// Password lockout (per environment password policy): the default first
// lock when an environment turns lockout on, and the longest one.
const (
	PasswordLockout    = 15 * time.Minute
	PasswordLockoutMax = 24 * time.Hour
)

// BreachCheckTimeout bounds a breached-password lookup; a slower answer
// lets the password through.
const BreachCheckTimeout = 3 * time.Second

// BcryptCost is the work-factor passed to bcrypt.GenerateFromPassword.
const BcryptCost = 12

// Token and session lifetimes.
const (
	TokenTTL              = 15 * time.Minute // JWT (self-signed & ID tokens)
	ImpersonationTokenTTL = 15 * time.Minute
	SessionTTL            = 24 * time.Hour // End-user session / refresh token window
	OperatorSessionTTL    = 1 * time.Hour  // Operator (management) session
	APIKeyTTL             = 24 * time.Hour // Bootstrap / recovery API key expiry
	SessionCookieMaxAge   = 3600           // seconds — matches OperatorSessionTTL
	InvitationTTL         = 7 * 24 * time.Hour
	// ChallengeTTL is how long an emailed one-time code (sign-in, password
	// reset, email verification) stays valid; emails state it.
	ChallengeTTL = 5 * time.Minute
)

// OAuth 2.0 / OIDC lifespans (fosite).
const (
	OAuthAuthorizeCodeLifespan = 5 * time.Minute
	OAuthAccessTokenLifespan   = 15 * time.Minute
	OAuthRefreshTokenLifespan  = 24 * time.Hour
	OAuthIDTokenLifespan       = 15 * time.Minute
	// OAuthAuthorizationTicketTTL bounds the interaction between
	// /oauth/authorize and completion; the hosted login pages (identify,
	// verify, choose organization) run inside this window.
	OAuthAuthorizationTicketTTL = 10 * time.Minute
	// FederationStateTTL bounds a round trip to an external identity
	// provider (state row and browser binding cookie).
	FederationStateTTL = 5 * time.Minute
)

// Multi-factor authentication.
const (
	// MFALoginTTL bounds the wait for the second factor of a headless login.
	MFALoginTTL = 5 * time.Minute
	// MFAAttempts is the number of wrong codes one pending login allows.
	MFAAttempts = 5
	// MFAFailures wrong codes in a row (any login, pending token or
	// self-service call) lock the user's factor for MFALockout, doubling
	// with every further MFAFailures up to MFALockoutMax.
	MFAFailures   = 10
	MFALockout    = 15 * time.Minute
	MFALockoutMax = 24 * time.Hour
	// MFAFreshAuth is how recently a session must have signed in to add,
	// remove or regenerate second factors.
	MFAFreshAuth = 10 * time.Minute
	// OperatorFreshAuth is how recently a console session must have signed
	// in to set a password without typing the current one (none is set).
	OperatorFreshAuth = 5 * time.Minute
	// MFAEnrollTTL is how long an unconfirmed authenticator is shown again
	// before a login enrollment starts a new one.
	MFAEnrollTTL = 15 * time.Minute
	// RecoveryCodes is how many recovery codes a user holds.
	RecoveryCodes = 10
	// TOTP parameters (RFC 6238 defaults understood by every authenticator app).
	TOTPPeriod = 30 // seconds
	TOTPDigits = 6
	TOTPSkew   = 1 // steps accepted either side of now
)

// ExternalHTTPTimeout is the timeout for all outbound HTTP calls
// (OIDC discovery, email webhooks, etc.).
const ExternalHTTPTimeout = 10 * time.Second

// CORSMaxAge is the preflight cache duration in seconds.
const CORSMaxAge = 3600
