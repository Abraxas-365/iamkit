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

// Signing keys. A key an environment stops signing with keeps verifying
// for SigningKeyRetireDelay: the longest token lifetime plus clock skew.
// Instances reread published keys every SigningKeyCacheTTL (and on an
// unknown kid, at most once per SigningKeyMissInterval).
const (
	SigningKeyRetireDelay  = 20 * time.Minute
	SigningKeyCacheTTL     = 30 * time.Second
	SigningKeyMissInterval = time.Second
)

// Client keys for private_key_jwt. A jwks_uri is read at most once per
// ClientJWKSRefreshInterval (an unknown kid triggers a refetch), reused for
// ClientJWKSCacheTTL, and must fit ClientJWKSMaxBytes. Assertions live at
// most ClientAssertionMaxAge (their exp minus iat or now).
const (
	ClientJWKSCacheTTL        = time.Hour
	ClientJWKSRefreshInterval = time.Minute
	ClientJWKSMaxBytes        = 64 * 1024
	ClientJWKSCacheEntries    = 1000
	ClientAssertionMaxAge     = time.Hour
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

// SAMLResponseMax bounds a SAML response posted to the assertion consumer
// service (base64, before decoding).
const SAMLResponseMax = 64 << 10

// LogoutDispatchInterval is how often each replica looks for due
// back-channel logout notifications.
const LogoutDispatchInterval = 5 * time.Second

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
	// FactorCodeTTL is how long an emailed or texted second-factor (or
	// phone verification) code stays valid.
	FactorCodeTTL = 5 * time.Minute
	// FactorCodeCooldown is the wait before another code is sent for the
	// same factor; FactorCodesPerHour caps the codes one factor receives.
	FactorCodeCooldown = 30 * time.Second
	FactorCodesPerHour = 10
	// WebAuthnCeremonyTTL is how long a security key or passkey prompt
	// (registration or sign-in) may take.
	WebAuthnCeremonyTTL = 5 * time.Minute
	// WebAuthnKeys caps the security keys and passkeys of one user.
	WebAuthnKeys = 20
	// FactorNameMaxLength bounds the name users give a key.
	FactorNameMaxLength = 64
)

// ExternalHTTPTimeout is the timeout for all outbound HTTP calls
// (OIDC discovery, email webhooks, etc.).
const ExternalHTTPTimeout = 10 * time.Second

// CORSMaxAge is the preflight cache duration in seconds.
const CORSMaxAge = 3600
