// Package config centralizes security and protocol constants so they are
// defined in exactly one place and easy to audit before going live.
package config

import "time"

// Password constraints (bcrypt imposes the 72-byte ceiling).
const (
	PasswordMinLength = 12
	PasswordMaxLength = 72
)

// BcryptCost is the work-factor passed to bcrypt.GenerateFromPassword.
const BcryptCost = 12

// Token and session lifetimes.
const (
	TokenTTL              = 15 * time.Minute // JWT (self-signed & ID tokens)
	ImpersonationTokenTTL = 15 * time.Minute
	SessionTTL            = 24 * time.Hour   // End-user session / refresh token window
	OperatorSessionTTL    = 1 * time.Hour    // Operator (management) session
	APIKeyTTL             = 24 * time.Hour   // Bootstrap / recovery API key expiry
	SessionCookieMaxAge   = 3600             // seconds — matches OperatorSessionTTL
)

// OAuth 2.0 / OIDC lifespans (fosite).
const (
	OAuthAuthorizeCodeLifespan = 5 * time.Minute
	OAuthAccessTokenLifespan   = 15 * time.Minute
	OAuthRefreshTokenLifespan  = 24 * time.Hour
	OAuthIDTokenLifespan       = 15 * time.Minute
)

// ExternalHTTPTimeout is the timeout for all outbound HTTP calls
// (OIDC discovery, email webhooks, etc.).
const ExternalHTTPTimeout = 10 * time.Second

// CORSMaxAge is the preflight cache duration in seconds.
const CORSMaxAge = 3600
