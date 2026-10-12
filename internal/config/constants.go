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

// Organization setup links (WorkOS-style admin portal links): the default
// and bounds of a link's lifetime, and how long the bearer it is exchanged
// for lasts (never beyond the link itself).
const (
	SetupLinkTTL       = 7 * 24 * time.Hour
	SetupLinkMinTTL    = 5 * time.Minute
	SetupLinkMaxTTL    = 30 * 24 * time.Hour
	SetupSessionTTL    = 1 * time.Hour
	SetupLinkMaxPerOrg = 50 // live (unrevoked, unexpired) links per organization
)

// API keys: the policy defaults for environments without an
// api_key_policies row (live keys per user per organization, live
// organization keys per organization); a key's last_used_at is rewritten at
// most every APIKeyUsedInterval. An omitted expires_in never expires
// (identity.NoExpiry), like WorkOS.
const (
	APIKeyMaxPerUserDefault         = 10
	APIKeyMaxPerOrganizationDefault = 50
	APIKeyUsedInterval              = time.Minute
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

// EventRetention is how long the event log keeps events unless
// IAMKIT_EVENT_RETENTION says otherwise.
const EventRetention = 90 * 24 * time.Hour

// App audit logs (auditlog module).
const (
	// AuditLogRetention is how long app audit log events are kept unless
	// IAMKIT_AUDIT_LOG_RETENTION says otherwise.
	AuditLogRetention = 365 * 24 * time.Hour
	// AuditLogMaxBody caps a POST …/audit-logs/events body.
	AuditLogMaxBody = 64 << 10
	// AuditLogFutureSkew is how far in the future occurred_at may be.
	AuditLogFutureSkew = 5 * time.Minute
)

// Log streams (logstream module): batches of events and app audit log
// events delivered to a SIEM or object storage. Retries, backoff and
// disabling reuse the EventWebhook* constants.
const (
	// LogStreamInterval is how often each replica looks for due batches.
	LogStreamInterval = 2 * time.Second
	// LogStreamBatchSize / LogStreamBatchBytes bound one batch.
	LogStreamBatchSize  = 500
	LogStreamBatchBytes = 1 << 20
	// LogStreamTimeout bounds one delivery request (an S3 upload included).
	LogStreamTimeout = 30 * time.Second
	// LogStreamDeliveryRetention keeps finished deliveries visible.
	LogStreamDeliveryRetention = 7 * 24 * time.Hour
)

// LogoutDispatchInterval is how often each replica looks for due
// back-channel logout notifications.
const LogoutDispatchInterval = 5 * time.Second

// Event webhooks (event_subscriptions).
const (
	// EventWebhookInterval is how often each replica looks for due
	// deliveries.
	EventWebhookInterval = 2 * time.Second
	// EventWebhookRetryBase doubles per failed attempt up to
	// EventWebhookRetryMax; a delivery is given up once its next attempt
	// would fall past EventWebhookRetryWindow after it was queued.
	EventWebhookRetryBase   = 15 * time.Second
	EventWebhookRetryMax    = time.Hour
	EventWebhookRetryWindow = 24 * time.Hour
	// EventWebhookDisableAfter of failures without a success disables a
	// subscription.
	EventWebhookDisableAfter = 3 * 24 * time.Hour
	// EventWebhookSecretOverlap is how long a rotated secret keeps signing.
	EventWebhookSecretOverlap = 24 * time.Hour
	// EventWebhookMaxPayload caps a delivery body; larger event data is
	// replaced by {"truncated": true}.
	EventWebhookMaxPayload = 64 << 10
	// ActionTimeout is a target's default timeout (100 ms to
	// ActionMaxTimeout); ActionMaxResponse caps the body read from it and
	// ActionMaxClaims the encoded claims it may add to a token.
	ActionTimeout     = 5 * time.Second
	ActionMaxTimeout  = 10 * time.Second
	ActionMaxResponse = 64 << 10
	ActionMaxClaims   = 4 << 10
	// ActionBreakerFailures consecutive failures of a target open its
	// circuit for ActionBreakerOpen: calls are skipped (and count as
	// failures) until it elapses.
	ActionBreakerFailures = 5
	ActionBreakerOpen     = 30 * time.Second
	// ActionCallRetention keeps the recent-calls log.
	ActionCallRetention = 7 * 24 * time.Hour
	// EventDeliveryRetention keeps finished deliveries visible to operators.
	EventDeliveryRetention = 7 * 24 * time.Hour
)

// Shared cache (REDIS_URL, internal/cache): copies of hot reads, deleted
// by the writer; an entry another write races past lives at most its TTL.
const (
	// CacheTTL bounds feature overrides and action bindings.
	CacheTTL = 30 * time.Second
	// OIDCDiscoveryCacheTTL bounds identity providers' discovery documents.
	OIDCDiscoveryCacheTTL = 15 * time.Minute
)

// Usage and limits (internal/iam/usage).
const (
	// UsageFlushInterval is how often each replica writes the counts it
	// keeps in memory (tokens, emails, SMS, action calls, API requests).
	UsageFlushInterval = 30 * time.Second
	// UsageLimitCacheTTL is how long a replica reuses an environment's
	// limits; another replica's change applies within it.
	UsageLimitCacheTTL = 30 * time.Second
	// UsageRollupSettle leaves events this young to a later round, so
	// transactions still committing lower ids are not skipped.
	UsageRollupSettle = time.Minute
	// UsageRollupBatch is the events read per rollup round.
	UsageRollupBatch = 5000
	// UsageRetention keeps daily usage rows.
	UsageRetention = 400 * 24 * time.Hour
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

// RequestHeaderLimit bounds a request's line plus headers (Fiber's
// ReadBufferSize; past it the answer is 431). Fiber's 4 KiB default is too
// small for browsers that carry an application's own cookies to IAMKit on a
// shared host.
const RequestHeaderLimit = 16 * 1024

// ClientOriginCacheTTL is how long an answer about an OAuth client's
// allowed origin is reused: a removed origin stops working within it.
const ClientOriginCacheTTL = time.Minute

// Bot protection (CAPTCHA) and risk signals.
const (
	// CaptchaTimeout bounds a CAPTCHA provider's siteverify call; a
	// transport error or a slower answer lets the request through
	// (logged, iamkit.captcha.unavailable), an "invalid" answer never does.
	CaptchaTimeout = 5 * time.Second
	// CaptchaPassTTL is how long a CAPTCHA solved on a hosted page covers
	// the next pages of the same authorization.
	CaptchaPassTTL = 10 * time.Minute
	// CaptchaPassUses is how many credential posts (password, code, reset,
	// directory) one solved hosted CAPTCHA covers; then the widget is shown
	// again, so one pass never covers an unbounded guessing run.
	CaptchaPassUses = 5
	// SignInAttemptRetention is how long sign-in attempts are kept unless
	// IAMKIT_SIGN_IN_ATTEMPT_RETENTION says otherwise.
	SignInAttemptRetention = 30 * 24 * time.Hour
	// MaxUserDevices caps the known devices of one user; the least
	// recently seen is forgotten first.
	MaxUserDevices = 50
	// UserDeviceRetention forgets a known device (its last IP, country and
	// User-Agent) not seen for this long; it is then new again.
	UserDeviceRetention = 180 * 24 * time.Hour
	// SignInBlockedEventInterval: at most one sign_in.blocked event per
	// client address and reason within it (every attempt is still kept).
	SignInBlockedEventInterval = time.Minute
	// DeviceCookieMaxAge is the lifetime of the hosted device cookie
	// (__Host-iamkit-device, 400 days: the browser maximum).
	DeviceCookieMaxAge = 400 * 24 * time.Hour
	// SecurityAlertInterval: at most one security_alert email per user per
	// detection within it.
	SecurityAlertInterval = time.Hour
	// GeoIPReloadInterval: how often the GeoIP database file is checked
	// for a newer version (mtime).
	GeoIPReloadInterval = time.Minute
	// ImpossibleTravelMinKm: closer sign-ins are never impossible travel
	// (GeoIP city precision).
	ImpossibleTravelMinKm = 500
)
