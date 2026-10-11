package risk

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// CaptchaCommands change an environment's CAPTCHA (audited captcha.update /
// captcha.delete) and record hosted passes.
type CaptchaCommands interface {
	// SaveCaptcha stores the configuration; the secret is sealed (no
	// Cipher → 422 ENCRYPTION_KEY_REQUIRED) and required when none is
	// stored.
	SaveCaptcha(ctx context.Context, m Mutation, input CaptchaInput) (CaptchaConfig, error)
	DeleteCaptcha(ctx context.Context, m Mutation) error
	// TestCaptcha calls siteverify with a dummy answer: a rejected answer
	// proves the secret (nil), a rejected secret is 422
	// CAPTCHA_SECRET_INVALID, no answer 502.
	TestCaptcha(ctx context.Context, environment identity.EnvironmentID) error
	// GrantPass records that the hosted journey of ticket (its hash)
	// solved the CAPTCHA, for config.CaptchaPassTTL and
	// config.CaptchaPassUses credential posts.
	GrantPass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) error
	// UsePass spends one use of ticket's pass for a credential post
	// (false: none left, the widget must be solved again).
	UsePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) (bool, error)
}

// CaptchaQueries read the configuration and verify answers.
type CaptchaQueries interface {
	// Captcha is the configuration (NotFound without one).
	Captcha(ctx context.Context, environment identity.EnvironmentID) (CaptchaConfig, error)
	// PublicCaptcha is what a surface's UI renders (Enabled false when no
	// CAPTCHA applies there or the captcha feature is off).
	PublicCaptcha(ctx context.Context, environment identity.EnvironmentID, surface string) (PublicCaptcha, error)
	// CheckCaptcha verifies an answer: "" when no CAPTCHA applies,
	// CaptchaPassed, or CaptchaUnavailable (the provider did not answer:
	// fail open); a missing or rejected answer is ErrCaptchaRequired.
	CheckCaptcha(ctx context.Context, check CaptchaCheck) (string, error)
	// Passed reports whether ticket holds a live hosted pass.
	Passed(ctx context.Context, environment identity.EnvironmentID, ticket []byte) (bool, error)
}

// CaptchaRepository persists CAPTCHA configurations and hosted passes.
type CaptchaRepository interface {
	// Captcha returns the configuration and its sealed secret (NotFound
	// without one).
	Captcha(ctx context.Context, environment identity.EnvironmentID) (CaptchaConfig, string, error)
	SaveCaptcha(ctx context.Context, m Mutation, config CaptchaConfig, sealed string) error
	DeleteCaptcha(ctx context.Context, m Mutation) error
	SavePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, expires time.Time, uses int) error
	Pass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, now time.Time) (bool, error)
	// UsePass spends one use of a live pass atomically (false when none
	// is left).
	UsePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, now time.Time) (bool, error)
}

// PolicyCommands change the risk policy and restrictions (audited
// risk_policy.* / risk_restriction.*).
type PolicyCommands interface {
	SavePolicy(ctx context.Context, m Mutation, input PolicyInput) (Policy, error)
	// DeletePolicy returns to the default policy (every detection off).
	DeletePolicy(ctx context.Context, m Mutation) error
	CreateRestriction(ctx context.Context, m Mutation, input NewRestriction) (Restriction, error)
	DeleteRestriction(ctx context.Context, m Mutation, restriction identity.RestrictionID) error
}

// PolicyQueries read the policy, the restrictions and the deployment's
// risk capabilities.
type PolicyQueries interface {
	// Policy is the saved policy or DefaultPolicy.
	Policy(ctx context.Context, environment identity.EnvironmentID) (Policy, error)
	Restrictions(ctx context.Context, environment identity.EnvironmentID, filter RestrictionFilter) ([]Restriction, error)
	Status(ctx context.Context, environment identity.EnvironmentID) (Status, error)
}

// PolicyRepository persists policies and restrictions.
type PolicyRepository interface {
	// Policy returns the saved policy (NotFound without one).
	Policy(ctx context.Context, environment identity.EnvironmentID) (Policy, error)
	SavePolicy(ctx context.Context, m Mutation, policy Policy) error
	DeletePolicy(ctx context.Context, m Mutation) error
	Restrictions(ctx context.Context, environment identity.EnvironmentID, filter RestrictionFilter) ([]Restriction, error)
	// CreateRestriction refuses past MaxRestrictions
	// (ErrTooManyRestrictions) and a duplicate kind/value (409).
	CreateRestriction(ctx context.Context, m Mutation, restriction Restriction) error
	DeleteRestriction(ctx context.Context, m Mutation, restriction identity.RestrictionID) error
}

// AttemptCommands maintain the attempt log.
type AttemptCommands interface {
	// Prune deletes attempts older than the retention (the
	// sign_in_attempt_prune job).
	Prune(ctx context.Context) (int, error)
}

// AttemptQueries read the attempt log and users' known devices.
type AttemptQueries interface {
	Attempts(ctx context.Context, environment identity.EnvironmentID, filter AttemptFilter) (AttemptPage, error)
	Attempt(ctx context.Context, environment identity.EnvironmentID, attempt identity.SignInAttemptID) (Attempt, error)
	Devices(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]Device, error)
}

// AttemptRepository persists attempts and devices and answers the
// detections' counting queries (indexed, no locks).
type AttemptRepository interface {
	// Record writes an attempt; a successful one with a device also
	// upserts the user's device (evicting past config.MaxUserDevices), and
	// detections with action log or stronger emit risk.detected, a block
	// sign_in.blocked — in one transaction through eventpg.
	Record(ctx context.Context, attempt Attempt, loginHash, deviceHash []byte) error
	Attempts(ctx context.Context, environment identity.EnvironmentID, filter AttemptFilter) ([]Attempt, error)
	Attempt(ctx context.Context, environment identity.EnvironmentID, attempt identity.SignInAttemptID) (Attempt, error)
	Devices(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]Device, error)
	// Counts are the failures of the last hour for the login (hash) and
	// the address.
	Counts(ctx context.Context, environment identity.EnvironmentID, loginHash []byte, ip string, since time.Time) (Counts, error)
	// KnownDevice reports whether the user signed in from the device.
	KnownDevice(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, deviceHash []byte) (bool, error)
	// LastLocated is the user's latest successful attempt with
	// coordinates (found false without one).
	LastLocated(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Last, bool, error)
	// LastSignedIn is users.last_signed_in_at (nil = never).
	LastSignedIn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (*time.Time, error)
	Prune(ctx context.Context, before time.Time) (int, error)
}

// Evaluator is risk evaluation of sign-ins: what authentication and the
// hosted journey consume (through their own one-purpose ports).
type Evaluator interface {
	// Screen applies the restrictions before any credential is checked:
	// a deny is ErrSignInBlocked (recorded). Infrastructure errors pass.
	Screen(ctx context.Context, signal Signal) error
	// Assess runs the detections for an identified user after the first
	// factor. Errors are logged and assess as nothing detected.
	Assess(ctx context.Context, signal Signal) Decision
	// Record writes the attempt after the outcome is known (never fails
	// the sign-in) and sends notify alerts.
	Record(ctx context.Context, signal Signal, outcome string, decision Decision)
}

// Verifier calls a CAPTCHA provider's siteverify. An error means the
// provider did not answer (transport, timeout, 5xx): the caller fails
// open.
type Verifier interface {
	Verify(ctx context.Context, provider, secret string, check CaptchaCheck) (Answer, error)
}

// Geo locates client addresses (deployment-wide GeoIP).
type Geo interface {
	// Locate returns where ip is; the country of a trusted proxy header
	// (identity.ClientInfo.Country) is passed as fallback.
	Locate(ip, headerCountry string) (Location, bool)
	Status() GeoStatus
}

// Notifier emails a user a security alert.
type Notifier interface {
	Alert(ctx context.Context, alert Alert) error
}

// Cipher seals and opens stored secrets.
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// Features reads IAMKit's feature flags (captcha, risk_signals).
type Features interface {
	Enabled(ctx context.Context, environment identity.EnvironmentID, name string) (bool, error)
}

// Keys derives the per-environment HMAC keys of login and device hashes.
type Keys interface {
	Hash(environment identity.EnvironmentID, purpose, value string) []byte
}
