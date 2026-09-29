package mfa

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Logins are the second-factor steps of a login. They implement
// authentication.SecondFactor (headless API) and back the hosted pages.
type Logins interface {
	// Requirement decides whether a login of the user into the boundary
	// needs a second factor.
	Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool) (authentication.Requirement, error)
	// Begin parks a headless login until its second factor and returns the
	// ik_mfa_ token; passwordHash replaces an expired password once it passes.
	Begin(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, enroll bool, passwordHash string) (string, error)
	// Complete verifies a code (TOTP or recovery) for a pending login and
	// consumes it. The first TOTP code of an enrolling login confirms the
	// factor and returns recovery codes. issue (the session) runs before the
	// commit, so a failed session keeps the pending login and the factor
	// unconfirmed.
	Complete(ctx context.Context, token, code string, issue func(done authentication.Completed) error) (authentication.Completed, error)
	// Enroll starts the TOTP factor of a pending login that must enroll.
	Enroll(ctx context.Context, token string) (authentication.Enrollment, error)
	// Verify checks a code for the user outside a headless login (hosted
	// pages). With enroll, an unconfirmed factor is confirmed by its first
	// code and the first recovery codes are returned.
	Verify(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, code string, enroll bool) (Verification, error)
	// Enrolling returns the unconfirmed TOTP factor to show again, starting
	// one when there is none.
	Enrolling(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Enrollment, error)
}

// Commands are the self-service and operator factor use cases.
type Commands interface {
	// Start creates an unconfirmed TOTP factor, replacing an earlier
	// unconfirmed one; a user with an active factor must remove it first.
	Start(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Enrollment, error)
	// Confirm activates the unconfirmed factor with its first code and
	// returns the recovery codes. A wrong code fails with 422, not 401: the
	// caller's access token is fine.
	Confirm(ctx context.Context, m Mutation, user identity.UserID, code string) ([]string, error)
	// Remove deletes the user's factor and recovery codes; code proves
	// possession (TOTP or recovery code).
	Remove(ctx context.Context, m Mutation, user identity.UserID, code string) error
	// Regenerate replaces the recovery codes; code proves possession.
	Regenerate(ctx context.Context, m Mutation, user identity.UserID, code string) ([]string, error)
	// Reset deletes every factor and recovery code of a user (operator).
	Reset(ctx context.Context, m Mutation, user identity.UserID) error
}

type Queries interface {
	Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Summary, error)
}

type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
	Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Summary, error)
	// Policy is what the login requirement depends on.
	Policy(ctx context.Context, boundary authentication.Context, user identity.UserID) (Policy, error)
	Account(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Account, error)
	// SaveUnconfirmed stores a new unconfirmed TOTP factor in place of an
	// earlier unconfirmed one; it fails with a conflict when the user has an
	// active factor.
	SaveUnconfirmed(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, sealedSecret string) error
	SavePending(ctx context.Context, tokenHash []byte, pending Pending) error
}

// Transaction serializes code checks per user so a code cannot be used twice.
type Transaction interface {
	// Factor locks the user's TOTP factor; ok is false when there is none.
	Factor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (factor Factor, ok bool, err error)
	UseStep(ctx context.Context, factor identity.FactorID, step int64) error
	Confirm(ctx context.Context, factor identity.FactorID, step int64) error
	// SetFailures records the wrong codes in a row and the lockout they
	// caused (nil: not locked).
	SetFailures(ctx context.Context, factor identity.FactorID, failures int, lockedUntil *time.Time) error
	// UseRecovery marks an unused recovery code used; false when there is
	// no such unused code.
	UseRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, codeHash []byte) (bool, error)
	ReplaceRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, codeHashes [][]byte) error
	// DeleteFactors removes the user's factors and recovery codes; false
	// when there was nothing to remove.
	DeleteFactors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (bool, error)
	// Pending locks an unexpired pending login.
	Pending(ctx context.Context, tokenHash []byte) (Pending, error)
	FailPending(ctx context.Context, tokenHash []byte) error
	DeletePending(ctx context.Context, tokenHash []byte) error
	Audit(ctx context.Context, m Mutation) error
	Commit() error
	Rollback() error
}

// TOTP generates and checks RFC 6238 codes.
type TOTP interface {
	// Secret returns a new random base32 secret.
	Secret() (string, error)
	// URI is the otpauth:// URI authenticator apps import.
	URI(secret string, account Account) string
	// Verify accepts a code within the allowed skew whose time step is
	// after the last one used, and returns that step.
	Verify(secret, code string, lastStep int64, at time.Time) (step int64, ok bool)
}

// Cipher seals TOTP secrets at rest (IAMKIT_ENCRYPTION_KEY).
type Cipher interface {
	Enabled() bool
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// Secrets generates pending-login tokens and recovery codes and hashes them.
type Secrets interface {
	Generate(prefix string) (raw string, hash []byte, err error)
	Hash(raw string) []byte
}
