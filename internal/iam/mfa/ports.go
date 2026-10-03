package mfa

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Logins are the second-factor steps of a login. They implement
// authentication.SecondFactor (headless API) and back the hosted pages.
// amr are the first factor's method references: the email factor never
// completes a login that started with an emailed code.
type Logins interface {
	// Requirement decides whether a login of the user into the boundary
	// needs a second factor, which factors it accepts and whether the user
	// must enroll one first.
	Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool, amr []string) (authentication.Requirement, error)
	// Begin parks a headless login until its second factor and returns the
	// ik_mfa_ token; passwordHash replaces an expired password once it passes.
	Begin(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, enroll bool, passwordHash string) (string, error)
	// Complete verifies a proof (TOTP, emailed or texted code, recovery
	// code, or security key) for a pending login and consumes it. The first
	// code of an enrolling login confirms the factor and returns recovery
	// codes. issue (the session) runs before the commit, so a failed session
	// keeps the pending login and the factor unconfirmed.
	Complete(ctx context.Context, token string, proof authentication.Proof, issue func(done authentication.Completed) error) (authentication.Completed, error)
	// Enroll starts the TOTP factor of a pending login that must enroll.
	Enroll(ctx context.Context, token string) (authentication.Enrollment, error)
	// Challenge sends a code for a pending login: to the user's email or SMS
	// factor, or — for a login that must enroll — to the user's email
	// address, which becomes their email factor once the code is entered.
	Challenge(ctx context.Context, token, factor string) (authentication.CodeSent, error)
	// Assert starts a security key prompt for a pending login.
	Assert(ctx context.Context, token string) (authentication.WebAuthnOptions, error)
	// Verify checks a proof for the user outside a headless login (hosted
	// pages). With enroll, an unconfirmed factor is confirmed by its first
	// code and the first recovery codes are returned.
	Verify(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, proof authentication.Proof, enroll bool) (Verification, error)
	// Send is Challenge for the hosted pages.
	Send(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, factor string, enroll bool) (authentication.CodeSent, error)
	// AssertFor is Assert for the hosted pages.
	AssertFor(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string) (authentication.WebAuthnOptions, error)
	// Enrolling returns the unconfirmed TOTP factor to show again, starting
	// one when there is none.
	Enrolling(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Enrollment, error)
}

// Commands are the self-service and operator factor use cases. kind is
// totp, email or sms.
type Commands interface {
	// Start creates an unconfirmed TOTP factor, replacing an earlier
	// unconfirmed one; a user with an active one must remove it first. The
	// environment and the boundary's organization must allow it.
	Start(ctx context.Context, boundary authentication.Context, user identity.UserID) (Enrollment, error)
	// StartCode creates (or refreshes) an unconfirmed email factor for the
	// user's address, or SMS factor for phone, and sends it a code; the kind
	// must be allowed like Start's.
	StartCode(ctx context.Context, boundary authentication.Context, user identity.UserID, kind, phone string) (authentication.CodeSent, error)
	// Confirm activates the unconfirmed factor of kind with its first code
	// and returns the recovery codes (first factor only). A wrong code fails
	// with 422, not 401: the caller's access token is fine.
	Confirm(ctx context.Context, m Mutation, user identity.UserID, kind, code string) ([]string, error)
	// SendProof sends a code to the user's active email or SMS factor, to
	// prove possession for Remove or Regenerate.
	SendProof(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, kind string) (authentication.CodeSent, error)
	// Remove deletes the user's factor of kind (and the recovery codes when
	// no other factor remains); proof shows possession of any factor.
	Remove(ctx context.Context, m Mutation, user identity.UserID, kind string, proof authentication.Proof) error
	// Regenerate replaces the recovery codes; proof shows possession.
	Regenerate(ctx context.Context, m Mutation, user identity.UserID, proof authentication.Proof) ([]string, error)
	// Reset deletes every factor and recovery code of a user (operator).
	Reset(ctx context.Context, m Mutation, user identity.UserID) error
	// StartWebAuthn begins registering a security key or passkey, allowed
	// like Start's.
	StartWebAuthn(ctx context.Context, boundary authentication.Context, user identity.UserID, input StartRegistration) (authentication.WebAuthnOptions, error)
	// FinishWebAuthn verifies the browser's attestation and adds the key;
	// the user's first factor also returns recovery codes.
	FinishWebAuthn(ctx context.Context, m Mutation, user identity.UserID, session string, credential []byte) (Registration, error)
	// ProveWebAuthn starts an assertion with any of the user's keys, to
	// prove possession for Remove, RemoveWebAuthn or Regenerate.
	ProveWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.WebAuthnOptions, error)
	// RenameWebAuthn names one of the user's keys.
	RenameWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, name string) (Factor, error)
	// RemoveWebAuthn deletes one of the user's keys; proof as for Remove.
	RemoveWebAuthn(ctx context.Context, m Mutation, user identity.UserID, factor identity.FactorID, proof authentication.Proof) error
}

// Passkeys sign users in with a discoverable WebAuthn credential
// (no email or password first).
type Passkeys interface {
	// BeginPasskey starts a passkey sign-in in the environment.
	BeginPasskey(ctx context.Context, environment identity.EnvironmentID) (authentication.WebAuthnOptions, error)
	// FinishPasskey verifies the assertion and returns the user.
	FinishPasskey(ctx context.Context, environment identity.EnvironmentID, session string, credential []byte) (identity.UserID, error)
}

// Relying is the WebAuthn relying party (adapter mfawebauthn). State is
// opaque to the service; it is kept with the ceremony until the answer.
type Relying interface {
	// Enabled reports whether the deployment has a usable relying party.
	Enabled() bool
	// Register starts a registration; passkey asks for a discoverable
	// credential that verifies the user.
	Register(holder Holder, passkey bool) (Challenge, error)
	// Created verifies an attestation answering a registration.
	Created(holder Holder, state, response []byte) (Credential, error)
	// Assert starts an assertion with one of the holder's credentials; a
	// zero holder starts a discoverable (passkey) one.
	Assert(holder Holder, verifyUser bool) (Challenge, error)
	// Handle reads the user handle of a passkey assertion before it is
	// verified, to look up its holder.
	Handle(response []byte) ([]byte, error)
	// Asserted verifies an assertion answering Assert.
	Asserted(holder Holder, state, response []byte) (Assertion, error)
}

type Queries interface {
	Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Summary, error)
}

type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
	Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Summary, error)
	// Policy is what the login requirement depends on; a zero organization
	// reads the environment's rules only.
	Policy(ctx context.Context, boundary authentication.Context, user identity.UserID) (Policy, error)
	// Allowed is the environment's allowed factor kinds.
	Allowed(ctx context.Context, environment identity.EnvironmentID) ([]string, error)
	Account(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Account, error)
	// SaveUnconfirmed stores a new unconfirmed TOTP factor in place of an
	// earlier unconfirmed one; it fails with a conflict when the user has an
	// active factor.
	SaveUnconfirmed(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, sealedSecret string) error
	SavePending(ctx context.Context, tokenHash []byte, pending Pending) error
	// SaveCeremony stores a started WebAuthn ceremony (sweeping expired ones).
	SaveCeremony(ctx context.Context, idHash []byte, ceremony Ceremony) error
	// RenameFactor names a WebAuthn factor of the user; not found otherwise.
	RenameFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, name string) (Factor, error)
}

// Transaction serializes code checks per user so a code cannot be used twice.
type Transaction interface {
	// Factors locks and returns every factor of the user (none: empty).
	Factors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]Factor, error)
	// Lock returns the user's wrong-code count; lock the factors first.
	Lock(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Lock, error)
	// SetLock records the wrong codes in a row and the lockout they caused
	// (nil: not locked).
	SetLock(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, lock Lock) error
	UseStep(ctx context.Context, factor identity.FactorID, step int64) error
	Confirm(ctx context.Context, factor identity.FactorID, step int64) error
	// SaveCodeFactor stores an unconfirmed email or SMS factor (phone ""
	// for email): it refreshes the user's unconfirmed one of that kind,
	// keeping its send counters, or inserts factor. It fails with a
	// conflict when the user has an active factor of that kind.
	SaveCodeFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, kind, phone string) (Factor, error)
	// SetCode stores a sent code on its factor, replacing the previous one.
	SetCode(ctx context.Context, factor identity.FactorID, code Code) error
	// UseCode consumes the factor's code.
	UseCode(ctx context.Context, factor identity.FactorID) error
	// FailCode counts a wrong entry of the factor's code and discards the
	// code after limit wrong entries.
	FailCode(ctx context.Context, factor identity.FactorID, limit int) error
	// ConfirmCode activates an email or SMS factor with its first code; an
	// SMS factor's number becomes the user's verified phone.
	ConfirmCode(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID) error
	// UseRecovery marks an unused recovery code used; false when there is
	// no such unused code.
	UseRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, codeHash []byte) (bool, error)
	ReplaceRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, codeHashes [][]byte) error
	// DeleteFactor removes one factor of the user.
	DeleteFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID) error
	// DeleteFactors removes the user's factors, recovery codes and lockout;
	// false when there was nothing to remove.
	DeleteFactors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (bool, error)
	// SaveWebAuthn stores a confirmed WebAuthn factor; a credential already
	// registered in the environment is a conflict.
	SaveWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor Factor, credential Credential) error
	// UseWebAuthn stores a credential's counter and flags after a sign-in.
	UseWebAuthn(ctx context.Context, factor identity.FactorID, credential Credential) error
	// TakeCeremony deletes and returns an unexpired ceremony of the
	// environment and purpose (single use); false when there is none.
	TakeCeremony(ctx context.Context, idHash []byte, environment identity.EnvironmentID, purpose string) (Ceremony, bool, error)
	// Pending locks an unexpired pending login.
	Pending(ctx context.Context, tokenHash []byte) (Pending, error)
	FailPending(ctx context.Context, tokenHash []byte) error
	DeletePending(ctx context.Context, tokenHash []byte) error
	Audit(ctx context.Context, m Mutation) error
	Commit() error
	Rollback() error
}

// Sender delivers second-factor codes: by email to the user's address, by
// SMS to a phone number. purpose is PurposeLogin or PurposePhone.
type Sender interface {
	Email(ctx context.Context, environment identity.EnvironmentID, email, purpose, code string) error
	SMS(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) error
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
