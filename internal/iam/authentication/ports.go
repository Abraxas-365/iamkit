package authentication

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Login(ctx context.Context, boundary Context, email, password string) (Result, error)
	Refresh(ctx context.Context, boundary Context, token string) (Issued, error)
	InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.ChallengeID, error)
	VerifyChallenge(ctx context.Context, boundary Context, challenge identity.ChallengeID, code, purpose, password string) (Result, error)
}

// SecondFactor is the multi-factor step of headless logins, implemented by
// the mfa module. Nil disables MFA.
type SecondFactor interface {
	Requirement(ctx context.Context, boundary Context, user identity.UserID, federated bool) (Requirement, error)
	Begin(ctx context.Context, boundary Context, user identity.UserID, amr []string, enroll bool) (string, error)
	// Complete verifies the code of a pending login and runs issue before
	// committing: when issue fails the verification rolls back.
	Complete(ctx context.Context, token, code string, issue func(done Completed) error) (Completed, error)
	Enroll(ctx context.Context, token string) (Enrollment, error)
}

// MFACommands finish a headless login that answered mfa_required.
type MFACommands interface {
	VerifyMFA(ctx context.Context, token, code string) (Issued, error)
	EnrollMFA(ctx context.Context, token string) (Enrollment, error)
}

// Authenticator splits login in two for the hosted pages: verify who the
// user is (no organization yet), then issue the session once the
// organization is chosen.
type Authenticator interface {
	VerifyPassword(ctx context.Context, environment identity.EnvironmentID, email, password string) (Verified, error)
	VerifyCode(ctx context.Context, environment identity.EnvironmentID, challenge identity.ChallengeID, code string) (Verified, error)
	// Organizations lists the organizations in which the user may use the
	// target application and resource.
	Organizations(ctx context.Context, target Target, user identity.UserID) ([]Organization, error)
	// Issue creates the session; password and code logins are refused where
	// the organization enforces SSO.
	Issue(ctx context.Context, boundary Context, verified Verified) (Issued, error)
}

type SessionCommands interface {
	Logout(ctx context.Context, token Token) error
	UpdateProfile(ctx context.Context, token Token, name string) error
	AddMember(ctx context.Context, token Token, user identity.UserID) error
}
type SessionQueries interface {
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
}

type Delivery interface {
	Send(ctx context.Context, message Message) error
}

// DeliveryConfigCommands manages per-environment webhook delivery settings.
type DeliveryConfigCommands interface {
	SetDeliveryConfig(ctx context.Context, environment identity.EnvironmentID, input DeliveryConfigInput) error
	DeleteDeliveryConfig(ctx context.Context, environment identity.EnvironmentID) error
}

// DeliveryConfigQueries reads per-environment webhook delivery settings.
type DeliveryConfigQueries interface {
	DeliveryConfig(ctx context.Context, environment identity.EnvironmentID) (DeliveryConfig, error)
}

// DeliveryConfigRepository is the storage interface for delivery configs.
type DeliveryConfigRepository interface {
	GetDeliveryConfig(ctx context.Context, environment identity.EnvironmentID) (DeliveryConfig, string, error) // config, webhook token, error
	SetDeliveryConfig(ctx context.Context, environment identity.EnvironmentID, input DeliveryConfigInput) error
	DeleteDeliveryConfig(ctx context.Context, environment identity.EnvironmentID) error
}
type Passwords interface {
	Hash(password string) (string, error)
	Compare(hash, password string) bool
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
	Code() (string, error)
}

type TokenIssuer interface {
	Issue(token Token, audience string) (string, error)
	KeyID() string
	JWKS() any
	Machine(ctx context.Context, raw string) (string, error)
}
type TokenValidator interface {
	Validate(ctx context.Context, raw string, audience string, environment identity.EnvironmentID) (Token, error)
	// ValidateSelf verifies a JWT that IAMKit itself issued, without requiring
	// the caller to specify audience/environment upfront. Used by /api/v1/*
	// where the token's own claims determine the environment scope.
	ValidateSelf(ctx context.Context, raw string) (Token, error)
}
type TokenCodec interface {
	Sign(token Token) (string, error)
	Verify(raw, audience string) (Token, error)
	// VerifySelf checks signature, issuer, and expiry without audience enforcement.
	VerifySelf(raw string) (Token, error)
	KeyID() string
	JWKS() any
}

// OAuthTokens reports whether an OAuth-issued access token is still live.
// The OAuth adapter owns token storage (and its signature hashing), so the
// authentication service asks it rather than reading OAuth tables itself.
// signature is the JWT's third segment.
type OAuthTokens interface {
	Active(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, signature string) (bool, error)
}

// Transactions retain the original user/session/challenge lock ordering.
type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
}
type Transaction interface {
	PasswordUser(ctx context.Context, boundary Context, email string) (identity.UserID, string, error)
	// SSORequired reports whether the boundary organization requires SSO for
	// the email: it has an active enforced connection, has verified the
	// email's domain, and the email's user has no sso_bypass membership.
	SSORequired(ctx context.Context, boundary Context, email string) (bool, error)
	// AccessibleOrganizations lists active organizations where the user is an
	// active member with grants on the target resource of an active
	// application linked to it.
	AccessibleOrganizations(ctx context.Context, target Target, user identity.UserID) ([]Organization, error)
	Resolve(ctx context.Context, boundary Context, user identity.UserID) (Access, error)
	// CreateSession stores the session; authenticated is its auth_time,
	// kept across refreshes.
	CreateSession(ctx context.Context, boundary Context, user identity.UserID, session identity.SessionID, authenticated, expires time.Time, amr []string) error
	SaveRefresh(ctx context.Context, hash []byte, user identity.UserID, session identity.SessionID, expires time.Time) error
	Refresh(ctx context.Context, boundary Context, hash []byte) (Session, error)
	RevokeSession(ctx context.Context, session identity.SessionID) error
	UseRefresh(ctx context.Context, hash []byte) error
	EligibleChallengeUser(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.UserID, error)
	RecentChallenges(ctx context.Context, user identity.UserID, purpose string) (int, error)
	CreateChallenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, hash []byte) error
	Challenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string) (Challenge, error)
	FailChallenge(ctx context.Context, challenge identity.ChallengeID) error
	CompleteChallenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, password string) error
	Commit() error
	Rollback() error
}

type TokenRepository interface {
	Current(ctx context.Context, token Token, environment identity.EnvironmentID) ([]string, error)
	ActorActive(ctx context.Context, token Token) (bool, error)
	Machine(ctx context.Context, hash []byte) (Token, string, error)
	Revoke(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID) error
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
	UpdateProfile(ctx context.Context, token Token, name string) error
	AddMember(ctx context.Context, token Token, user identity.UserID) error
}
