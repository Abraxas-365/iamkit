package authentication

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Login(ctx context.Context, boundary Context, email, password string) (Issued, error)
	Refresh(ctx context.Context, boundary Context, token string) (Issued, error)
	InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.ChallengeID, error)
	VerifyChallenge(ctx context.Context, boundary Context, challenge identity.ChallengeID, code, purpose, password string) (Issued, error)
}

type SessionCreator interface {
	NewSession(ctx context.Context, tx Transaction, boundary Context, user identity.UserID) (Issued, error)
}

type SessionCommands interface {
	Logout(ctx context.Context, token Token) error
	UpdateProfile(ctx context.Context, token Token, organization identity.OrganizationID) error
	AddMember(ctx context.Context, token Token, organization identity.OrganizationID) error
}
type SessionQueries interface {
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
}

type Delivery interface {
	Send(ctx context.Context, email, subject, body string) error
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
	SetDeliveryConfig(ctx context.Context, environment identity.EnvironmentID, webhookURL, webhookToken string) error
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

// Transactions retain the original user/session/challenge lock ordering.
type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
}
type Transaction interface {
	PasswordUser(ctx context.Context, boundary Context, email string) (identity.UserID, string, error)
	Resolve(ctx context.Context, boundary Context, user identity.UserID) (Access, error)
	CreateSession(ctx context.Context, boundary Context, user identity.UserID, session identity.SessionID, expires time.Time) error
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
	OAuthActive(ctx context.Context, token Token, client identity.ClientID) (bool, error)
	Machine(ctx context.Context, hash []byte) (Token, string, error)
	Revoke(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID) error
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
	UpdateProfile(ctx context.Context, token Token, organization identity.OrganizationID) error
	AddMember(ctx context.Context, token Token, organization identity.OrganizationID) error
}
