package authentication

import (
	"context"
	"time"
)

type Commands interface {
	Login(ctx context.Context, boundary Context, email, password string) (Issued, error)
	Refresh(ctx context.Context, boundary Context, token string) (Issued, error)
	InitiateChallenge(ctx context.Context, environment, email, purpose string) (string, error)
	VerifyChallenge(ctx context.Context, boundary Context, id, code, purpose, password string) (Issued, error)
}

type SessionCreator interface {
	NewSession(ctx context.Context, tx Transaction, boundary Context, userID string) (Issued, error)
}

type SessionCommands interface {
	Logout(ctx context.Context, token Token) error
	UpdateProfile(ctx context.Context, token Token, organizationID string) error
	AddMember(ctx context.Context, token Token, organizationID string) error
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
	SetDeliveryConfig(ctx context.Context, environmentID string, input DeliveryConfigInput) error
	DeleteDeliveryConfig(ctx context.Context, environmentID string) error
}

// DeliveryConfigQueries reads per-environment webhook delivery settings.
type DeliveryConfigQueries interface {
	DeliveryConfig(ctx context.Context, environmentID string) (DeliveryConfig, error)
}

// DeliveryConfigRepository is the storage interface for delivery configs.
type DeliveryConfigRepository interface {
	GetDeliveryConfig(ctx context.Context, environmentID string) (DeliveryConfig, string, error) // config, webhook token, error
	SetDeliveryConfig(ctx context.Context, environmentID, webhookURL, webhookToken string) error
	DeleteDeliveryConfig(ctx context.Context, environmentID string) error
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
	Validate(ctx context.Context, raw, audience, environment string) (Token, error)
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
	PasswordUser(ctx context.Context, boundary Context, email string) (string, string, error)
	Resolve(ctx context.Context, boundary Context, userID string) (Access, error)
	CreateSession(ctx context.Context, boundary Context, userID, sessionID string, expires time.Time) error
	SaveRefresh(ctx context.Context, hash []byte, userID, sessionID string, expires time.Time) error
	Refresh(ctx context.Context, boundary Context, hash []byte) (Session, error)
	RevokeSession(ctx context.Context, sessionID string) error
	UseRefresh(ctx context.Context, hash []byte) error
	EligibleChallengeUser(ctx context.Context, environment, email, purpose string) (string, error)
	RecentChallenges(ctx context.Context, userID, purpose string) (int, error)
	CreateChallenge(ctx context.Context, challengeID, userID, purpose, environment string, hash []byte) error
	Challenge(ctx context.Context, challengeID, userID, purpose string) (Challenge, error)
	FailChallenge(ctx context.Context, challengeID string) error
	CompleteChallenge(ctx context.Context, challengeID, userID, purpose, environment, password string) error
	Commit() error
	Rollback() error
}

type TokenRepository interface {
	Current(ctx context.Context, token Token, environment string) ([]string, error)
	ActorActive(ctx context.Context, token Token) (bool, error)
	OAuthActive(ctx context.Context, token Token, clientID string) (bool, error)
	Machine(ctx context.Context, hash []byte) (Token, string, error)
	Revoke(ctx context.Context, environment, sessionID string) error
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
	UpdateProfile(ctx context.Context, token Token, organizationID string) error
	AddMember(ctx context.Context, token Token, organizationID string) error
}
