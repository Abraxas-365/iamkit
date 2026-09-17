package authentication

import (
	"context"
	"time"
)

type Context struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
}
type Access struct {
	Audience    string
	Permissions []string
}
type Session struct {
	ID, User      string
	Expires       time.Time
	Used, Revoked bool
}
type Challenge struct {
	User     string
	Hash     []byte
	Attempts int
}
type Issued struct {
	Context                Context
	User, Session, Refresh string
	Access                 Access
}
type Commands interface {
	Login(context.Context, Context, string, string) (Issued, error)
	Refresh(context.Context, Context, string) (Issued, error)
	InitiateChallenge(context.Context, string, string, string) (string, error)
	VerifyChallenge(context.Context, Context, string, string, string, string) (Issued, error)
}

type SessionCreator interface {
	NewSession(context.Context, Transaction, Context, string) (Issued, error)
}

type Delivery interface {
	Send(context.Context, string, string, string) error
}
type Passwords interface {
	Hash(string) (string, error)
	Compare(string, string) bool
}
type Secrets interface {
	Generate(string) (string, []byte, error)
	Hash(string) []byte
	Code() (string, error)
}

// Transactions retain the original user/session/challenge lock ordering.
type Repository interface {
	Begin(context.Context) (Transaction, error)
}
type Transaction interface {
	PasswordUser(context.Context, Context, string) (string, string, error)
	Resolve(context.Context, Context, string) (Access, error)
	CreateSession(context.Context, Context, string, string, time.Time) error
	SaveRefresh(context.Context, []byte, string, string, time.Time) error
	Refresh(context.Context, Context, []byte) (Session, error)
	RevokeSession(context.Context, string) error
	UseRefresh(context.Context, []byte) error
	EligibleChallengeUser(context.Context, string, string, string) (string, error)
	RecentChallenges(context.Context, string, string) (int, error)
	CreateChallenge(context.Context, string, string, string, string, []byte) error
	Challenge(context.Context, string, string, string) (Challenge, error)
	FailChallenge(context.Context, string) error
	CompleteChallenge(context.Context, string, string, string, string, string) error
	Commit() error
	Rollback() error
}
