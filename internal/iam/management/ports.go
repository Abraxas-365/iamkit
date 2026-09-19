package management

import (
	"context"
	"time"
)

// ManagementAuthenticator validates management API credentials.
type ManagementAuthenticator interface {
	Authenticate(ctx context.Context, raw string) (Principal, error)
	AuthenticateSession(ctx context.Context, raw string) (Principal, error)
	EnvironmentAllowed(ctx context.Context, p Principal, environment string) bool
}

type SessionCommands interface {
	Login(ctx context.Context, email, password string) (string, Principal, error)
	Logout(ctx context.Context, raw string) error
	SetPassword(ctx context.Context, p Principal, password string) error
}

type ControlCommands interface {
	CreateKey(ctx context.Context, p Principal, expiresIn *string) (Credential, error)
	RevokeKey(ctx context.Context, p Principal, keyID string) error
	Delegate(ctx context.Context, p Principal, email, role string, expiresIn *string) (Delegated, error)
	DisableOperator(ctx context.Context, p Principal, operatorID string) error
	CreateProject(ctx context.Context, p Principal, name string) (string, error)
	CreateEnvironment(ctx context.Context, p Principal, projectID, name string) (string, error)
}
type ControlQueries interface {
	Keys(ctx context.Context, p Principal) ([]Key, error)
	Operators(ctx context.Context, p Principal) ([]Operator, error)
	Projects(ctx context.Context, p Principal) ([]Named, error)
	Environments(ctx context.Context, p Principal, projectID string) ([]Named, error)
}

type ActivityCommands interface {
	RevokeSession(ctx context.Context, environment, sessionID, actor, action, target string) error
}
type ActivityQueries interface {
	Sessions(ctx context.Context, environment string) ([]Session, error)
	Audit(ctx context.Context, environment string) ([]AuditEvent, error)
}

// Repository operations preserve bootstrap/recovery atomicity without exposing SQL transactions.
type Repository interface {
	Bootstrap(ctx context.Context, email, name string, hash []byte, expires time.Time) error
	RecoverOwner(ctx context.Context, workspaceID, email string, hash []byte, expires time.Time) error
	Authenticate(ctx context.Context, hash []byte) (Principal, error)
	EnvironmentAllowed(ctx context.Context, workspaceID, environment string) (bool, error)
}

type SessionRepository interface {
	PasswordByEmail(ctx context.Context, email string) (Principal, string, error)
	CreateSession(ctx context.Context, sessionID string, p Principal, hash []byte, expires time.Time) error
	AuthenticateSession(ctx context.Context, hash []byte) (Principal, error)
	RevokeSessionByHash(ctx context.Context, hash []byte) error
	RevokeOperatorSessions(ctx context.Context, operatorID string) error
	SetPassword(ctx context.Context, operatorID, hash string) error
	ResetPassword(ctx context.Context, operatorID string) error
}

type ControlRepository interface {
	CreateKey(ctx context.Context, p Principal, keyID string, hash []byte, expires time.Time) error
	Keys(ctx context.Context, p Principal) ([]Key, error)
	RevokeKey(ctx context.Context, p Principal, keyID string) error
	Delegate(ctx context.Context, p Principal, email, role, keyID string, hash []byte, expires time.Time) (string, error)
	DisableOperator(ctx context.Context, p Principal, operatorID string) error
	Operators(ctx context.Context, workspaceID string) ([]Operator, error)
	CreateProject(ctx context.Context, workspaceID, projectID, name string) error
	Projects(ctx context.Context, workspaceID string) ([]Named, error)
	CreateEnvironment(ctx context.Context, workspaceID, projectID, environmentID, name string) error
	Environments(ctx context.Context, workspaceID, projectID string) ([]Named, error)
}

type ActivityRepository interface {
	Sessions(ctx context.Context, environment string) ([]Session, error)
	Audit(ctx context.Context, environment string) ([]AuditEvent, error)
	RevokeSession(ctx context.Context, environment, sessionID, actor, action, target string) error
}

type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}

type Passwords interface {
	Hash(password string) (string, error)
	Compare(hash, password string) bool
}
