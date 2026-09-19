package management

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ManagementAuthenticator interface {
	Authenticate(ctx context.Context, raw string) (Principal, error)
	AuthenticateSession(ctx context.Context, raw string) (Principal, error)
	EnvironmentAllowed(ctx context.Context, p Principal, environment identity.EnvironmentID) bool
}

type SessionCommands interface {
	Login(ctx context.Context, email, password string) (string, Principal, error)
	Logout(ctx context.Context, raw string) error
	SetPassword(ctx context.Context, p Principal, password string) error
}

type ControlCommands interface {
	CreateKey(ctx context.Context, p Principal, expiresIn *string) (Credential, error)
	RevokeKey(ctx context.Context, p Principal, key identity.KeyID) error
	Delegate(ctx context.Context, p Principal, email, role string, expiresIn *string) (Delegated, error)
	DisableOperator(ctx context.Context, p Principal, operator identity.OperatorID) error
	CreateProject(ctx context.Context, p Principal, name string) (identity.ProjectID, error)
	CreateEnvironment(ctx context.Context, p Principal, project identity.ProjectID, name string) (identity.EnvironmentID, error)
}
type ControlQueries interface {
	Keys(ctx context.Context, p Principal) ([]Key, error)
	Operators(ctx context.Context, p Principal) ([]Operator, error)
	Projects(ctx context.Context, p Principal) ([]Named, error)
	Environments(ctx context.Context, p Principal, project identity.ProjectID) ([]Named, error)
}

type ActivityCommands interface {
	RevokeSession(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, actor, action, target string) error
}
type ActivityQueries interface {
	Sessions(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Session], error)
	Audit(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[AuditEvent], error)
}

type Repository interface {
	Bootstrap(ctx context.Context, email, name string, hash []byte, expires time.Time) error
	RecoverOwner(ctx context.Context, workspace identity.WorkspaceID, email string, hash []byte, expires time.Time) error
	Authenticate(ctx context.Context, hash []byte) (Principal, error)
	EnvironmentAllowed(ctx context.Context, workspace identity.WorkspaceID, environment identity.EnvironmentID) (bool, error)
}

type SessionRepository interface {
	PasswordByEmail(ctx context.Context, email string) (Principal, string, error)
	CreateSession(ctx context.Context, session identity.SessionID, p Principal, hash []byte, expires time.Time) error
	AuthenticateSession(ctx context.Context, hash []byte) (Principal, error)
	RevokeSessionByHash(ctx context.Context, hash []byte) error
	RevokeOperatorSessions(ctx context.Context, operator identity.OperatorID) error
	SetPassword(ctx context.Context, operator identity.OperatorID, hash string) error
	ResetPassword(ctx context.Context, operator identity.OperatorID) error
}

type ControlRepository interface {
	CreateKey(ctx context.Context, p Principal, key identity.KeyID, hash []byte, expires time.Time) error
	Keys(ctx context.Context, p Principal) ([]Key, error)
	RevokeKey(ctx context.Context, p Principal, key identity.KeyID) error
	Delegate(ctx context.Context, p Principal, email, role string, key identity.KeyID, hash []byte, expires time.Time) (identity.OperatorID, error)
	DisableOperator(ctx context.Context, p Principal, operator identity.OperatorID) error
	Operators(ctx context.Context, workspace identity.WorkspaceID) ([]Operator, error)
	CreateProject(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID, name string) error
	Projects(ctx context.Context, workspace identity.WorkspaceID) ([]Named, error)
	CreateEnvironment(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID, environment identity.EnvironmentID, name string) error
	Environments(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID) ([]Named, error)
}

type ActivityRepository interface {
	Sessions(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Session], error)
	Audit(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[AuditEvent], error)
	RevokeSession(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, actor, action, target string) error
}

type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}

type Passwords interface {
	Hash(password string) (string, error)
	Compare(hash, password string) bool
}
