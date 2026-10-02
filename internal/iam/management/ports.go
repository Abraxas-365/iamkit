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
	// Login signs in with a password. When the password must be replaced
	// (set by someone else) it fails with PASSWORD_CHANGE_REQUIRED unless
	// newPassword is given, which then replaces it.
	Login(ctx context.Context, email, password, newPassword string) (string, Principal, error)
	Logout(ctx context.Context, raw string) error
	// SetPassword changes the caller's password: current must match the
	// existing one; without one, the caller needs a recent sign-in (or a
	// management key). Other sessions end; the calling one stays.
	SetPassword(ctx context.Context, p Principal, current, password string) error
	// SetPreferences replaces the caller's console settings.
	SetPreferences(ctx context.Context, p Principal, input Preferences) error
}

// SessionQueries reads the caller's own sign-in state and settings.
type SessionQueries interface {
	PasswordStatus(ctx context.Context, p Principal) (PasswordStatus, error)
	Preferences(ctx context.Context, p Principal) (Preferences, error)
}

// SSOFlows is operator single sign-on through the providers the deployment
// configured. Callback returns a raw operator session like Login.
type SSOFlows interface {
	Options(ctx context.Context) LoginOptions
	Start(ctx context.Context, provider string) (SSOStart, error)
	Callback(ctx context.Context, code, state, binding string) (string, Principal, error)
}

// IdentityCommands and IdentityQueries manage the provider identities
// linked to a workspace's operators.
type IdentityCommands interface {
	// UnlinkIdentities removes every identity of the operator and revokes
	// their sessions; the next single sign-on links by verified email again.
	UnlinkIdentities(ctx context.Context, p Principal, operator identity.OperatorID) error
}
type IdentityQueries interface {
	Identities(ctx context.Context, p Principal, operator identity.OperatorID) ([]OperatorIdentity, error)
}

// IdentityProvider talks to the configured operator identity providers.
type IdentityProvider interface {
	Authorize(ctx context.Context, provider, state, nonce, verifier string) (string, error)
	Verify(ctx context.Context, provider, code, nonce, verifier string) (SSOClaims, error)
	Verifier() string
}

type ControlCommands interface {
	CreateKey(ctx context.Context, p Principal, expiresIn *string) (Credential, error)
	RevokeKey(ctx context.Context, p Principal, key identity.KeyID) error
	Delegate(ctx context.Context, p Principal, email, role string, expiresIn *string) (Delegated, error)
	DisableOperator(ctx context.Context, p Principal, operator identity.OperatorID) error
	// SetPasswordAccess grants or removes an operator's emergency password
	// access (owners only); it matters in break-glass mode.
	SetPasswordAccess(ctx context.Context, p Principal, operator identity.OperatorID, allowed bool) error
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
	Sessions(ctx context.Context, environment identity.EnvironmentID, filter SessionFilter, page query.Pagination) (query.Paginated[Session], error)
	Audit(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[AuditEvent], error)
}

type Repository interface {
	Bootstrap(ctx context.Context, email, name string, hash []byte, expires time.Time) error
	RecoverOwner(ctx context.Context, workspace identity.WorkspaceID, email string, hash []byte, expires time.Time) error
	Authenticate(ctx context.Context, hash []byte) (Principal, error)
	EnvironmentAllowed(ctx context.Context, workspace identity.WorkspaceID, environment identity.EnvironmentID) (bool, error)
}

type SessionRepository interface {
	// PasswordByEmail returns the active operator's principal, password hash
	// and emergency access grant in that workspace.
	PasswordByEmail(ctx context.Context, email string) (PasswordAccount, error)
	// OperatorPassword is the operator's password account in the workspace
	// (Principal is left zero); Unauthorized when not an active member.
	OperatorPassword(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) (PasswordAccount, error)
	// CreateSession stores a console session signed in now by p.Method.
	CreateSession(ctx context.Context, session identity.SessionID, p Principal, hash []byte, expires time.Time) error
	AuthenticateSession(ctx context.Context, hash []byte) (Principal, error)
	RevokeSessionByHash(ctx context.Context, hash []byte) error
	// SetPassword stores the hash and must-change flag and revokes every
	// session of the operator except keep (zero: all), in one transaction.
	SetPassword(ctx context.Context, operator identity.OperatorID, hash string, mustChange bool, keep identity.SessionID) error
	ResetPassword(ctx context.Context, operator identity.OperatorID) error
	Preferences(ctx context.Context, operator identity.OperatorID) (Preferences, error)
	SetPreferences(ctx context.Context, operator identity.OperatorID, input Preferences) error
}

type SSORepository interface {
	SaveSSOState(ctx context.Context, hash []byte, s SSOState, expires time.Time) error
	// ConsumeSSOState returns and spends the unexpired state whose binding
	// matches; ErrSSOExpired otherwise.
	ConsumeSSOState(ctx context.Context, stateHash, bindingHash []byte) (SSOState, error)
	// LinkedOperator returns the active principal linked to the identity;
	// found is false when the identity is not linked.
	LinkedOperator(ctx context.Context, issuer, subject string) (p Principal, found bool, err error)
	// LinkOperator links the identity to the active operator with the email
	// and returns it; ErrSSONotAuthorized when there is none or it is
	// already linked to another subject of the issuer.
	LinkOperator(ctx context.Context, issuer, subject, provider, email string) (Principal, error)
	// TouchIdentity records a sign-in with the identity.
	TouchIdentity(ctx context.Context, issuer, subject string) error
	Identities(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) ([]OperatorIdentity, error)
	UnlinkIdentities(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) error
}

type ControlRepository interface {
	CreateKey(ctx context.Context, p Principal, key identity.KeyID, hash []byte, expires time.Time) error
	Keys(ctx context.Context, p Principal) ([]Key, error)
	RevokeKey(ctx context.Context, p Principal, key identity.KeyID) error
	Delegate(ctx context.Context, p Principal, email, role string, key identity.KeyID, hash []byte, expires time.Time) (identity.OperatorID, error)
	DisableOperator(ctx context.Context, p Principal, operator identity.OperatorID) error
	// SetPasswordAccess updates the workspace membership; NotFound when the
	// operator is not a member.
	SetPasswordAccess(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID, allowed bool) error
	Operators(ctx context.Context, workspace identity.WorkspaceID) ([]Operator, error)
	CreateProject(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID, name string) error
	Projects(ctx context.Context, workspace identity.WorkspaceID) ([]Named, error)
	CreateEnvironment(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID, environment identity.EnvironmentID, name string) error
	Environments(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID) ([]Named, error)
}

type ActivityRepository interface {
	Sessions(ctx context.Context, environment identity.EnvironmentID, filter SessionFilter, page query.Pagination) (query.Paginated[Session], error)
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
