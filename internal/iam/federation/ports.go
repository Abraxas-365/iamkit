package federation

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, input Connection) (identity.ConnectionID, error)
	Link(ctx context.Context, m Mutation, connectionID identity.ConnectionID, userID identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connectionID identity.ConnectionID, userID identity.UserID) error
	Disable(ctx context.Context, m Mutation, connectionID identity.ConnectionID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionView, error)
	Connection(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (ConnectionDetail, error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) ([]ExternalIdentityView, error)
}
type Flows interface {
	Start(ctx context.Context, boundary authentication.Context, connectionID identity.ConnectionID) (Start, error)
	Callback(ctx context.Context, code, state, binding string) (authentication.Issued, error)
}

type Repository interface {
	Create(ctx context.Context, input Connection) error
	Find(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (Connection, error)
	FindDetail(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (ConnectionDetail, error)
	List(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionView, error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) ([]ExternalIdentityView, error)
	SaveState(ctx context.Context, hash []byte, s State) error
	ConsumeState(ctx context.Context, stateHash, bindingHash []byte) (State, error)
	LinkedUser(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID, subject string) (authentication.Transaction, identity.UserID, error)
	Link(ctx context.Context, m Mutation, connectionID identity.ConnectionID, userID identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connectionID identity.ConnectionID, userID identity.UserID) error
	Disable(ctx context.Context, m Mutation, connectionID identity.ConnectionID) error
}
type Provider interface {
	Approved(c Connection) bool
	Authorize(ctx context.Context, c Connection, redirectURI, nonce, verifier string) (string, error)
	Verify(ctx context.Context, c Connection, code, redirectURI, verifier string) (string, error)
	Verifier() string
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Sessions interface {
	NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, userID identity.UserID) (authentication.Issued, error)
}
