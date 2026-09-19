package federation

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

type Commands interface {
	Create(ctx context.Context, input Connection) (string, error)
	Link(ctx context.Context, m Mutation, connectionID, userID, subject string) error
	Unlink(ctx context.Context, m Mutation, connectionID, userID string) error
	Disable(ctx context.Context, m Mutation, connectionID string) error
}
type Queries interface {
	List(ctx context.Context, environment string) ([]ConnectionView, error)
	Connection(ctx context.Context, environment, connectionID string) (ConnectionDetail, error)
	Identities(ctx context.Context, environment, connectionID string) ([]ExternalIdentityView, error)
}
type Flows interface {
	Start(ctx context.Context, boundary authentication.Context, connectionID string) (Start, error)
	Callback(ctx context.Context, code, state, binding string) (authentication.Issued, error)
}

type Repository interface {
	Create(ctx context.Context, input Connection) error
	Find(ctx context.Context, environment, connectionID string) (Connection, error)
	FindDetail(ctx context.Context, environment, connectionID string) (ConnectionDetail, error)
	List(ctx context.Context, environment string) ([]ConnectionView, error)
	Identities(ctx context.Context, environment, connectionID string) ([]ExternalIdentityView, error)
	SaveState(ctx context.Context, hash []byte, s State) error
	ConsumeState(ctx context.Context, stateHash, bindingHash []byte) (State, error)
	LinkedUser(ctx context.Context, environment, connectionID, subject string) (authentication.Transaction, string, error)
	Link(ctx context.Context, m Mutation, connectionID, userID, subject string) error
	Unlink(ctx context.Context, m Mutation, connectionID, userID string) error
	Disable(ctx context.Context, m Mutation, connectionID string) error
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
	NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, userID string) (authentication.Issued, error)
}
