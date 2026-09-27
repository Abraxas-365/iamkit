package federation

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, m Mutation, input ConnectionInput) (identity.ConnectionID, error)
	Update(ctx context.Context, m Mutation, connection identity.ConnectionID, input ConnectionUpdate) error
	Link(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID) error
	Disable(ctx context.Context, m Mutation, connection identity.ConnectionID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter ConnectionFilter, page query.Pagination) (query.Paginated[ConnectionView], error)
	Connection(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (ConnectionDetail, error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, page query.Pagination) (query.Paginated[ExternalIdentityView], error)
}
type Flows interface {
	Discover(ctx context.Context, environment identity.EnvironmentID, email string) (Discovery, error)
	Start(ctx context.Context, boundary authentication.Context, connection identity.ConnectionID) (Start, error)
	// StartHosted starts a login for the hosted pages: the organization is
	// the connection's own, or chosen after the callback for environment
	// connections. continuation is the authorization ticket to resume.
	StartHosted(ctx context.Context, target authentication.Target, connection identity.ConnectionID, continuation string) (Start, error)
	Callback(ctx context.Context, code, state, binding string) (Outcome, error)
	// EnvironmentConnections lists the active connections that serve the
	// whole environment (social and workforce providers shown as buttons).
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionSummary, error)
}

type Repository interface {
	Create(ctx context.Context, m Mutation, input Connection) error
	Update(ctx context.Context, m Mutation, input Connection) error
	Find(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (Connection, error)
	FindDetail(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (ConnectionDetail, error)
	List(ctx context.Context, environment identity.EnvironmentID, filter ConnectionFilter, page query.Pagination) (query.Paginated[ConnectionView], error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, page query.Pagination) (query.Paginated[ExternalIdentityView], error)
	// HasVerifiedDomain reports whether the organization has verified any domain.
	HasVerifiedDomain(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error)
	// OperatorGroup reports whether the group exists in the organization and
	// is managed by operators rather than a SCIM directory.
	OperatorGroup(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, group identity.GroupID) (bool, error)
	// Discover returns the SSO route for a verified domain; the zero value
	// when no organization verified it or it has no active connection.
	Discover(ctx context.Context, environment identity.EnvironmentID, domain string) (Discovery, error)
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionSummary, error)
	SaveState(ctx context.Context, hash []byte, s State) error
	ConsumeState(ctx context.Context, stateHash, bindingHash []byte) (State, error)
	// LinkedUser returns an open transaction and the linked active user, or
	// (nil, zero, nil) when the subject is not linked.
	LinkedUser(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, subject string) (authentication.Transaction, identity.UserID, error)
	// Provision links the subject on first login, adopting the active user
	// with the email or creating one, and commits. It fails unless the email's
	// domain is verified by the organization.
	Provision(ctx context.Context, p Provisioning) error
	Link(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID) error
	Disable(ctx context.Context, m Mutation, connection identity.ConnectionID) error
}

// Provider talks to external OIDC providers. It resolves the connection's
// client secret itself: sealed secrets are opened with the Cipher, legacy
// secret_env references must match an approved deployment binding.
type Provider interface {
	Approved(c Connection) bool
	Authorize(ctx context.Context, c Connection, state, nonce, verifier string) (string, error)
	Verify(ctx context.Context, c Connection, code, nonce, verifier string) (Claims, error)
	Verifier() string
}

// Cipher seals client secrets for storage at rest.
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Sessions interface {
	NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID) (authentication.Issued, error)
}
