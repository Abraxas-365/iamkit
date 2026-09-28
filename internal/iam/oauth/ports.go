package oauth

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ClientRepository interface {
	FindActive(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (*Client, error)
}

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Registration) (identity.ClientID, string, error)
	Update(ctx context.Context, m Mutation, client identity.ClientID, input ClientUpdate) error
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter ClientFilter, page query.Pagination) (query.Paginated[ClientView], error)
	Find(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (ClientView, error)
}
type Flows interface {
	Client(ctx context.Context, client identity.ClientID) (*Client, error)
	Start(ctx context.Context, client *Client, form string) (string, string, error)
	// Pending checks an unfinished authorization ticket and its browser
	// binding without consuming it (hosted login pages).
	Pending(ctx context.Context, ticket, binding string) (Pending, error)
	Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(Ticket, Authorization) error) error
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
}

type Authorization interface {
	Ticket(ctx context.Context, hash []byte) (Ticket, error)
	// Session is the end-user session an authorization completes with.
	Session(ctx context.Context, session identity.SessionID) (SessionInfo, error)
	Consume(ctx context.Context, hash []byte) error
	Commit() error
	Rollback() error
}
type Repository interface {
	ClientRepository
	Environment(ctx context.Context, client identity.ClientID) (identity.EnvironmentID, error)
	Create(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, input Registration, secretHash []byte) error
	Update(ctx context.Context, m Mutation, client identity.ClientID, input ClientUpdate) error
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
	List(ctx context.Context, environment identity.EnvironmentID, filter ClientFilter, page query.Pagination) (query.Paginated[ClientView], error)
	Find(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (ClientView, error)
	SaveTicket(ctx context.Context, ticketHash, bindingHash []byte, client *Client, form string) error
	// PendingTicket reads an unconsumed, unexpired ticket without locking it.
	PendingTicket(ctx context.Context, ticketHash []byte) (Ticket, error)
	Begin(ctx context.Context) (Authorization, error)
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Passwords interface {
	Hash(password string) (string, error)
}
