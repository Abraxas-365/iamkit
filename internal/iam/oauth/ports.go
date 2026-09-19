package oauth

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ClientRepository interface {
	FindActive(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (*Client, error)
}

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Registration) (identity.ClientID, string, error)
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[ClientView], error)
}
type Flows interface {
	Client(ctx context.Context, client identity.ClientID) (*Client, error)
	Start(ctx context.Context, client *Client, form string) (string, string, error)
	Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(Ticket, Authorization) error) error
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
}

type Authorization interface {
	Ticket(ctx context.Context, hash []byte) (Ticket, error)
	SessionTimes(ctx context.Context, session identity.SessionID) (time.Time, time.Time, error)
	Consume(ctx context.Context, hash []byte) error
	Commit() error
	Rollback() error
}
type Repository interface {
	ClientRepository
	Environment(ctx context.Context, client identity.ClientID) (identity.EnvironmentID, error)
	Create(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, input Registration, secretHash []byte) error
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[ClientView], error)
	SaveTicket(ctx context.Context, ticketHash, bindingHash []byte, client *Client, form string) error
	Begin(ctx context.Context) (Authorization, error)
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Passwords interface{ Hash(password string) (string, error) }
