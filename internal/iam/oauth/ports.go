package oauth

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// ClientRepository loads only clients whose registration and application are active.
// Environment is explicit on every lookup; IDs alone never establish authority.
type ClientRepository interface {
	FindActive(ctx context.Context, environment, clientID string) (*Client, error)
}

type Commands interface {
	Create(ctx context.Context, environment string, input Registration) (string, string, error)
	Disable(ctx context.Context, m Mutation, clientID string) error
}
type Queries interface {
	List(ctx context.Context, environment string) ([]ClientView, error)
}
type Flows interface {
	Client(ctx context.Context, clientID string) (*Client, error)
	Start(ctx context.Context, client *Client, form string) (string, string, error)
	Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(Ticket, Authorization) error) error
	Access(ctx context.Context, client *Client, subject, sessionID, organizationID string) (authentication.Access, error)
}

type Authorization interface {
	Ticket(ctx context.Context, hash []byte) (Ticket, error)
	SessionTimes(ctx context.Context, sessionID string) (time.Time, time.Time, error)
	Consume(ctx context.Context, hash []byte) error
	Commit() error
	Rollback() error
}
type Repository interface {
	ClientRepository
	Environment(ctx context.Context, clientID string) (string, error)
	Create(ctx context.Context, environment, clientID string, input Registration, secretHash []byte) error
	Disable(ctx context.Context, m Mutation, clientID string) error
	List(ctx context.Context, environment string) ([]ClientView, error)
	SaveTicket(ctx context.Context, ticketHash, bindingHash []byte, client *Client, form string) error
	Begin(ctx context.Context) (Authorization, error)
	Access(ctx context.Context, client *Client, subject, sessionID, organizationID string) (authentication.Access, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Passwords interface{ Hash(password string) (string, error) }
