package oauth

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"time"
)

type Commands interface {
	Create(context.Context, string, Registration) (string, string, error)
	Disable(context.Context, Mutation, string) error
}
type Flows interface {
	Client(context.Context, string) (*Client, error)
	Start(context.Context, *Client, string) (string, string, error)
	Complete(context.Context, string, string, bool, func(Ticket, Authorization) error) error
	Access(context.Context, *Client, string, string, string) (authentication.Access, error)
}

type Registration struct {
	Application string   `json:"application_id"`
	Resource    string   `json:"resource_id"`
	Redirects   []string `json:"redirect_uris"`
	Public      bool     `json:"public"`
}
type Mutation struct{ Environment, Actor, Action, Target string }
type Ticket struct {
	Client    string    `db:"client_id"`
	Binding   []byte    `db:"binding_hash"`
	Form      string    `db:"request_form"`
	Requested time.Time `db:"requested_at"`
}
type Authorization interface {
	Ticket(context.Context, []byte) (Ticket, error)
	SessionTimes(context.Context, string) (time.Time, time.Time, error)
	Consume(context.Context, []byte) error
	Commit() error
	Rollback() error
}
type Repository interface {
	ClientRepository
	Environment(context.Context, string) (string, error)
	Create(context.Context, string, string, Registration, []byte) error
	Disable(context.Context, Mutation, string) error
	SaveTicket(context.Context, []byte, []byte, *Client, string) error
	Begin(context.Context) (Authorization, error)
	Access(context.Context, *Client, string, string, string) (authentication.Access, error)
}
type Secrets interface {
	Generate(string) (string, []byte, error)
	Hash(string) []byte
}
type Passwords interface{ Hash(string) (string, error) }
