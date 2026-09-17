package federation

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

type Connection struct{ ID, Environment, Name, Issuer, Client, SecretEnv string }
type State struct {
	Connection      string
	Boundary        authentication.Context
	Binding         []byte
	Nonce, Verifier string
}
type Start struct{ URL, Binding string }
type Mutation struct{ Environment, Actor, Action, Target string }
type Commands interface {
	Create(context.Context, Connection) (string, error)
	Link(context.Context, Mutation, string, string, string) error
	Disable(context.Context, Mutation, string) error
}
type Flows interface {
	Start(context.Context, authentication.Context, string) (Start, error)
	Callback(context.Context, string, string, string) (authentication.Issued, error)
}

type Repository interface {
	Create(context.Context, Connection) error
	Find(context.Context, string, string) (Connection, error)
	SaveState(context.Context, []byte, State) error
	ConsumeState(context.Context, []byte, []byte) (State, error)
	LinkedUser(context.Context, string, string, string) (authentication.Transaction, string, error)
	Link(context.Context, Mutation, string, string, string) error
	Disable(context.Context, Mutation, string) error
}
type Provider interface {
	Approved(Connection) bool
	Authorize(context.Context, Connection, string, string, string) (string, error)
	Verify(context.Context, Connection, string, string, string) (string, error)
	Verifier() string
}
type Secrets interface {
	Generate(string) (string, []byte, error)
	Hash(string) []byte
}
type Sessions interface {
	NewSession(context.Context, authentication.Transaction, authentication.Context, string) (authentication.Issued, error)
}
