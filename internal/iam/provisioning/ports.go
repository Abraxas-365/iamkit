package provisioning

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, p Principal, input User) (User, error)
	Update(ctx context.Context, p Principal, user identity.UserID, input Update) (User, error)
	Authenticate(ctx context.Context, raw string) (Principal, error)
}
type Queries interface {
	Find(ctx context.Context, p Principal, user identity.UserID) (User, error)
	List(ctx context.Context, p Principal, f Filter) ([]User, int, error)
}

type Repository interface {
	Authenticate(ctx context.Context, hash []byte) (Principal, error)
	Find(ctx context.Context, p Principal, user identity.UserID) (User, error)
	List(ctx context.Context, p Principal, f Filter) ([]User, int, error)
	Create(ctx context.Context, p Principal, input User) error
	Update(ctx context.Context, p Principal, user identity.UserID, input Update) (User, error)
}
type Secrets interface{ Hash(raw string) []byte }

type ControlCommands interface {
	Issue(ctx context.Context, environment identity.EnvironmentID, input CredentialInput) (Credential, error)
	Revoke(ctx context.Context, m Mutation, credential identity.CredentialID) error
	Link(ctx context.Context, m Mutation, input Link) error
}
type ControlQueries interface {
	Credentials(ctx context.Context, environment identity.EnvironmentID) ([]CredentialView, error)
}

type ControlRepository interface {
	IssueCredential(ctx context.Context, environment identity.EnvironmentID, input CredentialInput, cred Credential, hash []byte, create bool) error
	RevokeCredential(ctx context.Context, m Mutation, credential identity.CredentialID) error
	Link(ctx context.Context, m Mutation, input Link) error
	Credentials(ctx context.Context, environment identity.EnvironmentID) ([]CredentialView, error)
}
type Generator interface {
	Generate(prefix string) (string, []byte, error)
}
