package serviceaccount

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Input) (Credential, error)
	Revoke(ctx context.Context, environment identity.EnvironmentID, account identity.AccountID) error
	// SetAuthentication replaces how the account authenticates at the
	// token endpoint (audited service_account.authentication).
	SetAuthentication(ctx context.Context, m Mutation, account identity.AccountID, input identity.ClientAuth) error
	// SetImpersonation allows or forbids the account to exchange a user id
	// for that user's token (RFC 8693); only workspace owners may change it
	// (audited service_account.impersonation).
	SetImpersonation(ctx context.Context, m Mutation, owner bool, account identity.AccountID, allowed bool) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Account], error)
	Find(ctx context.Context, environment identity.EnvironmentID, account identity.AccountID) (Account, error)
}

type Repository interface {
	Catalog(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]string, error)
	Create(ctx context.Context, environment identity.EnvironmentID, input Input, cred Credential, hash []byte) error
	Revoke(ctx context.Context, environment identity.EnvironmentID, account identity.AccountID) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Account], error)
	Find(ctx context.Context, environment identity.EnvironmentID, account identity.AccountID) (Account, error)
	SetAuthentication(ctx context.Context, m Mutation, account identity.AccountID, auth identity.ClientAuth) error
	SetImpersonation(ctx context.Context, m Mutation, account identity.AccountID, allowed bool) error
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
}
