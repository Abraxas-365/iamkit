package serviceaccount

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Input) (Credential, error)
	Revoke(ctx context.Context, environment identity.EnvironmentID, accountID identity.AccountID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID) ([]Account, error)
}

type Repository interface {
	Catalog(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]string, error)
	Create(ctx context.Context, environment identity.EnvironmentID, input Input, cred Credential, hash []byte) error
	Revoke(ctx context.Context, environment identity.EnvironmentID, accountID identity.AccountID) error
	List(ctx context.Context, environment identity.EnvironmentID) ([]Account, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
}
