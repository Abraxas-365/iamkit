package serviceaccount

import "context"

type Commands interface {
	Create(ctx context.Context, environment string, input Input) (Credential, error)
	Revoke(ctx context.Context, environment, accountID string) error
}
type Queries interface {
	List(ctx context.Context, environment string) ([]Account, error)
}

type Repository interface {
	Catalog(ctx context.Context, environment, resourceID string) ([]string, error)
	Create(ctx context.Context, environment string, input Input, cred Credential, hash []byte) error
	Revoke(ctx context.Context, environment, accountID string) error
	List(ctx context.Context, environment string) ([]Account, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
}
