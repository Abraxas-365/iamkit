package user

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.UserID, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	Suspend(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID) ([]User, error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create, passwordHash string) (identity.UserID, error)
	List(ctx context.Context, environment identity.EnvironmentID) ([]User, error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	Suspend(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) error
}
type PasswordHasher interface{ Hash(password string) (string, error) }
