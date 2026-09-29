package user

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.UserID, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	Suspend(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) error
	Delete(ctx context.Context, m Mutation, user identity.UserID) error
	// Unlock clears the user's wrong-password count and lockout.
	Unlock(ctx context.Context, m Mutation, user identity.UserID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[User], error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create, passwordHash string) (identity.UserID, error)
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[User], error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	Suspend(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) error
	Delete(ctx context.Context, m Mutation, user identity.UserID) error
	Unlock(ctx context.Context, m Mutation, user identity.UserID) error
}
type PasswordHasher interface {
	Hash(password string) (string, error)
}

// PasswordPolicy checks a new password against the environment's policy
// (implemented by the authentication module).
type PasswordPolicy interface {
	CheckPassword(ctx context.Context, environment identity.EnvironmentID, password string) error
}
