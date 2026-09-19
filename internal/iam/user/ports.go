package user

import "context"

type Commands interface {
	Create(ctx context.Context, environment string, input Create) (string, error)
	Update(ctx context.Context, m Mutation, userID string, input Update) error
	Suspend(ctx context.Context, environment, userID string) error
}
type Queries interface {
	List(ctx context.Context, environment string) ([]User, error)
	Find(ctx context.Context, environment, userID string) (User, error)
}

type Repository interface {
	Create(ctx context.Context, environment string, input Create, passwordHash string) (string, error)
	List(ctx context.Context, environment string) ([]User, error)
	Find(ctx context.Context, environment, userID string) (User, error)
	Update(ctx context.Context, m Mutation, userID string, input Update) error
	Suspend(ctx context.Context, environment, userID string) error
}
type PasswordHasher interface{ Hash(password string) (string, error) }
