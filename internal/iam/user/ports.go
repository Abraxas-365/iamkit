package user

import "context"

type Commands interface {
	Create(context.Context, string, Create) (string, error)
	Update(context.Context, Mutation, string, Update) error
	Suspend(context.Context, string, string) error
}
type Queries interface {
	List(context.Context, string) ([]User, error)
	Find(context.Context, string, string) (User, error)
}

type Repository interface {
	Create(context.Context, string, Create, string) (string, error)
	List(context.Context, string) ([]User, error)
	Find(context.Context, string, string) (User, error)
	Update(context.Context, Mutation, string, Update) error
	Suspend(context.Context, string, string) error
}
type PasswordHasher interface{ Hash(string) (string, error) }
