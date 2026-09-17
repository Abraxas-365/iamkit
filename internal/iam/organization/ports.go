package organization

import "context"

type Commands interface {
	Create(context.Context, string, string) (string, error)
	Update(context.Context, Mutation, string, Update) error
	AddMember(context.Context, string, Membership) error
	RemoveMember(context.Context, string, string, string) error
}
type Queries interface {
	List(context.Context, string) ([]Summary, error)
	Find(context.Context, string, string) (Organization, error)
}

// Repository scopes every operation to an environment; mutations include atomic audit writes.
type Repository interface {
	Create(context.Context, string, string, string) error
	List(context.Context, string) ([]Summary, error)
	Find(context.Context, string, string) (Organization, error)
	Update(context.Context, Mutation, string, Update) error
	AddMember(context.Context, string, Membership) error
	RemoveMember(context.Context, string, string, string) error
}
