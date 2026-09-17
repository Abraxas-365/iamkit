package application

import "context"

// Commands are the application-management operations exposed to driving adapters
// and to other modules. They do not expose persistence.
type Commands interface {
	Create(context.Context, string, Create) (string, error)
	Update(context.Context, Mutation, string, Update) error
}

// Queries are the application read operations exposed outside this module.
type Queries interface {
	Find(context.Context, string, string) (Application, error)
	List(context.Context, string) ([]Application, error)
}

// Repository is an internal outbound port used only by application use cases.
type Repository interface {
	Create(context.Context, string, string, Create) error
	Find(context.Context, string, string) (Application, error)
	List(context.Context, string) ([]Application, error)
	Update(context.Context, Mutation, string, Update) error
}
