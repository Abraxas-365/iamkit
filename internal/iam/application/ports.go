package application

import "context"

// Commands are the application-management operations exposed to driving adapters
// and to other modules. They do not expose persistence.
type Commands interface {
	Create(ctx context.Context, environment string, input Create) (string, error)
	Update(ctx context.Context, m Mutation, applicationID string, input Update) error
}

// Queries are the application read operations exposed outside this module.
type Queries interface {
	Find(ctx context.Context, environment, applicationID string) (Application, error)
	List(ctx context.Context, environment string) ([]Application, error)
}

// Repository is an internal outbound port used only by application use cases.
type Repository interface {
	Create(ctx context.Context, environment, applicationID string, input Create) error
	Find(ctx context.Context, environment, applicationID string) (Application, error)
	List(ctx context.Context, environment string) ([]Application, error)
	Update(ctx context.Context, m Mutation, applicationID string, input Update) error
}
