package application

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.ApplicationID, error)
	Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
}

type Queries interface {
	Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
	List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, input Create) error
	Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
	List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
	Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
}
