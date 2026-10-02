package feature

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Commands override environment-scoped flags; every change is audited.
type Commands interface {
	// Set overrides the flag for the environment.
	Set(ctx context.Context, m Mutation, name string, input Set) (Feature, error)
	// Reset removes the environment's override (the deployment value or
	// default applies again).
	Reset(ctx context.Context, m Mutation, name string) (Feature, error)
}

// Queries read flags. Enabled is the port features consult to gate their
// behavior.
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID) ([]Feature, error)
	Find(ctx context.Context, environment identity.EnvironmentID, name string) (Feature, error)
	Enabled(ctx context.Context, environment identity.EnvironmentID, name string) (bool, error)
}

// Repository stores environment overrides.
type Repository interface {
	Overrides(ctx context.Context, environment identity.EnvironmentID) ([]Override, error)
	Override(ctx context.Context, environment identity.EnvironmentID, name string) (*Override, error)
	Save(ctx context.Context, m Mutation, name string, enabled bool) error
	// Delete removes an override; it audits only when one existed.
	Delete(ctx context.Context, m Mutation, name string) error
}
