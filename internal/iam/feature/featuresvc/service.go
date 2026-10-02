// Package featuresvc resolves feature flags and stores environment
// overrides.
package featuresvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository feature.Repository
	deployment feature.Deployment
	cache      cache.Store
}

// SetCache keeps environments' overrides in store (nil: read the database
// every time).
func (s *Service) SetCache(store cache.Store) { s.cache = store }

func cacheKey(environment identity.EnvironmentID) string { return "feature:" + environment.String() }

// override is the environment's override of name, through the cache.
func (s *Service) override(ctx context.Context, environment identity.EnvironmentID, name string) (*feature.Override, error) {
	if s.cache == nil {
		return s.repository.Override(ctx, environment, name)
	}
	stored, err := cache.Read(ctx, s.cache, cacheKey(environment), config.CacheTTL, func() ([]feature.Override, error) {
		return s.repository.Overrides(ctx, environment)
	})
	if err != nil {
		return nil, err
	}
	for i := range stored {
		if stored[i].Name == name {
			return &stored[i], nil
		}
	}
	return nil, nil
}

var (
	_ feature.Commands = (*Service)(nil)
	_ feature.Queries  = (*Service)(nil)
)

// New reads overrides from repository over the deployment values.
func New(repository feature.Repository, deployment feature.Deployment) *Service {
	return &Service{repository: repository, deployment: deployment}
}

func (s *Service) List(ctx context.Context, environment identity.EnvironmentID) ([]feature.Feature, error) {
	if environment.IsZero() {
		return nil, errx.Validation("environment_id is required")
	}
	stored, err := s.repository.Overrides(ctx, environment)
	if err != nil {
		return nil, err
	}
	byName := map[string]*feature.Override{}
	for i := range stored {
		byName[stored[i].Name] = &stored[i]
	}
	out := make([]feature.Feature, 0, len(config.Flags))
	for _, flag := range config.Flags {
		out = append(out, feature.Resolve(flag, s.deployment, byName[flag.Name]))
	}
	return out, nil
}

func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, name string) (feature.Feature, error) {
	flag, err := feature.Flag(name)
	if err != nil {
		return feature.Feature{}, err
	}
	if environment.IsZero() {
		return feature.Feature{}, errx.Validation("environment_id is required")
	}
	var override *feature.Override
	if flag.Scope == config.FeatureEnvironment {
		if override, err = s.override(ctx, environment, name); err != nil {
			return feature.Feature{}, err
		}
	}
	return feature.Resolve(flag, s.deployment, override), nil
}

// Enabled is the flag's effective value; deployment-scoped flags never
// read the database.
func (s *Service) Enabled(ctx context.Context, environment identity.EnvironmentID, name string) (bool, error) {
	out, err := s.Find(ctx, environment, name)
	return out.Enabled, err
}

func (s *Service) Set(ctx context.Context, m feature.Mutation, name string, input feature.Set) (feature.Feature, error) {
	flag, err := feature.Flag(name)
	if err != nil {
		return feature.Feature{}, err
	}
	if err = feature.Settable(flag); err != nil {
		return feature.Feature{}, err
	}
	if err = input.Validate(); err != nil {
		return feature.Feature{}, err
	}
	if err = s.repository.Save(ctx, m, name, *input.Enabled); err != nil {
		return feature.Feature{}, err
	}
	cache.Forget(ctx, s.cache, cacheKey(m.Environment))
	return s.Find(ctx, m.Environment, name)
}

func (s *Service) Reset(ctx context.Context, m feature.Mutation, name string) (feature.Feature, error) {
	flag, err := feature.Flag(name)
	if err != nil {
		return feature.Feature{}, err
	}
	if err = feature.Settable(flag); err != nil {
		return feature.Feature{}, err
	}
	if err = s.repository.Delete(ctx, m, name); err != nil {
		return feature.Feature{}, err
	}
	cache.Forget(ctx, s.cache, cacheKey(m.Environment))
	return s.Find(ctx, m.Environment, name)
}
