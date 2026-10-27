package oauthsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// ProtectedResources manages protected resources (OAuth resource servers
// such as remote MCP servers) and their environment's TTL policy.
type ProtectedResources struct {
	repository oauth.ProtectedResourceRepository
}

var (
	_ oauth.ProtectedResourceCommands = (*ProtectedResources)(nil)
	_ oauth.ProtectedResourceQueries  = (*ProtectedResources)(nil)
)

func NewProtectedResources(r oauth.ProtectedResourceRepository) *ProtectedResources {
	return &ProtectedResources{repository: r}
}

// CreateProtectedResource registers a resource of an application: its
// audience must be canonical (the URI), its default scopes among its
// permissions and its TTLs within the environment's policy.
func (s *ProtectedResources) CreateProtectedResource(ctx context.Context, m oauth.Mutation, input oauth.ProtectedResourceCreate) (identity.ProtectedResourceID, error) {
	input = input.WithDefaults()
	if err := input.Validate(); err != nil {
		return identity.ProtectedResourceID{}, err
	}
	source, err := s.repository.ProtectedResourceSource(ctx, m.Environment, input.Application, input.Resource)
	if err != nil {
		return identity.ProtectedResourceID{}, err
	}
	uri, err := source.CheckSource()
	if err != nil {
		return identity.ProtectedResourceID{}, err
	}
	if err = source.CheckScopes(input.DefaultScopes); err != nil {
		return identity.ProtectedResourceID{}, err
	}
	policy, err := s.ProtectedResourcePolicy(ctx, m.Environment)
	if err != nil {
		return identity.ProtectedResourceID{}, err
	}
	if err = policy.Admits(input.IdleTTLSeconds, input.MaxTTLSeconds); err != nil {
		return identity.ProtectedResourceID{}, err
	}
	id := identity.NewProtectedResourceID()
	m.Action, m.Target = oauth.ActionProtectedResourceCreate, id.String()
	return id, s.repository.CreateProtectedResource(ctx, m, id, uri, input)
}

func (s *ProtectedResources) UpdateProtectedResource(ctx context.Context, m oauth.Mutation, id identity.ProtectedResourceID, input oauth.ProtectedResourceUpdate) error {
	if err := input.Validate(); err != nil {
		return err
	}
	current, err := s.repository.FindProtectedResource(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	next := input.Apply(current)
	if err = next.Validate(); err != nil {
		return err
	}
	if input.DefaultScopes != nil {
		source, err := s.repository.ProtectedResourceSource(ctx, m.Environment, current.Application, current.Resource)
		if err != nil {
			return err
		}
		if err = source.CheckScopes(next.DefaultScopes); err != nil {
			return err
		}
	}
	if input.IdleTTLSeconds != nil || input.MaxTTLSeconds != nil {
		policy, err := s.ProtectedResourcePolicy(ctx, m.Environment)
		if err != nil {
			return err
		}
		if err = policy.Admits(next.IdleTTLSeconds, next.MaxTTLSeconds); err != nil {
			return err
		}
	}
	m.Action, m.Target = oauth.ActionProtectedResourceUpdate, id.String()
	return s.repository.SaveProtectedResource(ctx, m, next)
}

func (s *ProtectedResources) DeleteProtectedResource(ctx context.Context, m oauth.Mutation, id identity.ProtectedResourceID) error {
	if id.IsZero() {
		return errx.NotFound("protected resource not found")
	}
	m.Action, m.Target = oauth.ActionProtectedResourceDelete, id.String()
	return s.repository.DeleteProtectedResource(ctx, m, id)
}

func (s *ProtectedResources) SetProtectedResourcePolicy(ctx context.Context, m oauth.Mutation, policy oauth.ProtectedResourcePolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	m.Action, m.Target = oauth.ActionProtectedResourcePolicy, m.Environment.String()
	return s.repository.SetProtectedResourcePolicy(ctx, m, policy)
}

func (s *ProtectedResources) ListProtectedResources(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[oauth.ProtectedResource], error) {
	return s.repository.ListProtectedResources(ctx, environment, page)
}

func (s *ProtectedResources) FindProtectedResource(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (oauth.ProtectedResource, error) {
	return s.repository.FindProtectedResource(ctx, environment, id)
}

func (s *ProtectedResources) ProtectedResourceImpact(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (oauth.ProtectedResourceImpact, error) {
	if id.IsZero() {
		return oauth.ProtectedResourceImpact{}, errx.NotFound("protected resource not found")
	}
	return s.repository.ProtectedResourceImpact(ctx, environment, id)
}

func (s *ProtectedResources) ProtectedResourcePolicy(ctx context.Context, environment identity.EnvironmentID) (oauth.ProtectedResourcePolicy, error) {
	saved, err := s.repository.ProtectedResourcePolicy(ctx, environment)
	if err != nil || saved == nil {
		return oauth.DefaultProtectedResourcePolicy(), err
	}
	return *saved, nil
}
