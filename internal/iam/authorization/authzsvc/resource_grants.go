package authzsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// ResourceGrants implements authorization.ResourceGrantCommands and
// authorization.ResourceGrantQueries.
type ResourceGrants struct {
	repository authorization.ResourceGrantRepository
}

var _ authorization.ResourceGrantCommands = (*ResourceGrants)(nil)
var _ authorization.ResourceGrantQueries = (*ResourceGrants)(nil)

func NewResourceGrants(repository authorization.ResourceGrantRepository) *ResourceGrants {
	return &ResourceGrants{repository}
}

// iamResource refuses the environment's IAM resource: organization
// administration (built-in roles, iam:org:*) governs it.
func iamResource(r authorization.Resource) error {
	if r.Prefix == "iam" {
		return errx.Business("the IAM resource cannot be owned or granted")
	}
	return nil
}

func (s *ResourceGrants) SetResourceAccess(ctx context.Context, m authorization.Mutation, id identity.ResourceID, input authorization.ResourceAccess) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	resource, err := s.repository.FindResource(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	if err := iamResource(resource); err != nil {
		return err
	}
	return s.repository.SetResourceAccess(ctx, m, id, input)
}

func (s *ResourceGrants) PutResourceGrant(ctx context.Context, m authorization.Mutation, input authorization.ResourceGrantInput) (authorization.ResourceGrant, error) {
	if err := input.Validate(); err != nil {
		return authorization.ResourceGrant{}, err
	}
	resource, err := s.repository.FindResource(ctx, m.Environment, input.Resource)
	if err != nil {
		return authorization.ResourceGrant{}, err
	}
	if err := iamResource(resource); err != nil {
		return authorization.ResourceGrant{}, err
	}
	if resource.OwnerOrganization != nil && *resource.OwnerOrganization == input.Organization {
		return authorization.ResourceGrant{}, errx.Business("the owner organization needs no grant")
	}
	if len(input.Roles) > 0 {
		n, err := s.repository.CountRoles(ctx, m.Environment, input.Resource, input.Roles)
		if err != nil {
			return authorization.ResourceGrant{}, err
		}
		if n != len(input.Roles) {
			return authorization.ResourceGrant{}, errx.Validation("role_ids must be roles of the resource")
		}
	}
	id, err := s.repository.PutResourceGrant(ctx, m, identity.NewResourceGrantID(), input)
	if err != nil {
		return authorization.ResourceGrant{}, err
	}
	return s.repository.FindResourceGrant(ctx, m.Environment, id)
}

func (s *ResourceGrants) DeleteResourceGrant(ctx context.Context, m authorization.Mutation, id identity.ResourceGrantID) error {
	if id.IsZero() {
		return errx.NotFound("resource grant not found")
	}
	return s.repository.DeleteResourceGrant(ctx, m, id)
}

func (s *ResourceGrants) ListResourceGrants(ctx context.Context, environment identity.EnvironmentID, filter authorization.ResourceGrantFilter, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error) {
	return s.repository.ListResourceGrants(ctx, environment, filter, page)
}

func (s *ResourceGrants) FindResourceGrant(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceGrantID) (authorization.ResourceGrant, error) {
	if id.IsZero() {
		return authorization.ResourceGrant{}, errx.NotFound("resource grant not found")
	}
	return s.repository.FindResourceGrant(ctx, environment, id)
}
