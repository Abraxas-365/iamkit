package authzsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Grants struct{ repository authorization.GrantRepository }

func NewGrants(r authorization.GrantRepository) *Grants { return &Grants{r} }
func (s *Grants) ListRoles(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID, page query.Pagination) (query.Paginated[authorization.RoleView], error) {
	out, err := s.repository.ListRoles(ctx, environment, id, page)
	if err != nil || (!id.IsZero() && len(out.Items) == 0) {
		if err != nil {
			return query.Paginated[authorization.RoleView]{}, err
		}
		return query.Paginated[authorization.RoleView]{}, errx.NotFound("resource not found")
	}
	return out, nil
}
func (s *Grants) ListGrants(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID, page query.Pagination) (query.Paginated[authorization.GrantView], error) {
	out, err := s.repository.ListGrants(ctx, environment, id, page)
	if err != nil || (!id.IsZero() && len(out.Items) == 0) {
		if err != nil {
			return query.Paginated[authorization.GrantView]{}, err
		}
		return query.Paginated[authorization.GrantView]{}, errx.NotFound("resource not found")
	}
	return out, nil
}
func (s *Grants) permissions(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, permissions []string) error {
	if err := identity.ValidatePermissions(permissions, ""); err != nil {
		return err
	}
	catalog, err := s.repository.Catalog(ctx, environment, resource)
	if err != nil {
		return err
	}
	if !identity.Subset(permissions, catalog) {
		return errx.Validation("permissions outside resource catalog")
	}
	return nil
}
func (s *Grants) SaveRole(ctx context.Context, m authorization.Mutation, id identity.RoleID, input authorization.Role) (identity.RoleID, error) {
	if err := input.Validate(); err != nil {
		return identity.RoleID{}, err
	}
	if err := s.permissions(ctx, m.Environment, input.Resource, input.Permissions); err != nil {
		return identity.RoleID{}, err
	}
	creating := id.IsZero()
	if creating {
		id = identity.NewRoleID()
	}
	return id, s.repository.SaveRole(ctx, m, id, input, creating)
}
func (s *Grants) DeleteRole(ctx context.Context, m authorization.Mutation, id identity.RoleID) error {
	if id.IsZero() {
		return errx.NotFound("role not found")
	}
	return s.repository.DeleteRole(ctx, m, id)
}
func (s *Grants) AssignRole(ctx context.Context, m authorization.Mutation, input authorization.RoleAssignment, remove bool) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if remove {
		return s.repository.UnassignRole(ctx, m, input)
	}
	return s.repository.AssignRole(ctx, m, input)
}
func (s *Grants) PutGrant(ctx context.Context, environment identity.EnvironmentID, input authorization.Grant) (identity.GrantID, error) {
	if err := input.Validate(); err != nil {
		return identity.GrantID{}, err
	}
	if err := s.permissions(ctx, environment, input.Resource, input.Permissions); err != nil {
		return identity.GrantID{}, err
	}
	return s.repository.PutGrant(ctx, environment, identity.NewGrantID(), input)
}
func (s *Grants) DeleteGrant(ctx context.Context, environment identity.EnvironmentID, id identity.GrantID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.DeleteGrant(ctx, environment, id)
}
func (s *Grants) RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter authorization.RoleAssignmentFilter, page query.Pagination) (query.Paginated[authorization.RoleAssignmentView], error) {
	return s.repository.RoleAssignments(ctx, environment, filter, page)
}
