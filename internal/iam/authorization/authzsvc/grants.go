package authzsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Grants struct{ repository authorization.Grants }

func NewGrants(r authorization.Grants) *Grants { return &Grants{r} }
func (s *Grants) Roles(ctx context.Context, environment, id string) ([]authorization.RoleView, error) {
	if id != "" && !identity.ValidID(id) {
		return nil, errx.NotFound("resource not found")
	}
	out, err := s.repository.Roles(ctx, environment, id)
	if err != nil || (id != "" && len(out) == 0) {
		if err != nil {
			return nil, err
		}
		return nil, errx.NotFound("resource not found")
	}
	return out, nil
}
func (s *Grants) Grants(ctx context.Context, environment, id string) ([]authorization.GrantView, error) {
	if id != "" && !identity.ValidID(id) {
		return nil, errx.NotFound("resource not found")
	}
	out, err := s.repository.Grants(ctx, environment, id)
	if err != nil || (id != "" && len(out) == 0) {
		if err != nil {
			return nil, err
		}
		return nil, errx.NotFound("resource not found")
	}
	return out, nil
}
func (s *Grants) permissions(ctx context.Context, environment, resource string, permissions []string) error {
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
func (s *Grants) SaveRole(ctx context.Context, m authorization.Mutation, id string, input authorization.Role) (string, error) {
	if err := input.Validate(); err != nil {
		return "", err
	}
	if err := s.permissions(ctx, m.Environment, input.Resource, input.Permissions); err != nil {
		return "", err
	}
	creating := id == ""
	if creating {
		id = uuid.NewString()
	}
	if !identity.ValidID(id) {
		return "", errx.Validation("invalid role")
	}
	return id, s.repository.SaveRole(ctx, m, id, input, creating)
}
func (s *Grants) DeleteRole(ctx context.Context, m authorization.Mutation, id string) error {
	if !identity.ValidID(id) {
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
func (s *Grants) PutGrant(ctx context.Context, environment string, input authorization.Grant) (string, error) {
	if err := input.Validate(); err != nil {
		return "", err
	}
	if err := s.permissions(ctx, environment, input.Resource, input.Permissions); err != nil {
		return "", err
	}
	return s.repository.PutGrant(ctx, environment, uuid.NewString(), input)
}
func (s *Grants) DeleteGrant(ctx context.Context, environment, id string) error {
	if !identity.ValidID(id) {
		return errx.NotFound("resource not found")
	}
	return s.repository.DeleteGrant(ctx, environment, id)
}
func (s *Grants) RoleAssignments(ctx context.Context, environment string, filter authorization.RoleAssignmentFilter, page httpx.Pagination) ([]authorization.RoleAssignmentView, int, error) {
	return s.repository.RoleAssignments(ctx, environment, filter, page)
}
