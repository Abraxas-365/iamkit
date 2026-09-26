package orgsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Groups manages organization groups for operators.
type Groups struct{ repository organization.GroupRepository }

func NewGroups(r organization.GroupRepository) *Groups { return &Groups{r} }

var _ organization.GroupCommands = (*Groups)(nil)
var _ organization.GroupQueries = (*Groups)(nil)

func (s *Groups) CreateGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, input organization.GroupInput) (identity.GroupID, error) {
	if err := input.Validate(); err != nil {
		return identity.GroupID{}, err
	}
	id := identity.NewGroupID()
	return id, s.repository.CreateGroup(ctx, b, m, id, input)
}

// operatorGroup loads a group and rejects directory-owned ones, whose name and
// members are controlled by their SCIM connection.
func (s *Groups) operatorGroup(ctx context.Context, b organization.Boundary, id identity.GroupID) error {
	g, err := s.FindGroup(ctx, b, id)
	if err != nil {
		return err
	}
	if g.Managed() {
		return errx.Business("group is managed by a provisioning directory")
	}
	return nil
}

func (s *Groups) UpdateGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID, input organization.GroupUpdate) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := s.operatorGroup(ctx, b, id); err != nil {
		return err
	}
	return s.repository.UpdateGroup(ctx, b, m, id, input)
}

func (s *Groups) DeleteGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID) error {
	if err := s.operatorGroup(ctx, b, id); err != nil {
		return err
	}
	return s.repository.DeleteGroup(ctx, b, m, id)
}

func (s *Groups) ChangeGroupMembers(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID, input organization.GroupMembers) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := s.operatorGroup(ctx, b, id); err != nil {
		return err
	}
	return s.repository.ChangeGroupMembers(ctx, b, m, id, input)
}

func (s *Groups) ListGroups(ctx context.Context, b organization.Boundary, filter organization.GroupFilter, page query.Pagination) (query.Paginated[organization.Group], error) {
	return s.repository.ListGroups(ctx, b, filter, page)
}

func (s *Groups) FindGroup(ctx context.Context, b organization.Boundary, id identity.GroupID) (organization.Group, error) {
	if id.IsZero() {
		return organization.Group{}, errx.NotFound("group not found")
	}
	return s.repository.FindGroup(ctx, b, id)
}

func (s *Groups) ListGroupMembers(ctx context.Context, b organization.Boundary, id identity.GroupID, page query.Pagination) (query.Paginated[organization.GroupMemberView], error) {
	if _, err := s.FindGroup(ctx, b, id); err != nil {
		return query.Paginated[organization.GroupMemberView]{}, err
	}
	return s.repository.ListGroupMembers(ctx, b, id, page)
}
