package orgsvc

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository organization.Repository
	actions    organization.Actions
	quota      organization.Quota
}

// SetQuota enforces the environment's organizations limit on Create.
func (s *Service) SetQuota(q organization.Quota) { s.quota = q }

func New(repository organization.Repository) *Service { return &Service{repository: repository} }

// SetActions runs the environment's request:membership.create hooks.
func (s *Service) SetActions(actions organization.Actions) { s.actions = actions }
func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, name string) (identity.OrganizationID, error) {
	if strings.TrimSpace(name) == "" {
		return identity.OrganizationID{}, errx.Validation("organization name is required")
	}
	if s.quota != nil {
		if err := s.quota.Admit(ctx, environment, usage.LimitOrganizations); err != nil {
			return identity.OrganizationID{}, err
		}
	}
	id := identity.NewOrganizationID()
	return id, s.repository.Create(ctx, environment, id, name)
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter organization.Filter, page query.Pagination) (query.Paginated[organization.Summary], error) {
	return s.repository.List(ctx, environment, filter, page)
}
func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.OrganizationID) (organization.Organization, error) {
	if id.IsZero() {
		return organization.Organization{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation organization.Mutation, id identity.OrganizationID, input organization.Update) error {
	if id.IsZero() {
		return errx.Validation("invalid organization update")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) AddMember(ctx context.Context, environment identity.EnvironmentID, input organization.Membership) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if s.actions != nil {
		if _, err := s.actions.Run(ctx, environment, action.MembershipAdd, func() action.Input {
			body, _ := json.Marshal(input)
			return action.Input{Organization: &input.Organization, User: &action.UserInput{ID: &input.User}, Request: body}
		}); err != nil {
			return err
		}
	}
	return s.repository.AddMember(ctx, environment, input)
}
func (s *Service) RemoveMember(ctx context.Context, environment identity.EnvironmentID, org identity.OrganizationID, user identity.UserID) error {
	if org.IsZero() || user.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.RemoveMember(ctx, environment, org, user)
}
func (s *Service) UpdateMember(ctx context.Context, m organization.Mutation, org identity.OrganizationID, user identity.UserID, input organization.MemberUpdate) error {
	if org.IsZero() || user.IsZero() {
		return errx.NotFound("resource not found")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.UpdateMember(ctx, m, org, user, input)
}
func (s *Service) Members(ctx context.Context, environment identity.EnvironmentID, org identity.OrganizationID, filter organization.MemberFilter, page query.Pagination) (query.Paginated[organization.MemberView], error) {
	if org.IsZero() {
		return query.Paginated[organization.MemberView]{}, errx.NotFound("resource not found")
	}
	return s.repository.Members(ctx, environment, org, filter, page)
}

var _ organization.Commands = (*Service)(nil)
var _ organization.Queries = (*Service)(nil)

func (s *Service) Metadata(ctx context.Context, environment identity.EnvironmentID, id identity.OrganizationID, key string) (json.RawMessage, error) {
	if err := identity.MetadataKey(key); err != nil {
		return nil, err
	}
	org, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	value, ok := identity.MetadataValue(org.Metadata, key)
	if !ok {
		return nil, errx.NotFound("metadata key not found")
	}
	return value, nil
}

func (s *Service) SetMetadata(ctx context.Context, m organization.Mutation, id identity.OrganizationID, key string, value json.RawMessage) error {
	if err := identity.MetadataKey(key); err != nil {
		return err
	}
	m.Action = organization.ActionMetadataSet
	return s.repository.EditMetadata(ctx, m, id, func(current json.RawMessage) (json.RawMessage, error) {
		return identity.SetMetadata(current, key, value)
	})
}

func (s *Service) DeleteMetadata(ctx context.Context, m organization.Mutation, id identity.OrganizationID, key string) error {
	if err := identity.MetadataKey(key); err != nil {
		return err
	}
	m.Action = organization.ActionMetadataDeleted
	return s.repository.EditMetadata(ctx, m, id, func(current json.RawMessage) (json.RawMessage, error) {
		out, found, err := identity.DeleteMetadata(current, key)
		if err == nil && !found {
			err = errx.NotFound("metadata key not found")
		}
		return out, err
	})
}
