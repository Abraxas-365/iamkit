package authzsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	resources authorization.ResourceRepository
}

func New(resources authorization.ResourceRepository) *Service { return &Service{resources} }
func (s *Service) CreateResource(ctx context.Context, environment identity.EnvironmentID, input authorization.Resource) (identity.ResourceID, error) {
	if err := input.Validate(); err != nil {
		return identity.ResourceID{}, err
	}
	input.Prefix = strings.TrimSpace(input.Prefix)
	if err := identity.ValidatePrefix(input.Prefix); err != nil {
		return identity.ResourceID{}, err
	}
	if err := identity.ValidatePermissions(input.Permissions, input.Prefix); err != nil {
		return identity.ResourceID{}, err
	}
	input.ID = identity.NewResourceID()
	return input.ID, s.resources.Create(ctx, environment, input)
}
func (s *Service) Resources(ctx context.Context, environment identity.EnvironmentID) ([]authorization.Resource, error) {
	return s.resources.List(ctx, environment)
}
func (s *Service) Resource(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID) (authorization.Resource, error) {
	if id.IsZero() {
		return authorization.Resource{}, errx.NotFound("resource not found")
	}
	return s.resources.Find(ctx, environment, id)
}
func (s *Service) UpdateCatalog(ctx context.Context, m authorization.Mutation, id identity.ResourceID, input authorization.Catalog) error {
	if id.IsZero() {
		return errx.Validation("resource ID must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	existing, err := s.resources.Find(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	if err := identity.ValidatePermissions(input.Permissions, existing.Prefix); err != nil {
		return err
	}
	return s.resources.UpdateCatalog(ctx, m, id, input)
}
func (s *Service) LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	if application.IsZero() || resource.IsZero() {
		return errx.Validation("invalid request")
	}
	return s.resources.LinkApplication(ctx, environment, application, resource)
}
func (s *Service) UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	if application.IsZero() || resource.IsZero() {
		return errx.Validation("invalid request")
	}
	return s.resources.UnlinkApplication(ctx, environment, application, resource)
}
func (s *Service) ResourcesByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) ([]authorization.Resource, error) {
	if application.IsZero() {
		return nil, errx.Validation("application_id must be a valid UUID")
	}
	return s.resources.ListByApplication(ctx, environment, application)
}
