package authzsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct {
	resources authorization.ResourceRepository
}

func New(resources authorization.ResourceRepository) *Service { return &Service{resources} }
func validID(id string) bool                                  { _, err := uuid.Parse(id); return err == nil }
func (s *Service) CreateResource(ctx context.Context, environment string, input authorization.Resource) (string, error) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Audience) == "" {
		return "", errx.Validation("invalid request")
	}
	if err := identity.ValidatePermissions(input.Permissions); err != nil {
		return "", err
	}
	input.ID = uuid.NewString()
	return input.ID, s.resources.Create(ctx, environment, input)
}
func (s *Service) Resources(ctx context.Context, environment string) ([]authorization.Resource, error) {
	return s.resources.List(ctx, environment)
}
func (s *Service) Resource(ctx context.Context, environment, id string) (authorization.Resource, error) {
	if !validID(id) {
		return authorization.Resource{}, errx.NotFound("resource not found")
	}
	return s.resources.Find(ctx, environment, id)
}
func (s *Service) UpdateCatalog(ctx context.Context, m authorization.Mutation, id string, input authorization.Catalog) error {
	if !validID(id) || strings.TrimSpace(input.Name) == "" {
		return errx.Validation("resource ID and name required")
	}
	if err := identity.ValidatePermissions(input.Permissions); err != nil {
		return err
	}
	return s.resources.UpdateCatalog(ctx, m, id, input)
}
func (s *Service) LinkApplication(ctx context.Context, environment, application, resource string) error {
	if !validID(application) || !validID(resource) {
		return errx.Validation("invalid request")
	}
	return s.resources.LinkApplication(ctx, environment, application, resource)
}
