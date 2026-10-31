package authzsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Descriptions implements authorization.DescriptionCommands and
// authorization.DescriptionQueries.
type Descriptions struct {
	repository authorization.DescriptionRepository
}

var (
	_ authorization.DescriptionCommands = (*Descriptions)(nil)
	_ authorization.DescriptionQueries  = (*Descriptions)(nil)
)

func NewDescriptions(repository authorization.DescriptionRepository) *Descriptions {
	return &Descriptions{repository}
}

func (s *Descriptions) SetDescriptions(ctx context.Context, m authorization.Mutation, id identity.ResourceID, descriptions []authorization.PermissionDescription) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	resource, err := s.repository.FindResource(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	clean, err := authorization.ValidateDescriptions(resource.Permissions, descriptions)
	if err != nil {
		return err
	}
	return s.repository.ReplaceDescriptions(ctx, m, id, clean)
}

func (s *Descriptions) Descriptions(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID) ([]authorization.PermissionDescription, error) {
	if id.IsZero() {
		return nil, errx.NotFound("resource not found")
	}
	if _, err := s.repository.FindResource(ctx, environment, id); err != nil {
		return nil, err
	}
	return s.repository.ListDescriptions(ctx, environment, id)
}

func (s *Descriptions) Describe(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID, permissions []string, locales ...string) ([]authorization.DescribedPermission, error) {
	stored, err := s.repository.ListDescriptions(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	return authorization.DescribeAll(stored, permissions, locales...), nil
}
