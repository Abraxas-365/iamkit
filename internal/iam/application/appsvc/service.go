package appsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct{ repository application.Repository }

func New(r application.Repository) *Service { return &Service{r} }

func (s *Service) Create(ctx context.Context, environment string, input application.Create) (string, error) {
	if err := input.Validate(); err != nil {
		return "", err
	}
	if err := identity.ValidateRedirects(input.Redirects); err != nil {
		return "", err
	}
	id := uuid.NewString()
	return id, s.repository.Create(ctx, environment, id, input)
}

func (s *Service) Find(ctx context.Context, environment, id string) (application.Application, error) {
	if !identity.ValidID(id) {
		return application.Application{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}

func (s *Service) List(ctx context.Context, environment string) ([]application.Application, error) {
	return s.repository.List(ctx, environment)
}

func (s *Service) Update(ctx context.Context, m application.Mutation, id string, input application.Update) error {
	if !identity.ValidID(id) {
		return errx.Validation("invalid application update")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	if input.Redirects != nil {
		if err := identity.ValidateRedirects(*input.Redirects); err != nil {
			return err
		}
	}
	return s.repository.Update(ctx, m, id, input)
}

var _ application.Commands = (*Service)(nil)
var _ application.Queries = (*Service)(nil)
