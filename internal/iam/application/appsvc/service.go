package appsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct{ repository application.Repository }

func New(r application.Repository) *Service { return &Service{r} }

func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input application.Create) (identity.ApplicationID, error) {
	if err := input.Validate(); err != nil {
		return identity.ApplicationID{}, err
	}
	if err := identity.ValidateRedirects(input.Redirects); err != nil {
		return identity.ApplicationID{}, err
	}
	id := identity.NewApplicationID()
	return id, s.repository.Create(ctx, environment, id, input)
}

func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ApplicationID) (application.Application, error) {
	if id.IsZero() {
		return application.Application{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}

func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[application.Application], error) {
	return s.repository.List(ctx, environment, page)
}

func (s *Service) Update(ctx context.Context, m application.Mutation, id identity.ApplicationID, input application.Update) error {
	if id.IsZero() {
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
