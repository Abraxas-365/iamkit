package sacctsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository serviceaccount.Repository
	secrets    serviceaccount.Secrets
}

func New(r serviceaccount.Repository, s serviceaccount.Secrets) *Service { return &Service{r, s} }
func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input serviceaccount.Input) (serviceaccount.Credential, error) {
	var out serviceaccount.Credential
	if err := input.Validate(); err != nil {
		return out, err
	}
	ttl, err := identity.ParseTTL(input.ExpiresIn)
	if err != nil {
		return out, err
	}
	catalog, err := s.repository.Catalog(ctx, environment, input.Resource)
	if err != nil {
		return out, err
	}
	if !identity.Subset(input.Permissions, catalog) {
		return out, errx.Validation("permissions outside resource catalog")
	}
	raw, hash, err := s.secrets.Generate("ik_svc_")
	if err != nil {
		return out, err
	}
	out = serviceaccount.Credential{ID: identity.NewAccountID(), Secret: raw, Expires: time.Now().Add(ttl)}
	return out, s.repository.Create(ctx, environment, input, out, hash)
}
func (s *Service) Revoke(ctx context.Context, environment identity.EnvironmentID, id identity.AccountID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.Revoke(ctx, environment, id)
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[serviceaccount.Account], error) {
	return s.repository.List(ctx, environment, page)
}

var _ serviceaccount.Commands = (*Service)(nil)
var _ serviceaccount.Queries = (*Service)(nil)
