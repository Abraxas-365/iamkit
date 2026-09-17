package sacctsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct {
	repository serviceaccount.Repository
	secrets    serviceaccount.Secrets
}

func New(r serviceaccount.Repository, s serviceaccount.Secrets) *Service { return &Service{r, s} }
func validID(id string) bool                                             { _, err := uuid.Parse(id); return err == nil }
func (s *Service) Create(ctx context.Context, environment string, input serviceaccount.Input) (serviceaccount.Credential, error) {
	var out serviceaccount.Credential
	if strings.TrimSpace(input.Name) == "" || !validID(input.Application) || !validID(input.Resource) || identity.ValidatePermissions(input.Permissions) != nil {
		return out, errx.Validation("invalid request")
	}
	catalog, err := s.repository.Catalog(ctx, environment, input.Resource)
	if err != nil {
		return out, err
	}
	if !identity.Subset(input.Permissions, catalog) {
		return out, errx.Validation("invalid request")
	}
	raw, hash, err := s.secrets.Generate("ik_svc_")
	if err != nil {
		return out, err
	}
	out = serviceaccount.Credential{ID: uuid.NewString(), Secret: raw, Expires: time.Now().Add(24 * time.Hour)}
	return out, s.repository.Create(ctx, environment, input, out, hash)
}
func (s *Service) Revoke(ctx context.Context, environment, id string) error {
	if !validID(id) {
		return errx.NotFound("resource not found")
	}
	return s.repository.Revoke(ctx, environment, id)
}
func (s *Service) List(ctx context.Context, environment string) ([]serviceaccount.Account, error) {
	return s.repository.List(ctx, environment)
}

var _ serviceaccount.Commands = (*Service)(nil)
var _ serviceaccount.Queries = (*Service)(nil)
