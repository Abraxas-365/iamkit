package provsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository provisioning.Repository
	secrets    provisioning.Secrets
}

func New(repository provisioning.Repository, secrets provisioning.Secrets) *Service {
	return &Service{repository, secrets}
}
func (s *Service) Authenticate(ctx context.Context, raw string) (provisioning.Principal, error) {
	if !strings.HasPrefix(raw, "ik_scim_") {
		return provisioning.Principal{}, errx.Unauthorized("invalid credential")
	}
	return s.repository.Authenticate(ctx, s.secrets.Hash(raw))
}
func (s *Service) Find(ctx context.Context, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	if id.IsZero() {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	return s.repository.Find(ctx, p, id)
}
func (s *Service) List(ctx context.Context, p provisioning.Principal, f provisioning.Filter) ([]provisioning.User, int, error) {
	if f.Start < 1 || f.Count < 0 || f.Count > 100 {
		return nil, 0, errx.Validation("invalid pagination")
	}
	if f.Field != "" && f.Field != "userName" && f.Field != "externalId" {
		return nil, 0, errx.Validation("unsupported filter")
	}
	return s.repository.List(ctx, p, f)
}
func (s *Service) Create(ctx context.Context, p provisioning.Principal, input provisioning.User) (provisioning.User, error) {
	email, err := identity.Email(input.Email)
	if err != nil {
		return input, err
	}
	input.Email = email
	if input.Name == "" {
		input.Name = email
	}
	if input.External == "" {
		input.External = email
	}
	input.ID = identity.NewUserID()
	return input, s.repository.Create(ctx, p, input)
}
func (s *Service) Update(ctx context.Context, p provisioning.Principal, id identity.UserID, input provisioning.Update) (provisioning.User, error) {
	if id.IsZero() {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	return s.repository.Update(ctx, p, id, input)
}
