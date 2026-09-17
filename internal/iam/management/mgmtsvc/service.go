package mgmtsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct {
	repository management.Repository
	secrets    management.Secrets
}

func New(repository management.Repository, secrets management.Secrets) *Service {
	return &Service{repository: repository, secrets: secrets}
}
func (s *Service) Bootstrap(ctx context.Context, email, name string) (string, error) {
	email, err := identity.Email(email)
	if err != nil {
		return "", errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	if name == "" {
		return "", errx.Validation("workspace name required")
	}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return "", errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	if err = s.repository.Bootstrap(ctx, email, name, hash, time.Now().Add(24*time.Hour)); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) RecoverOwner(ctx context.Context, workspace, email string) (string, error) {
	if _, err := uuid.Parse(workspace); err != nil {
		return "", errx.Validation("workspace UUID required")
	}
	email, err := identity.Email(email)
	if err != nil {
		return "", errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return "", errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if err = s.repository.RecoverOwner(ctx, workspace, email, hash, time.Now().Add(24*time.Hour)); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) Authenticate(ctx context.Context, raw string) (management.Principal, error) {
	if len(raw) < 9 || !strings.HasPrefix(raw, "ik_mgmt_") {
		return management.Principal{}, errx.Unauthorized("management credential required")
	}
	return s.repository.Authenticate(ctx, s.secrets.Hash(raw))
}
func (s *Service) EnvironmentAllowed(ctx context.Context, p management.Principal, environment string) bool {
	allowed, err := s.repository.EnvironmentAllowed(ctx, p.WorkspaceID, environment)
	return err == nil && allowed
}
