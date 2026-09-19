package mgmtsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository management.Repository
	sessions   management.SessionRepository
	secrets    management.Secrets
	passwords  management.Passwords
}

func New(repository management.Repository, sessions management.SessionRepository, secrets management.Secrets, passwords management.Passwords) *Service {
	return &Service{repository: repository, sessions: sessions, secrets: secrets, passwords: passwords}
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
	if err = s.repository.Bootstrap(ctx, email, name, hash, time.Now().Add(config.APIKeyTTL)); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) RecoverOwner(ctx context.Context, workspace identity.WorkspaceID, email string) (string, error) {
	if workspace.IsZero() {
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
	if err = s.repository.RecoverOwner(ctx, workspace, email, hash, time.Now().Add(config.APIKeyTTL)); err != nil {
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
func (s *Service) AuthenticateSession(ctx context.Context, raw string) (management.Principal, error) {
	if raw == "" {
		return management.Principal{}, errx.Unauthorized("management credential required")
	}
	return s.sessions.AuthenticateSession(ctx, s.secrets.Hash(raw))
}
func (s *Service) EnvironmentAllowed(ctx context.Context, p management.Principal, environment identity.EnvironmentID) bool {
	allowed, err := s.repository.EnvironmentAllowed(ctx, p.WorkspaceID, environment)
	return err == nil && allowed
}
func (s *Service) Login(ctx context.Context, email, password string) (string, management.Principal, error) {
	email, err := identity.Email(email)
	if err != nil || len(password) > config.PasswordMaxLength {
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	p, hash, err := s.sessions.PasswordByEmail(ctx, email)
	if err != nil {
		s.passwords.Compare("", password)
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	if !s.passwords.Compare(hash, password) {
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	raw, secretHash, err := s.secrets.Generate("ik_sess_")
	if err != nil {
		return "", management.Principal{}, errx.Wrap(err, "session creation failed", errx.TypeInternal)
	}
	id := identity.NewSessionID()
	expires := time.Now().Add(config.OperatorSessionTTL)
	if err = s.sessions.CreateSession(ctx, id, p, secretHash, expires); err != nil {
		return "", management.Principal{}, err
	}
	return raw, p, nil
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return errx.Validation("invalid session")
	}
	return s.sessions.RevokeSessionByHash(ctx, s.secrets.Hash(raw))
}
func (s *Service) SetPassword(ctx context.Context, p management.Principal, password string) error {
	if len(password) < config.PasswordMinLength || len(password) > config.PasswordMaxLength {
		return errx.Validation("password must be 12-72 bytes")
	}
	hash, err := s.passwords.Hash(password)
	if err != nil {
		return err
	}
	if err = s.sessions.SetPassword(ctx, p.OperatorID, hash); err != nil {
		return err
	}
	return s.sessions.RevokeOperatorSessions(ctx, p.OperatorID)
}
