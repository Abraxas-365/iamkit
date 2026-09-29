package usersvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository user.Repository
	passwords  user.PasswordHasher
	policy     user.PasswordPolicy // nil checks only the length
}

func New(repository user.Repository, passwords user.PasswordHasher) *Service {
	return &Service{repository: repository, passwords: passwords}
}

// SetPasswordPolicy makes new passwords follow the environment's policy.
func (s *Service) SetPasswordPolicy(p user.PasswordPolicy) { s.policy = p }

func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input user.Create) (identity.UserID, error) {
	if err := input.Validate(); err != nil {
		return identity.UserID{}, err
	}
	email, err := identity.Email(input.Email)
	if err != nil {
		return identity.UserID{}, errx.Validation("valid email required")
	}
	input.Email = email
	var hash string
	if input.Password != "" {
		if err = s.checkPassword(ctx, environment, input.Password); err != nil {
			return identity.UserID{}, err
		}
		hash, err = s.passwords.Hash(input.Password)
		if err != nil {
			return identity.UserID{}, err
		}
	}
	input.Password = ""
	return s.repository.Create(ctx, environment, input, hash)
}

func (s *Service) checkPassword(ctx context.Context, environment identity.EnvironmentID, password string) error {
	if s.policy != nil {
		return s.policy.CheckPassword(ctx, environment, password)
	}
	if len(password) < config.PasswordMinLength {
		return errx.Validation("password must be 12-72 characters long")
	}
	return nil
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[user.User], error) {
	return s.repository.List(ctx, environment, page)
}
func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (user.User, error) {
	if id.IsZero() {
		return user.User{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation user.Mutation, id identity.UserID, input user.Update) error {
	if id.IsZero() {
		return errx.Validation("invalid user update")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) Suspend(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.Suspend(ctx, environment, id)
}
func (s *Service) Delete(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.Delete(ctx, m, id)
}
func (s *Service) Unlock(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	m.Action = user.ActionUnlocked
	return s.repository.Unlock(ctx, m, id)
}

var _ user.Commands = (*Service)(nil)
var _ user.Queries = (*Service)(nil)
