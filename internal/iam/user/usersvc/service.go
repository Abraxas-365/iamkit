package usersvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository user.Repository
	passwords  user.PasswordHasher
}

func New(repository user.Repository, passwords user.PasswordHasher) *Service {
	return &Service{repository: repository, passwords: passwords}
}
func (s *Service) Create(ctx context.Context, environment string, input user.Create) (string, error) {
	if err := input.Validate(); err != nil {
		return "", err
	}
	email, err := identity.Email(input.Email)
	if err != nil {
		return "", errx.Validation("valid email required")
	}
	input.Email = email
	var hash string
	if input.Password != "" {
		hash, err = s.passwords.Hash(input.Password)
		if err != nil {
			return "", err
		}
	}
	input.Password = ""
	return s.repository.Create(ctx, environment, input, hash)
}
func (s *Service) List(ctx context.Context, environment string) ([]user.User, error) {
	return s.repository.List(ctx, environment)
}
func (s *Service) Find(ctx context.Context, environment, id string) (user.User, error) {
	if !identity.ValidID(id) {
		return user.User{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation user.Mutation, id string, input user.Update) error {
	if !identity.ValidID(id) {
		return errx.Validation("invalid user update")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) Suspend(ctx context.Context, environment, id string) error {
	if !identity.ValidID(id) {
		return errx.NotFound("resource not found")
	}
	return s.repository.Suspend(ctx, environment, id)
}

var _ user.Commands = (*Service)(nil)
var _ user.Queries = (*Service)(nil)
