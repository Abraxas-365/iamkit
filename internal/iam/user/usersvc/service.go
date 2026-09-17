package usersvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct {
	repository user.Repository
	passwords  user.PasswordHasher
}

func New(repository user.Repository, passwords user.PasswordHasher) *Service {
	return &Service{repository: repository, passwords: passwords}
}
func (s *Service) Create(ctx context.Context, environment string, input user.Create) (string, error) {
	email, err := identity.Email(input.Email)
	if err != nil || strings.TrimSpace(input.Name) == "" || (input.Password != "" && (len(input.Password) < 12 || len(input.Password) > 72)) {
		return "", errx.Validation("valid email, name and optional 12-72 byte password required")
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
	if _, err := uuid.Parse(id); err != nil {
		return user.User{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation user.Mutation, id string, input user.Update) error {
	if _, err := uuid.Parse(id); err != nil {
		return errx.Validation("invalid user update")
	}
	if input.Name != nil && strings.TrimSpace(*input.Name) == "" {
		return errx.Validation("invalid user update")
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) Suspend(ctx context.Context, environment, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errx.NotFound("resource not found")
	}
	return s.repository.Suspend(ctx, environment, id)
}

var _ user.Commands = (*Service)(nil)
var _ user.Queries = (*Service)(nil)
