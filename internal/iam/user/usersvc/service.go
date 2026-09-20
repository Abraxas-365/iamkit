package usersvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository user.Repository
	passwords  user.PasswordHasher
}

func New(repository user.Repository, passwords user.PasswordHasher) *Service {
	return &Service{repository: repository, passwords: passwords}
}
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
		hash, err = s.passwords.Hash(input.Password)
		if err != nil {
			return identity.UserID{}, err
		}
	}
	input.Password = ""
	return s.repository.Create(ctx, environment, input, hash)
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

var _ user.Commands = (*Service)(nil)
var _ user.Queries = (*Service)(nil)
