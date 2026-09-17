package orgsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/google/uuid"
)

type Service struct{ repository organization.Repository }

func New(repository organization.Repository) *Service { return &Service{repository} }
func validID(id string) bool                          { _, err := uuid.Parse(id); return err == nil }
func (s *Service) Create(ctx context.Context, environment, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errx.Validation("invalid request")
	}
	id := uuid.NewString()
	return id, s.repository.Create(ctx, environment, id, name)
}
func (s *Service) List(ctx context.Context, environment string) ([]organization.Summary, error) {
	return s.repository.List(ctx, environment)
}
func (s *Service) Find(ctx context.Context, environment, id string) (organization.Organization, error) {
	if !validID(id) {
		return organization.Organization{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation organization.Mutation, id string, input organization.Update) error {
	if !validID(id) || (input.Name != nil && strings.TrimSpace(*input.Name) == "") {
		return errx.Validation("invalid organization update")
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) AddMember(ctx context.Context, environment string, input organization.Membership) error {
	if !validID(input.User) || !validID(input.Organization) || (input.Role != "owner" && input.Role != "admin" && input.Role != "member") {
		return errx.Validation("invalid request")
	}
	return s.repository.AddMember(ctx, environment, input)
}
func (s *Service) RemoveMember(ctx context.Context, environment, org, user string) error {
	if !validID(org) || !validID(user) {
		return errx.NotFound("resource not found")
	}
	return s.repository.RemoveMember(ctx, environment, org, user)
}

var _ organization.Commands = (*Service)(nil)
var _ organization.Queries = (*Service)(nil)
