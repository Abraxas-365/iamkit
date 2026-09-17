package orgsvc

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/google/uuid"
)

type Structure struct {
	repository organization.StructureRepository
}

func NewStructure(r organization.StructureRepository) *Structure { return &Structure{r} }
func optionalID(id *string) bool                                 { return id == nil || validID(*id) }
func (s *Structure) Check(ctx context.Context, b organization.Boundary) error {
	if !validID(b.Organization) {
		return errx.NotFound("organization not found")
	}
	exists, err := s.repository.Exists(ctx, b)
	if err != nil {
		return err
	}
	if !exists {
		return errx.NotFound("organization not found")
	}
	return nil
}
func (s *Structure) View(ctx context.Context, b organization.Boundary, view organization.StructureView, id string) (json.RawMessage, error) {
	if id != "" && !validID(id) {
		return nil, errx.NotFound("resource not found")
	}
	return s.repository.View(ctx, b, view, id)
}
func (s *Structure) SaveUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id string, input organization.Unit) (string, error) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Kind) == "" || !optionalID(input.Parent) {
		return "", errx.Validation("invalid organizational unit")
	}
	creating := id == ""
	if creating {
		id = uuid.NewString()
	}
	if !validID(id) {
		return "", errx.Validation("invalid unit")
	}
	return id, s.repository.SaveUnit(ctx, b, m, id, input, creating)
}
func (s *Structure) DeleteUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	if !validID(id) {
		return errx.Validation("invalid unit")
	}
	return s.repository.DeleteUnit(ctx, b, m, id)
}
func (s *Structure) SetProfile(ctx context.Context, b organization.Boundary, m organization.Mutation, user string, input organization.Profile) error {
	if !validID(user) || !optionalID(input.Unit) || !optionalID(input.Manager) {
		return errx.Validation("invalid member profile")
	}
	return s.repository.SetProfile(ctx, b, m, user, input)
}
func (s *Structure) SavePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id string, input organization.Position) (string, error) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Code) == "" {
		return "", errx.Validation("position name and code required")
	}
	if id == "" {
		id = uuid.NewString()
		return id, s.repository.CreatePosition(ctx, b, id, input)
	}
	if !validID(id) {
		return "", errx.Validation("invalid position")
	}
	return id, s.repository.UpdatePosition(ctx, b, m, id, input)
}
func (s *Structure) DeletePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	if !validID(id) {
		return errx.Validation("invalid position")
	}
	return s.repository.DeletePosition(ctx, b, m, id)
}
func (s *Structure) AssignPosition(ctx context.Context, b organization.Boundary, input organization.Assignment) (string, error) {
	if !validID(input.Position) || !validID(input.User) || !optionalID(input.Unit) {
		return "", errx.Validation("invalid position assignment")
	}
	id := uuid.NewString()
	return id, s.repository.AssignPosition(ctx, b, id, input)
}
func (s *Structure) DeleteAssignment(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	if !validID(id) {
		return errx.Validation("invalid assignment")
	}
	return s.repository.DeleteAssignment(ctx, b, m, id)
}
