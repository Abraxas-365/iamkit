package orgsvc

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Structure struct {
	repository organization.StructureRepository
}

func NewStructure(r organization.StructureRepository) *Structure { return &Structure{r} }
func (s *Structure) Check(ctx context.Context, b organization.Boundary) error {
	if b.Organization.IsZero() {
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
	return s.repository.View(ctx, b, view, id)
}
func (s *Structure) SaveUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.UnitID, input organization.Unit) (identity.UnitID, error) {
	if err := input.Validate(); err != nil {
		return identity.UnitID{}, err
	}
	if id.IsZero() {
		id = identity.NewUnitID()
	}
	return id, s.repository.SaveUnit(ctx, b, m, id, input, id.IsZero())
}
func (s *Structure) DeleteUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.UnitID) error {
	if id.IsZero() {
		return errx.Validation("invalid unit")
	}
	return s.repository.DeleteUnit(ctx, b, m, id)
}
func (s *Structure) SetProfile(ctx context.Context, b organization.Boundary, m organization.Mutation, userID identity.UserID, input organization.Profile) error {
	if userID.IsZero() {
		return errx.Validation("invalid member profile")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.SetProfile(ctx, b, m, userID, input)
}
func (s *Structure) SavePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.PositionID, input organization.Position) (identity.PositionID, error) {
	if err := input.Validate(); err != nil {
		return identity.PositionID{}, err
	}
	if id.IsZero() {
		id = identity.NewPositionID()
		return id, s.repository.CreatePosition(ctx, b, id, input)
	}
	return id, s.repository.UpdatePosition(ctx, b, m, id, input)
}
func (s *Structure) DeletePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.PositionID) error {
	if id.IsZero() {
		return errx.Validation("invalid position")
	}
	return s.repository.DeletePosition(ctx, b, m, id)
}
func (s *Structure) AssignPosition(ctx context.Context, b organization.Boundary, input organization.Assignment) (identity.AssignmentID, error) {
	if err := input.Validate(); err != nil {
		return identity.AssignmentID{}, err
	}
	id := identity.NewAssignmentID()
	return id, s.repository.AssignPosition(ctx, b, id, input)
}
func (s *Structure) DeleteAssignment(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.AssignmentID) error {
	if id.IsZero() {
		return errx.Validation("invalid assignment")
	}
	return s.repository.DeleteAssignment(ctx, b, m, id)
}
