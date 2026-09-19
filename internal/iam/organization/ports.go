package organization

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, name string) (identity.OrganizationID, error)
	Update(ctx context.Context, m Mutation, organizationID identity.OrganizationID, input Update) error
	AddMember(ctx context.Context, environment identity.EnvironmentID, input Membership) error
	RemoveMember(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID, userID identity.UserID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID) ([]Summary, error)
	Find(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID) (Organization, error)
	Members(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID) ([]MemberView, error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID, name string) error
	List(ctx context.Context, environment identity.EnvironmentID) ([]Summary, error)
	Find(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID) (Organization, error)
	Update(ctx context.Context, m Mutation, organizationID identity.OrganizationID, input Update) error
	AddMember(ctx context.Context, environment identity.EnvironmentID, input Membership) error
	RemoveMember(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID, userID identity.UserID) error
	Members(ctx context.Context, environment identity.EnvironmentID, organizationID identity.OrganizationID) ([]MemberView, error)
}

type StructureCommands interface {
	Check(ctx context.Context, b Boundary) error
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unitID identity.UnitID, input Unit) (identity.UnitID, error)
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unitID identity.UnitID) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, userID identity.UserID, input Profile) error
	SavePosition(ctx context.Context, b Boundary, m Mutation, positionID identity.PositionID, input Position) (identity.PositionID, error)
	DeletePosition(ctx context.Context, b Boundary, m Mutation, positionID identity.PositionID) error
	AssignPosition(ctx context.Context, b Boundary, input Assignment) (identity.AssignmentID, error)
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignmentID identity.AssignmentID) error
}
type StructureQueries interface {
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
}

type StructureRepository interface {
	Exists(ctx context.Context, b Boundary) (bool, error)
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unitID identity.UnitID, input Unit, create bool) error
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unitID identity.UnitID) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, userID identity.UserID, input Profile) error
	CreatePosition(ctx context.Context, b Boundary, positionID identity.PositionID, input Position) error
	UpdatePosition(ctx context.Context, b Boundary, m Mutation, positionID identity.PositionID, input Position) error
	DeletePosition(ctx context.Context, b Boundary, m Mutation, positionID identity.PositionID) error
	AssignPosition(ctx context.Context, b Boundary, assignmentID identity.AssignmentID, input Assignment) error
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignmentID identity.AssignmentID) error
}
