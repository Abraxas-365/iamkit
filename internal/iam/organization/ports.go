package organization

import (
	"context"
	"encoding/json"
)

type Commands interface {
	Create(ctx context.Context, environment, name string) (string, error)
	Update(ctx context.Context, m Mutation, organizationID string, input Update) error
	AddMember(ctx context.Context, environment string, input Membership) error
	RemoveMember(ctx context.Context, environment, organizationID, userID string) error
}
type Queries interface {
	List(ctx context.Context, environment string) ([]Summary, error)
	Find(ctx context.Context, environment, organizationID string) (Organization, error)
	Members(ctx context.Context, environment, organizationID string) ([]MemberView, error)
}

// Repository scopes every operation to an environment; mutations include atomic audit writes.
type Repository interface {
	Create(ctx context.Context, environment, organizationID, name string) error
	List(ctx context.Context, environment string) ([]Summary, error)
	Find(ctx context.Context, environment, organizationID string) (Organization, error)
	Update(ctx context.Context, m Mutation, organizationID string, input Update) error
	AddMember(ctx context.Context, environment string, input Membership) error
	RemoveMember(ctx context.Context, environment, organizationID, userID string) error
	Members(ctx context.Context, environment, organizationID string) ([]MemberView, error)
}

type StructureCommands interface {
	Check(ctx context.Context, b Boundary) error
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unitID string, input Unit) (string, error)
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unitID string) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, userID string, input Profile) error
	SavePosition(ctx context.Context, b Boundary, m Mutation, positionID string, input Position) (string, error)
	DeletePosition(ctx context.Context, b Boundary, m Mutation, positionID string) error
	AssignPosition(ctx context.Context, b Boundary, input Assignment) (string, error)
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignmentID string) error
}
type StructureQueries interface {
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
}

type StructureRepository interface {
	Exists(ctx context.Context, b Boundary) (bool, error)
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unitID string, input Unit, create bool) error
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unitID string) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, userID string, input Profile) error
	CreatePosition(ctx context.Context, b Boundary, positionID string, input Position) error
	UpdatePosition(ctx context.Context, b Boundary, m Mutation, positionID string, input Position) error
	DeletePosition(ctx context.Context, b Boundary, m Mutation, positionID string) error
	AssignPosition(ctx context.Context, b Boundary, assignmentID string, input Assignment) error
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignmentID string) error
}
