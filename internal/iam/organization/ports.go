package organization

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, name string) (identity.OrganizationID, error)
	Update(ctx context.Context, m Mutation, organization identity.OrganizationID, input Update) error
	AddMember(ctx context.Context, environment identity.EnvironmentID, input Membership) error
	RemoveMember(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Summary], error)
	Find(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (Organization, error)
	Members(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, filter MemberFilter, page query.Pagination) (query.Paginated[MemberView], error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, name string) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Summary], error)
	Find(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (Organization, error)
	Update(ctx context.Context, m Mutation, organization identity.OrganizationID, input Update) error
	AddMember(ctx context.Context, environment identity.EnvironmentID, input Membership) error
	RemoveMember(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) error
	Members(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, filter MemberFilter, page query.Pagination) (query.Paginated[MemberView], error)
}

type StructureCommands interface {
	Check(ctx context.Context, b Boundary) error
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unit identity.UnitID, input Unit) (identity.UnitID, error)
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unit identity.UnitID) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, user identity.UserID, input Profile) error
	SavePosition(ctx context.Context, b Boundary, m Mutation, position identity.PositionID, input Position) (identity.PositionID, error)
	DeletePosition(ctx context.Context, b Boundary, m Mutation, position identity.PositionID) error
	AssignPosition(ctx context.Context, b Boundary, input Assignment) (identity.AssignmentID, error)
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignment identity.AssignmentID) error
}
type StructureQueries interface {
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
}

type StructureRepository interface {
	Exists(ctx context.Context, b Boundary) (bool, error)
	View(ctx context.Context, b Boundary, view StructureView, param string) (json.RawMessage, error)
	SaveUnit(ctx context.Context, b Boundary, m Mutation, unit identity.UnitID, input Unit, create bool) error
	DeleteUnit(ctx context.Context, b Boundary, m Mutation, unit identity.UnitID) error
	SetProfile(ctx context.Context, b Boundary, m Mutation, user identity.UserID, input Profile) error
	CreatePosition(ctx context.Context, b Boundary, position identity.PositionID, input Position) error
	UpdatePosition(ctx context.Context, b Boundary, m Mutation, position identity.PositionID, input Position) error
	DeletePosition(ctx context.Context, b Boundary, m Mutation, position identity.PositionID) error
	AssignPosition(ctx context.Context, b Boundary, assignment identity.AssignmentID, input Assignment) error
	DeleteAssignment(ctx context.Context, b Boundary, m Mutation, assignment identity.AssignmentID) error
}

// GroupCommands manages operator groups and their members. Directory-owned
// groups reject name and member changes with a business error.
type GroupCommands interface {
	CreateGroup(ctx context.Context, b Boundary, m Mutation, input GroupInput) (identity.GroupID, error)
	UpdateGroup(ctx context.Context, b Boundary, m Mutation, group identity.GroupID, input GroupUpdate) error
	DeleteGroup(ctx context.Context, b Boundary, m Mutation, group identity.GroupID) error
	ChangeGroupMembers(ctx context.Context, b Boundary, m Mutation, group identity.GroupID, input GroupMembers) error
}
type GroupQueries interface {
	ListGroups(ctx context.Context, b Boundary, filter GroupFilter, page query.Pagination) (query.Paginated[Group], error)
	FindGroup(ctx context.Context, b Boundary, group identity.GroupID) (Group, error)
	ListGroupMembers(ctx context.Context, b Boundary, group identity.GroupID, page query.Pagination) (query.Paginated[GroupMemberView], error)
}

// GroupRepository persists groups. Mutations only touch operator groups
// (connection_id IS NULL); the service checks ownership first for a clear error.
type GroupRepository interface {
	CreateGroup(ctx context.Context, b Boundary, m Mutation, group identity.GroupID, input GroupInput) error
	UpdateGroup(ctx context.Context, b Boundary, m Mutation, group identity.GroupID, input GroupUpdate) error
	DeleteGroup(ctx context.Context, b Boundary, m Mutation, group identity.GroupID) error
	ChangeGroupMembers(ctx context.Context, b Boundary, m Mutation, group identity.GroupID, input GroupMembers) error
	ListGroups(ctx context.Context, b Boundary, filter GroupFilter, page query.Pagination) (query.Paginated[Group], error)
	FindGroup(ctx context.Context, b Boundary, group identity.GroupID) (Group, error)
	ListGroupMembers(ctx context.Context, b Boundary, group identity.GroupID, page query.Pagination) (query.Paginated[GroupMemberView], error)
}
