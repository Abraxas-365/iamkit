package authorization

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/httpx"
)

type ResourceCommands interface {
	CreateResource(ctx context.Context, environment string, input Resource) (string, error)
	UpdateCatalog(ctx context.Context, m Mutation, resourceID string, input Catalog) error
	LinkApplication(ctx context.Context, environment, applicationID, resourceID string) error
	UnlinkApplication(ctx context.Context, environment, applicationID, resourceID string) error
}
type ResourceQueries interface {
	Resources(ctx context.Context, environment string) ([]Resource, error)
	Resource(ctx context.Context, environment, resourceID string) (Resource, error)
	ResourcesByApplication(ctx context.Context, environment, applicationID string) ([]Resource, error)
}

type GrantCommands interface {
	SaveRole(ctx context.Context, m Mutation, resourceID string, input Role) (string, error)
	DeleteRole(ctx context.Context, m Mutation, roleID string) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment, assign bool) error
	PutGrant(ctx context.Context, environment string, input Grant) (string, error)
	DeleteGrant(ctx context.Context, environment, grantID string) error
}
type GrantQueries interface {
	Roles(ctx context.Context, environment, resourceID string) ([]RoleView, error)
	Grants(ctx context.Context, environment, resourceID string) ([]GrantView, error)
	RoleAssignments(ctx context.Context, environment string, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
}

// ResourceRepository updates the catalog and dependent permissions atomically.
type ResourceRepository interface {
	Create(ctx context.Context, environment string, input Resource) error
	List(ctx context.Context, environment string) ([]Resource, error)
	Find(ctx context.Context, environment, resourceID string) (Resource, error)
	UpdateCatalog(ctx context.Context, m Mutation, resourceID string, input Catalog) error
	LinkApplication(ctx context.Context, environment, applicationID, resourceID string) error
	UnlinkApplication(ctx context.Context, environment, applicationID, resourceID string) error
	ListByApplication(ctx context.Context, environment, applicationID string) ([]Resource, error)
}

type Grants interface {
	Catalog(ctx context.Context, environment, resourceID string) ([]string, error)
	Roles(ctx context.Context, environment, resourceID string) ([]RoleView, error)
	Grants(ctx context.Context, environment, resourceID string) ([]GrantView, error)
	RoleAssignments(ctx context.Context, environment string, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
	SaveRole(ctx context.Context, m Mutation, resourceID string, input Role, create bool) error
	DeleteRole(ctx context.Context, m Mutation, roleID string) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	UnassignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	PutGrant(ctx context.Context, environment, grantID string, input Grant) (string, error)
	DeleteGrant(ctx context.Context, environment, grantID string) error
}
