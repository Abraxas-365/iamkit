package authorization

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type ResourceCommands interface {
	CreateResource(ctx context.Context, environment identity.EnvironmentID, input Resource) (identity.ResourceID, error)
	UpdateCatalog(ctx context.Context, m Mutation, resourceID identity.ResourceID, input Catalog) error
	LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
}
type ResourceQueries interface {
	Resources(ctx context.Context, environment identity.EnvironmentID) ([]Resource, error)
	Resource(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) (Resource, error)
	ResourcesByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) ([]Resource, error)
}

type GrantCommands interface {
	SaveRole(ctx context.Context, m Mutation, roleID identity.RoleID, input Role) (identity.RoleID, error)
	DeleteRole(ctx context.Context, m Mutation, roleID identity.RoleID) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment, assign bool) error
	PutGrant(ctx context.Context, environment identity.EnvironmentID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grantID identity.GrantID) error
}
type GrantQueries interface {
	Roles(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]RoleView, error)
	Grants(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]GrantView, error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
}

type ResourceRepository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Resource) error
	List(ctx context.Context, environment identity.EnvironmentID) ([]Resource, error)
	Find(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) (Resource, error)
	UpdateCatalog(ctx context.Context, m Mutation, resourceID identity.ResourceID, input Catalog) error
	LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) ([]Resource, error)
}

type Grants interface {
	Catalog(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]string, error)
	Roles(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]RoleView, error)
	Grants(ctx context.Context, environment identity.EnvironmentID, resourceID identity.ResourceID) ([]GrantView, error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
	SaveRole(ctx context.Context, m Mutation, roleID identity.RoleID, input Role, create bool) error
	DeleteRole(ctx context.Context, m Mutation, roleID identity.RoleID) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	UnassignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	PutGrant(ctx context.Context, environment identity.EnvironmentID, grantID identity.GrantID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grantID identity.GrantID) error
}
