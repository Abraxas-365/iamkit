package authorization

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ResourceCommands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Resource) (identity.ResourceID, error)
	UpdateCatalog(ctx context.Context, m Mutation, resource identity.ResourceID, input Catalog) error
	LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
}
type ResourceQueries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Resource], error)
	Find(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (Resource, error)
	ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, page query.Pagination) (query.Paginated[Resource], error)
}

type GrantCommands interface {
	SaveRole(ctx context.Context, m Mutation, role identity.RoleID, input Role) (identity.RoleID, error)
	DeleteRole(ctx context.Context, m Mutation, role identity.RoleID) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment, assign bool) error
	PutGrant(ctx context.Context, environment identity.EnvironmentID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID) error
}
type GrantQueries interface {
	ListRoles(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, page query.Pagination) (query.Paginated[RoleView], error)
	ListGrants(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, page query.Pagination) (query.Paginated[GrantView], error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
}

type ResourceRepository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Resource) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Resource], error)
	Find(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (Resource, error)
	UpdateCatalog(ctx context.Context, m Mutation, resource identity.ResourceID, input Catalog) error
	LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, page query.Pagination) (query.Paginated[Resource], error)
}

type GrantRepository interface {
	Catalog(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]string, error)
	ListRoles(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, page query.Pagination) (query.Paginated[RoleView], error)
	ListGrants(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, page query.Pagination) (query.Paginated[GrantView], error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
	SaveRole(ctx context.Context, m Mutation, role identity.RoleID, input Role, create bool) error
	DeleteRole(ctx context.Context, m Mutation, role identity.RoleID) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	UnassignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	PutGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID) error
}
