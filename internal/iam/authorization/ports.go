package authorization

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ResourceCommands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Resource) (identity.ResourceID, error)
	UpdateCatalog(ctx context.Context, m Mutation, resource identity.ResourceID, input Catalog) error
	// UpdateAPIKeyPermissions replaces the resource's API key allowlist
	// (audited resource.api_key_permissions_update → resource.updated).
	UpdateAPIKeyPermissions(ctx context.Context, m Mutation, resource identity.ResourceID, input APIKeyPermissions) error
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
	AssignGroupRole(ctx context.Context, m Mutation, input GroupRoleAssignment, remove bool) error
	PutGrant(ctx context.Context, environment identity.EnvironmentID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID) error
}
type GrantQueries interface {
	ListRoles(ctx context.Context, environment identity.EnvironmentID, role identity.RoleID, page query.Pagination) (query.Paginated[RoleView], error)
	ListGrants(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID, page query.Pagination) (query.Paginated[GrantView], error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
	GroupRoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter GroupRoleAssignmentFilter, page query.Pagination) (query.Paginated[GroupRoleAssignmentView], error)
	// EffectiveRoles lists every role user holds with its source, in
	// organization or, when organization is zero, in all of the user's.
	EffectiveRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) ([]EffectiveRoleView, error)
}

type ResourceRepository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Resource) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Resource], error)
	Find(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (Resource, error)
	UpdateCatalog(ctx context.Context, m Mutation, resource identity.ResourceID, input Catalog) error
	UpdateAPIKeyPermissions(ctx context.Context, m Mutation, resource identity.ResourceID, input APIKeyPermissions) error
	LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error
	ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, page query.Pagination) (query.Paginated[Resource], error)
}

type GrantRepository interface {
	Catalog(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]string, error)
	ListRoles(ctx context.Context, environment identity.EnvironmentID, role identity.RoleID, page query.Pagination) (query.Paginated[RoleView], error)
	ListGrants(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID, page query.Pagination) (query.Paginated[GrantView], error)
	RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
	SaveRole(ctx context.Context, m Mutation, role identity.RoleID, input Role, create bool) error
	DeleteRole(ctx context.Context, m Mutation, role identity.RoleID) error
	AssignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	UnassignRole(ctx context.Context, m Mutation, input RoleAssignment) error
	AssignGroupRole(ctx context.Context, m Mutation, input GroupRoleAssignment) error
	UnassignGroupRole(ctx context.Context, m Mutation, input GroupRoleAssignment) error
	GroupRoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter GroupRoleAssignmentFilter, page query.Pagination) (query.Paginated[GroupRoleAssignmentView], error)
	EffectiveRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) ([]EffectiveRoleView, error)
	PutGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID, input Grant) (identity.GrantID, error)
	DeleteGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.GrantID) error
}

// ResourceGrantCommands set who owns a resource and which organizations it
// is granted to (see ResourceAccess).
type ResourceGrantCommands interface {
	SetResourceAccess(ctx context.Context, m Mutation, resource identity.ResourceID, input ResourceAccess) error
	// PutResourceGrant creates the grant or replaces its roles.
	PutResourceGrant(ctx context.Context, m Mutation, input ResourceGrantInput) (ResourceGrant, error)
	DeleteResourceGrant(ctx context.Context, m Mutation, grant identity.ResourceGrantID) error
}
type ResourceGrantQueries interface {
	ListResourceGrants(ctx context.Context, environment identity.EnvironmentID, filter ResourceGrantFilter, page query.Pagination) (query.Paginated[ResourceGrant], error)
	FindResourceGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.ResourceGrantID) (ResourceGrant, error)
}

type ResourceGrantRepository interface {
	FindResource(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (Resource, error)
	// CountRoles counts how many of roles belong to resource.
	CountRoles(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, roles []identity.RoleID) (int, error)
	// SetResourceAccess also ends the sessions of organizations that lose
	// access to the resource.
	SetResourceAccess(ctx context.Context, m Mutation, resource identity.ResourceID, input ResourceAccess) error
	// PutResourceGrant upserts on (resource, organization), keeping the ID of
	// an existing grant, and ends the organization's sessions for the
	// resource when roles were taken away.
	PutResourceGrant(ctx context.Context, m Mutation, grant identity.ResourceGrantID, input ResourceGrantInput) (identity.ResourceGrantID, error)
	DeleteResourceGrant(ctx context.Context, m Mutation, grant identity.ResourceGrantID) error
	ListResourceGrants(ctx context.Context, environment identity.EnvironmentID, filter ResourceGrantFilter, page query.Pagination) (query.Paginated[ResourceGrant], error)
	FindResourceGrant(ctx context.Context, environment identity.EnvironmentID, grant identity.ResourceGrantID) (ResourceGrant, error)
}

// DescriptionCommands edit how people read a resource's permissions (D40).
type DescriptionCommands interface {
	// SetDescriptions replaces the resource's whole set of descriptions
	// (idempotent, so a catalog sync can repeat it). Every permission must
	// be in the catalog; an empty set clears them. Audited
	// resource.descriptions_updated.
	SetDescriptions(ctx context.Context, m Mutation, resource identity.ResourceID, descriptions []PermissionDescription) error
}

// DescriptionQueries read them.
type DescriptionQueries interface {
	// Descriptions is the stored set, ordered by permission then locale.
	Descriptions(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]PermissionDescription, error)
	// Describe resolves permissions for a reader who prefers locales (see
	// Describe): exact locale, base language, default text, the name.
	Describe(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, permissions []string, locales ...string) ([]DescribedPermission, error)
}

// DescriptionRepository persists descriptions next to the catalog they
// describe.
type DescriptionRepository interface {
	FindResource(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (Resource, error)
	// ReplaceDescriptions swaps the set in one transaction, checking it
	// against the catalog as locked there, and records the event.
	ReplaceDescriptions(ctx context.Context, m Mutation, resource identity.ResourceID, descriptions []PermissionDescription) error
	ListDescriptions(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]PermissionDescription, error)
}
