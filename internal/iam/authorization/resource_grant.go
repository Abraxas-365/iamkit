package authorization

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ResourceAccess says which organization owns a resource and whether only
// the owner and granted organizations reach it. The owner organization's
// administrators (iam:org:resources:write) grant it to other organizations,
// whose administrators then assign its roles to their members.
type ResourceAccess struct {
	// OwnerOrganization is the vendor organization shipping the resource;
	// nil = owned by the environment (operators only).
	OwnerOrganization *identity.OrganizationID `json:"owner_organization_id"`
	// RequireGrant limits token access to the owner and granted
	// organizations (and, for roles, to granted roles). Off by default: any
	// organization can hold the resource's roles, as operators assign them.
	RequireGrant bool `json:"require_grant"`
}

// Validate checks the structural invariants ResourceAccess owns.
func (a ResourceAccess) Validate() error {
	if a.OwnerOrganization != nil && a.OwnerOrganization.IsZero() {
		return errx.Validation("owner_organization_id must be a valid UUID")
	}
	return nil
}

// ResourceGrant lets an organization use a resource it does not own.
type ResourceGrant struct {
	ID               identity.ResourceGrantID `json:"id" db:"id"`
	Resource         identity.ResourceID      `json:"resource_id" db:"resource_id"`
	ResourceName     string                   `json:"resource_name" db:"resource_name"`
	Organization     identity.OrganizationID  `json:"organization_id" db:"organization_id"`
	OrganizationName string                   `json:"organization_name" db:"organization_name"`
	// Roles are the granted roles; nil grants every role of the resource,
	// current and future.
	Roles   []identity.RoleID `json:"role_ids" db:"-"`
	Created time.Time         `json:"created_at" db:"created_at"`
	Updated time.Time         `json:"updated_at" db:"updated_at"`
}

// ResourceGrantInput grants a resource to an organization; putting it again
// replaces the granted roles.
type ResourceGrantInput struct {
	Resource     identity.ResourceID     `json:"resource_id"`
	Organization identity.OrganizationID `json:"organization_id"`
	// Roles nil (absent or null) grants every role; [] grants none, so
	// only direct permission grants of operators count.
	Roles []identity.RoleID `json:"role_ids"`
}

// Validate checks the structural invariants ResourceGrantInput owns.
func (g ResourceGrantInput) Validate() error {
	if g.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if g.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	seen := make(map[identity.RoleID]bool, len(g.Roles))
	for _, role := range g.Roles {
		if role.IsZero() {
			return errx.Validation("role_ids must be valid UUIDs")
		}
		if seen[role] {
			return errx.Validation("role_ids must not repeat")
		}
		seen[role] = true
	}
	return nil
}

// ResourceGrantFilter narrows a list of resource grants; zero fields match
// everything. Owner lists the grants of resources that organization owns.
type ResourceGrantFilter struct {
	Resource     identity.ResourceID
	Organization identity.OrganizationID
	Owner        identity.OrganizationID
}
