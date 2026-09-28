package authorization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Role struct {
	Name        string              `json:"name"`
	Resource    identity.ResourceID `json:"resource_id"`
	Permissions []string            `json:"permissions"`
}

func (r Role) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errx.Validation("role name is required")
	}
	if r.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	return nil
}

type Grant struct {
	Organization identity.OrganizationID `json:"organization_id"`
	User         identity.UserID         `json:"user_id"`
	Resource     identity.ResourceID     `json:"resource_id"`
	Permissions  []string                `json:"permissions"`
}

func (g Grant) Validate() error {
	if g.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if g.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	if g.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	return nil
}

type RoleAssignment struct {
	Organization identity.OrganizationID `json:"organization_id"`
	User         identity.UserID         `json:"user_id"`
	Role         identity.RoleID         `json:"role_id"`
}

func (a RoleAssignment) Validate() error {
	if a.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if a.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	if a.Role.IsZero() {
		return errx.Validation("role_id must be a valid UUID")
	}
	return nil
}

type RoleView struct {
	ID           identity.RoleID     `json:"id" db:"id"`
	Name         string              `json:"name" db:"name"`
	Resource     identity.ResourceID `json:"resource_id" db:"resource_id"`
	ResourceName string              `json:"resource_name" db:"resource_name"`
	Permissions  []string            `json:"permissions" db:"permissions"`
}
type GrantView struct {
	ID               identity.GrantID        `json:"id" db:"id"`
	Organization     identity.OrganizationID `json:"organization_id" db:"organization_id"`
	OrganizationName string                  `json:"organization_name" db:"organization_name"`
	User             identity.UserID         `json:"user_id" db:"user_id"`
	UserName         string                  `json:"user_name" db:"user_name"`
	Resource         identity.ResourceID     `json:"resource_id" db:"resource_id"`
	ResourceName     string                  `json:"resource_name" db:"resource_name"`
	Permissions      []string                `json:"permissions" db:"permissions"`
}
type RoleAssignmentView struct {
	Organization     identity.OrganizationID `json:"organization_id" db:"organization_id"`
	OrganizationName string                  `json:"organization_name" db:"organization_name"`
	User             identity.UserID         `json:"user_id" db:"user_id"`
	UserName         string                  `json:"user_name" db:"user_name"`
	UserEmail        string                  `json:"user_email" db:"user_email"`
	Resource         identity.ResourceID     `json:"resource_id" db:"resource_id"`
	ResourceName     string                  `json:"resource_name" db:"resource_name"`
	Role             identity.RoleID         `json:"role_id" db:"role_id"`
	RoleName         string                  `json:"role_name" db:"role_name"`
}

type RoleAssignmentFilter struct {
	RoleID         identity.RoleID
	OrganizationID identity.OrganizationID
	UserID         identity.UserID
	ResourceID     identity.ResourceID
}

// GroupRoleAssignment binds a role to a group; every group member holds it.
// Directory-owned groups can be bound too: the directory controls members,
// operators control which roles the group carries.
type GroupRoleAssignment struct {
	Organization identity.OrganizationID `json:"organization_id"`
	Group        identity.GroupID        `json:"group_id"`
	Role         identity.RoleID         `json:"role_id"`
}

func (a GroupRoleAssignment) Validate() error {
	if a.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if a.Group.IsZero() {
		return errx.Validation("group_id must be a valid UUID")
	}
	if a.Role.IsZero() {
		return errx.Validation("role_id must be a valid UUID")
	}
	return nil
}

type GroupRoleAssignmentView struct {
	Organization     identity.OrganizationID `json:"organization_id" db:"organization_id"`
	OrganizationName string                  `json:"organization_name" db:"organization_name"`
	Group            identity.GroupID        `json:"group_id" db:"group_id"`
	GroupName        string                  `json:"group_name" db:"group_name"`
	Resource         identity.ResourceID     `json:"resource_id" db:"resource_id"`
	ResourceName     string                  `json:"resource_name" db:"resource_name"`
	Role             identity.RoleID         `json:"role_id" db:"role_id"`
	RoleName         string                  `json:"role_name" db:"role_name"`
}

type GroupRoleAssignmentFilter struct {
	OrganizationID identity.OrganizationID
	GroupID        identity.GroupID
	RoleID         identity.RoleID
	ResourceID     identity.ResourceID
}

// Role sources reported by EffectiveRoles.
const (
	SourceDirect = "direct"
	SourceGroup  = "group"
)

// EffectiveRoleView is one reason a member holds a role: a direct assignment
// or membership in a group bound to the role. A role held both ways appears
// once per source.
type EffectiveRoleView struct {
	Organization identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Role         identity.RoleID         `json:"role_id" db:"role_id"`
	RoleName     string                  `json:"role_name" db:"role_name"`
	Resource     identity.ResourceID     `json:"resource_id" db:"resource_id"`
	ResourceName string                  `json:"resource_name" db:"resource_name"`
	Source       string                  `json:"source" db:"source"`
	Group        *identity.GroupID       `json:"group_id,omitempty" db:"group_id"`
	GroupName    *string                 `json:"group_name,omitempty" db:"group_name"`
}
