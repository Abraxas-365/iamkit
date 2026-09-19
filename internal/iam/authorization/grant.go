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
	Search         string
}
