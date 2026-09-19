package authorization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Role struct {
	Name        string   `json:"name"`
	Resource    string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
}

// Validate checks the structural invariants Role owns.
func (r Role) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errx.Validation("role name is required")
	}
	if !identity.ValidID(r.Resource) {
		return errx.Validation("resource_id must be a valid UUID")
	}
	return nil
}

type Grant struct {
	Organization string   `json:"organization_id"`
	User         string   `json:"user_id"`
	Resource     string   `json:"resource_id"`
	Permissions  []string `json:"permissions"`
}

// Validate checks the structural invariants Grant owns.
func (g Grant) Validate() error {
	if !identity.ValidID(g.Organization) {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if !identity.ValidID(g.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	if !identity.ValidID(g.Resource) {
		return errx.Validation("resource_id must be a valid UUID")
	}
	return nil
}

type RoleAssignment struct {
	Organization string `json:"organization_id"`
	User         string `json:"user_id"`
	Role         string `json:"role_id"`
}

// Validate checks the structural invariants RoleAssignment owns.
func (a RoleAssignment) Validate() error {
	if !identity.ValidID(a.Organization) {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if !identity.ValidID(a.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	if !identity.ValidID(a.Role) {
		return errx.Validation("role_id must be a valid UUID")
	}
	return nil
}
type RoleView struct {
	ID           string   `json:"id" db:"id"`
	Name         string   `json:"name" db:"name"`
	Resource     string   `json:"resource_id" db:"resource_id"`
	ResourceName string   `json:"resource_name" db:"resource_name"`
	Permissions  []string `json:"permissions" db:"permissions"`
}
type GrantView struct {
	ID               string   `json:"id" db:"id"`
	Organization     string   `json:"organization_id" db:"organization_id"`
	OrganizationName string   `json:"organization_name" db:"organization_name"`
	User             string   `json:"user_id" db:"user_id"`
	UserName         string   `json:"user_name" db:"user_name"`
	Resource         string   `json:"resource_id" db:"resource_id"`
	ResourceName     string   `json:"resource_name" db:"resource_name"`
	Permissions      []string `json:"permissions" db:"permissions"`
}
type RoleAssignmentView struct {
	Organization     string `json:"organization_id" db:"organization_id"`
	OrganizationName string `json:"organization_name" db:"organization_name"`
	User             string `json:"user_id" db:"user_id"`
	UserName         string `json:"user_name" db:"user_name"`
	UserEmail        string `json:"user_email" db:"user_email"`
	Resource         string `json:"resource_id" db:"resource_id"`
	ResourceName     string `json:"resource_name" db:"resource_name"`
	Role             string `json:"role_id" db:"role_id"`
	RoleName         string `json:"role_name" db:"role_name"`
}

// RoleAssignmentFilter holds optional filters for listing role assignments.
// Empty string fields are ignored (match all).
type RoleAssignmentFilter struct {
	RoleID         string
	OrganizationID string
	UserID         string
	ResourceID     string
	Search         string // free-text match on names/email
}
