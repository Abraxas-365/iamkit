package authorization

import "context"

type Role struct {
	Name        string   `json:"name"`
	Resource    string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
}
type Grant struct {
	Organization string   `json:"organization_id"`
	User         string   `json:"user_id"`
	Resource     string   `json:"resource_id"`
	Permissions  []string `json:"permissions"`
}
type RoleAssignment struct {
	Organization string `json:"organization_id"`
	User         string `json:"user_id"`
	Role         string `json:"role_id"`
}
type RoleView struct {
	ID          string   `json:"id" db:"id"`
	Name        string   `json:"name" db:"name"`
	Resource    string   `json:"resource_id" db:"resource_id"`
	Permissions []string `json:"permissions" db:"permissions"`
}
type GrantView struct {
	ID           string   `json:"id" db:"id"`
	Organization string   `json:"organization_id" db:"organization_id"`
	User         string   `json:"user_id" db:"user_id"`
	Resource     string   `json:"resource_id" db:"resource_id"`
	Permissions  []string `json:"permissions" db:"permissions"`
}
type ResourceCommands interface {
	CreateResource(context.Context, string, Resource) (string, error)
	UpdateCatalog(context.Context, Mutation, string, Catalog) error
	LinkApplication(context.Context, string, string, string) error
}
type ResourceQueries interface {
	Resources(context.Context, string) ([]Resource, error)
	Resource(context.Context, string, string) (Resource, error)
}
type GrantCommands interface {
	SaveRole(context.Context, Mutation, string, Role) (string, error)
	DeleteRole(context.Context, Mutation, string) error
	AssignRole(context.Context, Mutation, RoleAssignment, bool) error
	PutGrant(context.Context, string, Grant) (string, error)
	DeleteGrant(context.Context, string, string) error
}
type GrantQueries interface {
	Roles(context.Context, string, string) ([]RoleView, error)
	Grants(context.Context, string, string) ([]GrantView, error)
}

type Grants interface {
	Catalog(context.Context, string, string) ([]string, error)
	Roles(context.Context, string, string) ([]RoleView, error)
	Grants(context.Context, string, string) ([]GrantView, error)
	SaveRole(context.Context, Mutation, string, Role, bool) error
	DeleteRole(context.Context, Mutation, string) error
	AssignRole(context.Context, Mutation, RoleAssignment) error
	UnassignRole(context.Context, Mutation, RoleAssignment) error
	PutGrant(context.Context, string, string, Grant) (string, error)
	DeleteGrant(context.Context, string, string) error
}
