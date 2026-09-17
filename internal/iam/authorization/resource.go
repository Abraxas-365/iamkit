package authorization

import "context"

type Resource struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}
type Catalog struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}
type Mutation struct{ Environment, Actor, Action, Target string }

// ResourceRepository updates the catalog and dependent permissions atomically.
type ResourceRepository interface {
	Create(context.Context, string, Resource) error
	List(context.Context, string) ([]Resource, error)
	Find(context.Context, string, string) (Resource, error)
	UpdateCatalog(context.Context, Mutation, string, Catalog) error
	LinkApplication(context.Context, string, string, string) error
}
