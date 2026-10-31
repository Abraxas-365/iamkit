// Package authzmodule assembles authorization resource and grant use cases.
package authzmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzpg"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/authzsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	ActorID func(*fiber.Ctx) string
}
type Module struct {
	ResourceCommands      authorization.ResourceCommands
	ResourceQueries       authorization.ResourceQueries
	GrantCommands         authorization.GrantCommands
	GrantQueries          authorization.GrantQueries
	ResourceGrantCommands authorization.ResourceGrantCommands
	ResourceGrantQueries  authorization.ResourceGrantQueries
	DescriptionCommands   authorization.DescriptionCommands
	DescriptionQueries    authorization.DescriptionQueries
	HTTP                  *authzhttp.Handler
	Grants                *authzhttp.Grants
	ResourceGrants        *authzhttp.ResourceGrants
	Descriptions          *authzhttp.Descriptions
}

func New(deps Deps) Module {
	repository := authzpg.New(deps.DB)
	resources := authzsvc.New(repository)
	grants := authzsvc.NewGrants(repository)
	resourceGrants := authzsvc.NewResourceGrants(repository)
	descriptions := authzsvc.NewDescriptions(repository)
	return Module{DescriptionCommands: descriptions, DescriptionQueries: descriptions, Descriptions: authzhttp.NewDescriptions(descriptions, descriptions, deps.ActorID),
		ResourceCommands: resources, ResourceQueries: resources, GrantCommands: grants, GrantQueries: grants,
		ResourceGrantCommands: resourceGrants, ResourceGrantQueries: resourceGrants,
		HTTP: authzhttp.New(resources, resources, deps.ActorID), Grants: authzhttp.NewGrants(grants, grants, deps.ActorID),
		ResourceGrants: authzhttp.NewResourceGrants(resourceGrants, resourceGrants, deps.ActorID)}
}
