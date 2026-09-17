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
	ResourceCommands authorization.ResourceCommands
	ResourceQueries  authorization.ResourceQueries
	GrantCommands    authorization.GrantCommands
	GrantQueries     authorization.GrantQueries
	HTTP             *authzhttp.Handler
	Grants           *authzhttp.Grants
}

func New(deps Deps) Module {
	repository := authzpg.New(deps.DB)
	resources := authzsvc.New(repository)
	grants := authzsvc.NewGrants(repository)
	return Module{ResourceCommands: resources, ResourceQueries: resources, GrantCommands: grants, GrantQueries: grants, HTTP: authzhttp.New(resources, resources, deps.ActorID), Grants: authzhttp.NewGrants(grants, grants, deps.ActorID)}
}
