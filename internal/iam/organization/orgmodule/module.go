// Package orgmodule assembles organization use cases and adapters.
package orgmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orgpg"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/orgsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	ActorID func(*fiber.Ctx) string
}
type Module struct {
	Commands          organization.Commands
	Queries           organization.Queries
	StructureCommands organization.StructureCommands
	StructureQueries  organization.StructureQueries
	HTTP              *orghttp.Handler
	Structure         *orghttp.Structure
}

func New(deps Deps) Module {
	repository := orgpg.New(deps.DB)
	service := orgsvc.New(repository)
	structure := orgsvc.NewStructure(repository)
	return Module{Commands: service, Queries: service, StructureCommands: structure, StructureQueries: structure, HTTP: orghttp.New(service, service, deps.ActorID), Structure: orghttp.NewStructure(structure, structure, deps.ActorID)}
}
