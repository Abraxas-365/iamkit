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
	GroupCommands     organization.GroupCommands
	GroupQueries      organization.GroupQueries
	HTTP              *orghttp.Handler
	Structure         *orghttp.Structure
	Groups            *orghttp.Groups
}

func New(deps Deps) Module {
	repository := orgpg.New(deps.DB)
	service := orgsvc.New(repository)
	structure := orgsvc.NewStructure(repository)
	groups := orgsvc.NewGroups(repository)
	return Module{
		Commands: service, Queries: service,
		StructureCommands: structure, StructureQueries: structure,
		GroupCommands: groups, GroupQueries: groups,
		HTTP:      orghttp.New(service, service, deps.ActorID),
		Structure: orghttp.NewStructure(structure, structure, deps.ActorID),
		Groups:    orghttp.NewGroups(groups, groups, deps.ActorID),
	}
}
