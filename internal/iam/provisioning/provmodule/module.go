// Package provmodule assembles SCIM provisioning and its management controls.
package provmodule

import (
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/adapters/provhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/adapters/provpg"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/provsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	ActorID func(*fiber.Ctx) string
	// Quota enforces the users limit on SCIM creates (nil: none).
	Quota provisioning.Quota
}
type Module struct {
	Commands        provisioning.Commands
	Queries         provisioning.Queries
	GroupCommands   provisioning.GroupCommands
	GroupQueries    provisioning.GroupQueries
	ControlCommands provisioning.ControlCommands
	ControlQueries  provisioning.ControlQueries
	HTTP            *provhttp.Handler
	Control         *provhttp.Control
}

func New(deps Deps) Module {
	repository := provpg.New(deps.DB)
	service := provsvc.New(repository, cryptox.Generator{})
	if deps.Quota != nil {
		service.SetQuota(deps.Quota)
	}
	groups := provsvc.NewGroups(repository)
	control := provsvc.NewControl(repository, cryptox.Generator{})
	return Module{
		Commands: service, Queries: service,
		GroupCommands: groups, GroupQueries: groups,
		ControlCommands: control,
		ControlQueries:  control,
		HTTP:            provhttp.New(service, service, provhttp.NewGroups(groups, groups)),
		Control:         provhttp.NewControl(control, control, deps.ActorID),
	}
}
