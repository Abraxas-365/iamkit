// Package provmodule assembles SCIM provisioning and its management controls.
package provmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
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
}
type Module struct {
	Commands        provisioning.Commands
	Queries         provisioning.Queries
	ControlCommands provisioning.ControlCommands
	HTTP            *provhttp.Handler
	Control         *provhttp.Control
}

func New(deps Deps) Module {
	repository := provpg.New(deps.DB)
	service := provsvc.New(repository, mgmtsecret.Generator{})
	control := provsvc.NewControl(repository, mgmtsecret.Generator{})
	return Module{Commands: service, Queries: service, ControlCommands: control, HTTP: provhttp.New(service, service), Control: provhttp.NewControl(control, deps.ActorID)}
}
