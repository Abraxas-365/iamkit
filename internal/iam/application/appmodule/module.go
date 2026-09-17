// Package appmodule assembles the application module's concrete adapters.
// It is imported only by the composition root and module integration tests.
package appmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apppg"
	"github.com/Abraxas-365/iamkit/internal/iam/application/appsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands application.Commands
	Queries  application.Queries
	HTTP     *apphttp.Handler
}

func New(deps Deps) Module {
	service := appsvc.New(apppg.New(deps.DB))
	return Module{
		Commands: service,
		Queries:  service,
		HTTP:     apphttp.New(service, service, deps.ActorID),
	}
}
