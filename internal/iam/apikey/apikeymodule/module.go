// Package apikeymodule assembles the API key adapters. It is imported only
// by the composition root.
package apikeymodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey/adapters/apikeyhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey/adapters/apikeypg"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey/apikeysvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	Secrets apikey.Secrets
	// ActorID names the operator behind a management change.
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands apikey.Commands
	Queries  apikey.Queries
	HTTP     *apikeyhttp.Handler
}

// Self builds the self-service handler once the token validator exists.
func (m Module) Self(validate apikeyhttp.Validate) *apikeyhttp.Self {
	return apikeyhttp.NewSelf(m.Commands, m.Queries, validate)
}

func New(deps Deps) Module {
	service := apikeysvc.New(apikeypg.New(deps.DB), deps.Secrets)
	return Module{Commands: service, Queries: service, HTTP: apikeyhttp.New(service, service, deps.ActorID)}
}
