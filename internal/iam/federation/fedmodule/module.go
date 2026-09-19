// Package fedmodule assembles federation use cases and HTTP adapter.
package fedmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedoidc"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/fedsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB           *sqlx.DB
	Issuer       string
	Sessions     authentication.SessionCreator
	ActorID      func(*fiber.Ctx) string
	IssueSession func(*fiber.Ctx, authentication.Issued) error
}
type Module struct {
	Commands federation.Commands
	Flows    federation.Flows
	HTTP     *fedhttp.Handler
}

func New(deps Deps) Module {
	service := fedsvc.New(fedpg.New(deps.DB), fedoidc.Provider{Issuer: deps.Issuer}, mgmtsecret.Generator{}, deps.Sessions, deps.Issuer)
	return Module{Commands: service, Flows: service, HTTP: fedhttp.New(service, service, service, deps.ActorID, deps.IssueSession)}
}
