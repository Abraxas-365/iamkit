// Package samlmodule assembles the SAML identity provider.
package samlmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlpg"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/samlsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Keys sign responses (the environment's signing key).
	Keys signing.Keyring
	// Issuer is IAMKit's public base URL; entity IDs and endpoints derive
	// from it.
	Issuer  string
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands samlidp.Commands
	Queries  samlidp.Queries
	Flows    samlidp.Flows
	HTTP     *samlhttp.Handler
}

func New(deps Deps) Module {
	service := samlsvc.New(samlpg.New(deps.DB), samlxml.New(deps.Keys, deps.Issuer), mgmtsecret.Generator{})
	return Module{Commands: service, Queries: service, Flows: service, HTTP: samlhttp.New(service, service, service, deps.ActorID)}
}
