// Package samlmodule assembles the SAML identity provider.
package samlmodule

import (
	"context"
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlpg"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/samlsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/worker"
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
	// Transport sends back-channel logout (nil: public addresses only).
	Transport http.RoundTripper
}

type Module struct {
	Commands samlidp.Commands
	Queries  samlidp.Queries
	Flows    samlidp.Flows
	// Logouts is single logout (inbound requests, back-channel delivery).
	Logouts samlidp.LogoutFlows
	// Jobs are the back-channel logout background jobs.
	Jobs []worker.Job
	HTTP *samlhttp.Handler
}

func New(deps Deps) Module {
	repository := samlpg.New(deps.DB)
	protocol := samlxml.New(deps.Keys, deps.Issuer)
	service := samlsvc.New(repository, protocol, cryptox.Generator{})
	service.SetLogout(repository, protocol, samlxml.NewSender(deps.Transport))
	handler := samlhttp.New(service, service, service, deps.ActorID)
	handler.Logout(service)
	return Module{Commands: service, Queries: service, Flows: service, Logouts: service, HTTP: handler, Jobs: []worker.Job{
		{Name: "saml_logout_delivery", Interval: config.LogoutDispatchInterval, Run: service.DispatchLogouts},
		{Name: "saml_logout_prune", Interval: time.Hour, Run: func(ctx context.Context) (bool, error) { return false, service.PruneLogouts(ctx) }},
	}}
}
