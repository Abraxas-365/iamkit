// Package oauthmodule assembles OAuth use cases, Fosite provider factory and HTTP adapter.
package oauthmodule

import (
	"crypto/rsa"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

type Deps struct {
	DB         *sqlx.DB
	Key        *rsa.PrivateKey
	Issuer     string
	HMACSecret func() string
	Tokens     *authhttp.Tokens
	ActorID    func(*fiber.Ctx) string
}
type Module struct {
	Commands oauth.Commands
	Flows    oauth.Flows
	HTTP     *oauthhttp.Handler
}

func New(deps Deps) Module {
	clients := oauthpg.New(deps.DB)
	service := oauthsvc.New(clients, mgmtsecret.Generator{}, authbcrypt.Hasher{})
	provider := func(client *oauth.Client) (fosite.OAuth2Provider, *oauthfosite.Store, error) {
		store := &oauthfosite.Store{DB: deps.DB, Environment: client.Environment, Clients: clients}
		p, err := oauthfosite.NewProvider(store, deps.Issuer, []byte(deps.HMACSecret()), deps.Key)
		return p, store, err
	}
	return Module{Commands: service, Flows: service, HTTP: oauthhttp.New(service, service, provider, deps.Tokens, deps.Issuer, deps.ActorID)}
}
