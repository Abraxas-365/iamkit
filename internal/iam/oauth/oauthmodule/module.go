// Package oauthmodule assembles OAuth use cases, Fosite provider factory and HTTP adapter.
package oauthmodule

import (
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

type Deps struct {
	DB         *sqlx.DB
	Keys       signing.Keyring
	Issuer     string
	HMACSecret func() string
	// Transport reaches clients' jwks_uri and back-channel logout URIs
	// (nil: public addresses only).
	Transport http.RoundTripper
	Tokens    *authhttp.Tokens
	ActorID   func(*fiber.Ctx) string
}
type Module struct {
	// Logouts serves the back-channel logout delivery log.
	Logouts *oauthhttp.Logouts
	// Jobs are the back-channel logout background jobs (delivery, pruning).
	Jobs []worker.Job
	// Dispatcher sends one round now (tests).
	Dispatcher oauth.Dispatcher
	Commands   oauth.Commands
	// Queries reads clients (and their allowed origins, for CORS).
	Queries oauth.Queries
	Flows   oauth.Flows
	// Devices is the device authorization grant (the hosted module serves
	// its user side; wire oauthhttp.Handler.Devices to enable it).
	Devices oauth.Devices
	HTTP    *oauthhttp.Handler
}

func New(deps Deps) Module {
	clients := oauthpg.New(deps.DB)
	service := oauthsvc.New(clients, mgmtsecret.Generator{}, authbcrypt.Hasher{}, oauthfosite.Hints{Keys: deps.Keys, Issuer: deps.Issuer})
	fetcher := oauthfosite.NewKeyFetcher(deps.Transport)
	provider := func(client *oauth.Client) (fosite.OAuth2Provider, *oauthfosite.Store, error) {
		store := &oauthfosite.Store{DB: deps.DB, Environment: client.Environment, Clients: clients}
		p, err := oauthfosite.NewProvider(store, deps.Issuer, []byte(deps.HMACSecret()), deps.Keys, fetcher, client.AccessTokenFormat == oauth.TokenFormatOpaque)
		return p, store, err
	}
	handler := oauthhttp.New(service, service, service, provider, deps.Tokens, deps.Issuer, deps.ActorID)
	handler.Accounts(oauthfosite.NewAccounts(deps.DB, clients, deps.Issuer, fetcher))
	handler.Exchanges(service)
	logouts := oauthsvc.NewLogouts(clients, oauthfosite.NewLogoutSender(deps.Keys, deps.Issuer, deps.Transport))
	return Module{Commands: service, Queries: service, Flows: service, Devices: service, HTTP: handler, Logouts: oauthhttp.NewLogouts(logouts, logouts, deps.ActorID), Dispatcher: logouts, Jobs: []worker.Job{
		{Name: "logout_delivery", Interval: config.LogoutDispatchInterval, Run: logouts.DispatchRound, Lag: logouts.Lag},
		{Name: "logout_prune", Interval: time.Hour, Run: logouts.Prune},
	}}
}
