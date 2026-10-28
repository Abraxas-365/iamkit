// Package oauthmodule assembles OAuth use cases, Fosite provider factory and HTTP adapter.
package oauthmodule

import (
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthcimd"
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
	// Passwords hashes client secrets.
	Passwords oauth.Passwords
	// Transport reaches clients' jwks_uri and back-channel logout URIs
	// (nil: public addresses only).
	Transport http.RoundTripper
	// ClientMetadataTransport reaches Client ID Metadata Documents and
	// their jwks_uri (nil: public addresses only, no redirects).
	ClientMetadataTransport http.RoundTripper
	// Cache keeps fetched metadata documents and key sets across replicas
	// (REDIS_URL; nil: this process only).
	Cache cache.Store
	// Features gates client_id URLs per environment (feature.Queries; nil:
	// always on).
	Features oauth.Features
	// Tokens reads, signs and answers IAMKit's own bearer tokens
	// (authhttp.Tokens).
	Tokens  oauthhttp.Tokens
	ActorID func(*fiber.Ctx) string
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
	// ProtectedResources serves …/protected-resources and
	// …/protected-resource-policy.
	ProtectedResources *oauthhttp.ProtectedResources
}

func New(deps Deps) Module {
	clients := oauthpg.New(deps.DB)
	service := oauthsvc.New(clients, cryptox.Generator{}, deps.Passwords, oauthfosite.Hints{Keys: deps.Keys, Issuer: deps.Issuer})
	fetcher := oauthfosite.NewKeyFetcher(deps.Transport)
	documents := oauthcimd.New(deps.ClientMetadataTransport, deps.Cache)
	service.SetExternalClients(documents, deps.Features)
	provider := func(client *oauth.Client) (fosite.OAuth2Provider, *oauthfosite.Store, error) {
		store := &oauthfosite.Store{DB: deps.DB, Environment: client.Environment, Clients: clients, Bound: client}
		// An external client's keys are on its document's origin: the same
		// guarded, size-capped, cached reads as the document.
		var keys fosite.JWKSFetcherStrategy = fetcher
		if client.External() {
			keys = documents
		}
		p, err := oauthfosite.NewProvider(store, deps.Issuer, []byte(deps.HMACSecret()), deps.Keys, keys, client.AccessTokenFormat == oauth.TokenFormatOpaque)
		return p, store, err
	}
	handler := oauthhttp.New(service, service, service, provider, deps.Tokens, deps.Issuer, deps.ActorID)
	handler.Accounts(oauthfosite.NewAccounts(deps.DB, clients, deps.Issuer, fetcher))
	handler.Exchanges(service)
	logouts := oauthsvc.NewLogouts(clients, oauthfosite.NewLogoutSender(deps.Keys, deps.Issuer, deps.Transport))
	protected := oauthsvc.NewProtectedResources(oauthpg.NewProtectedResources(deps.DB))
	return Module{Commands: service, Queries: service, Flows: service, Devices: service, HTTP: handler, Logouts: oauthhttp.NewLogouts(logouts, logouts, deps.ActorID), Dispatcher: logouts,
		ProtectedResources: oauthhttp.NewProtectedResources(protected, protected, deps.ActorID), Jobs: []worker.Job{
			{Name: "logout_delivery", Interval: config.LogoutDispatchInterval, Run: logouts.DispatchRound, Lag: logouts.Lag},
			{Name: "logout_prune", Interval: time.Hour, Run: logouts.Prune},
		}}
}
