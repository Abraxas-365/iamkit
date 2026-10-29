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
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
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
	// Window counts document fetches per environment across replicas
	// (usage.Window; nil: not counted).
	Window usage.Window
	// MaxPending is how many pending external clients an environment keeps
	// (0: config.ClientMetadataMaxPending).
	MaxPending int
	// MaxRequestsPerUser and MaxRequestsPerOrganization cap a user's, and an
	// organization's, requests for pending clients (0: the config defaults).
	MaxRequestsPerUser, MaxRequestsPerOrganization int
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
	// Admissions serves what IT does with clients of metadata documents:
	// …/protected-resources/:id/clients, the allowlist and the presets.
	Admissions *oauthhttp.Admissions
}

func New(deps Deps) Module {
	clients := oauthpg.New(deps.DB)
	service := oauthsvc.New(clients, cryptox.Generator{}, deps.Passwords, oauthfosite.Hints{Keys: deps.Keys, Issuer: deps.Issuer})
	fetcher := oauthfosite.NewKeyFetcher(deps.Transport)
	// Registered clients' jwks_uri refetch limit is shared by the replicas
	// when a shared store exists (a nil Cache keeps it per process).
	if deps.Cache != nil {
		fetcher.Throttle(deps.Cache)
	}
	documents := oauthcimd.New(deps.ClientMetadataTransport, deps.Cache)
	// A nil Window leaves fetches uncounted (bootstrap always passes one).
	var fetches oauth.Throttle
	if deps.Window != nil {
		fetches = deps.Window
	}
	service.SetExternalClients(documents, deps.Features, fetches)
	service.SetPendingCap(deps.MaxPending)
	service.SetRequestCaps(deps.MaxRequestsPerUser, deps.MaxRequestsPerOrganization)
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
	handler.Offers(oauthsvc.NewCapabilities(clients, deps.Features, deps.Cache))
	logouts := oauthsvc.NewLogouts(clients, oauthfosite.NewLogoutSender(deps.Keys, deps.Issuer, deps.Transport))
	protected := oauthsvc.NewProtectedResources(oauthpg.NewProtectedResources(deps.DB))
	admissions := oauthsvc.NewAdmissions(oauthpg.NewAdmission(deps.DB), deps.Features)
	return Module{Commands: service, Queries: service, Flows: service, Devices: service, HTTP: handler, Logouts: oauthhttp.NewLogouts(logouts, logouts, deps.ActorID), Dispatcher: logouts,
		ProtectedResources: oauthhttp.NewProtectedResources(protected, protected, deps.ActorID), Admissions: oauthhttp.NewAdmissions(admissions, admissions, deps.ActorID), Jobs: []worker.Job{
			{Name: "logout_delivery", Interval: config.LogoutDispatchInterval, Run: logouts.DispatchRound, Lag: logouts.Lag},
			{Name: "logout_prune", Interval: time.Hour, Run: logouts.Prune},
			// Check-at-use (Client.Admitted) already refuses an expired
			// approval; this job revokes the client's tokens and sessions
			// eagerly and records oauth_client.expired.
			{Name: "client_admission_expire", Interval: config.ClientExpireInterval, Run: admissions.ExpireApprovals},
			// The client_metadata_documents feature belongs to another
			// module: when it is off, approvals are taken back here
			// (the check at use is immediate; Client.Disabled).
			{Name: "client_documents_reconcile", Interval: config.ClientExpireInterval, Run: admissions.ReconcileDocuments},
			{Name: "client_pending_prune", Interval: time.Hour, Run: service.PruneExternal},
		}}
}
