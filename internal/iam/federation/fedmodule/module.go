// Package fedmodule assembles federation use cases and HTTP adapter.
package fedmodule

import (
	"net/http"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedldap"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedoidc"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/fedsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB     *sqlx.DB
	Issuer string
	Cipher federation.Cipher
	// Keys signs SAML requests and decrypts SAML assertions (the
	// environment's active signing key).
	Keys signing.Keyring
	// Transport, when set, replaces the guarded transport for sealed-secret
	// connections (tests with a loopback provider).
	Transport http.RoundTripper
	// LDAPAllowed lists directory hosts (host or host:port) reachable on
	// private networks (IAMKIT_LDAP_ALLOWED_HOSTS); LDAPDial, when set,
	// replaces the dialer for every directory (tests).
	LDAPAllowed []string
	LDAPDial    fedldap.Dialer
	Sessions    federation.Sessions
	ActorID     func(*fiber.Ctx) string
	// Respond answers a headless login: tokens or the mfa_required body.
	Respond func(*fiber.Ctx, authentication.Result) error
}
type Module struct {
	Commands federation.Commands
	Flows    federation.Flows
	HTTP     *fedhttp.Handler
}

func New(deps Deps) Module {
	provider := router{
		oidc: fedoidc.Provider{Issuer: deps.Issuer, Cipher: deps.Cipher, Guarded: deps.Transport},
		saml: fedsaml.New(deps.Issuer, deps.Keys, deps.Transport),
	}
	directory := fedldap.New(deps.Cipher, deps.LDAPAllowed, deps.LDAPDial)
	service := fedsvc.New(fedpg.New(deps.DB), provider, directory, deps.Cipher, mgmtsecret.Generator{}, deps.Sessions, deps.Issuer)
	return Module{Commands: service, Flows: service, HTTP: fedhttp.New(service, service, service, deps.ActorID, deps.Respond)}
}
