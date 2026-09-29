// Package bootstrap is the composition root. Only here are concrete application
// services wired to persistence, cryptography and HTTP adapters.
package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/console"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/application/appmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhibp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/authzmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/fedmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/hostedmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/impmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/invmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtpg"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/mfamodule"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/orgmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/provmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/sacctmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/usermodule"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// Option customizes New; production callers pass none.
type Option func(*options)

// invitations joins the invitation use cases the hosted accept page needs.
type invitations struct {
	invitation.Commands
	invitation.Queries
}

type options struct {
	resolver  organization.Resolver
	sealer    *cryptox.Sealer
	transport http.RoundTripper
	mail      authmodule.Mail
	sso       *OperatorSSO
	breaches  authentication.Breaches
	noBreach  bool
}

// WithBreaches replaces the Have I Been Pwned breach check (nil disables
// it), so tests never reach the internet.
func WithBreaches(b authentication.Breaches) Option {
	return func(o *options) { o.breaches, o.noBreach = b, b == nil }
}

// WithResolver replaces the system DNS resolver used for domain verification.
func WithResolver(r organization.Resolver) Option { return func(o *options) { o.resolver = r } }

// WithSealer sets the encryption for secrets at rest; without it, storing
// secrets is refused.
func WithSealer(s *cryptox.Sealer) Option { return func(o *options) { o.sealer = s } }

// WithFederationTransport replaces the guarded transport used to reach
// identity providers of sealed-secret connections, so tests can reach a
// provider on a loopback address.
func WithFederationTransport(t http.RoundTripper) Option {
	return func(o *options) { o.transport = t }
}

func New(db *sqlx.DB, key *rsa.PrivateKey, issuer string, delivery authentication.Delivery, opts ...Option) *server.Server {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.sealer == nil {
		o.sealer = &cryptox.Sealer{}
	}
	if o.breaches == nil && !o.noBreach {
		o.breaches = authhibp.Breaches{}
	}
	managementDeps := mgmtmodule.Deps{DB: db}
	if o.sso != nil {
		managementDeps.SSO = &mgmtmodule.SSO{Settings: o.sso.Settings, Provider: newOperatorIdP(issuer, *o.sso)}
	}
	managementModule := mgmtmodule.New(managementDeps)
	s := &server.Server{Control: managementModule.HTTP, OperatorSSO: managementModule.SSOHTTP, Health: db.PingContext}
	// Built before authentication (its second factor); tokens are bound late.
	mfaModule := mfamodule.New(mfamodule.Deps{DB: db, Cipher: o.sealer, ActorID: server.OperatorID, Validate: func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
		return s.Tokens.Validate(c, environment, audience)
	}})
	s.Factors = mfaModule.HTTP
	authenticationModule := authmodule.New(authmodule.Deps{DB: db, Key: key, Issuer: issuer, Delivery: delivery, OAuthTokens: oauthfosite.AccessTokens{DB: db}, IssueSession: s.IssueSession, SecondFactor: mfaModule.SecondFactor, Cipher: o.sealer, Breaches: o.breaches, ActorID: server.OperatorID, Mail: o.mail})
	s.Tokens = authenticationModule.Tokens
	s.Auth = authenticationModule.HTTP
	s.PasswordPolicy = authenticationModule.PasswordPoliciesHTTP
	s.Delivery = authhttp.NewDeliveryHandler(authenticationModule.DeliveryService, authenticationModule.DeliveryService, server.OperatorID).
		Templates(authenticationModule.DeliveryService, authenticationModule.DeliveryService)
	userModule := usermodule.New(usermodule.Deps{DB: db, ActorID: server.OperatorID, PasswordPolicy: authenticationModule.PasswordPolicies})
	s.Users = userModule.HTTP
	organizationModule := orgmodule.New(orgmodule.Deps{DB: db, ActorID: server.OperatorID, Resolver: o.resolver})
	s.Structure = organizationModule.Structure
	s.Groups = organizationModule.Groups
	s.Domains = organizationModule.Domains
	s.Organizations = organizationModule.HTTP
	invitationModule := invmodule.New(invmodule.Deps{DB: db, Delivery: authenticationModule.DeliveryService, ActorID: server.OperatorID, PasswordPolicy: authenticationModule.PasswordPolicies})
	s.Invitations = invitationModule.HTTP
	authorizationModule := authzmodule.New(authzmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Grants = authorizationModule.Grants
	s.Authorization = authorizationModule.HTTP
	federationModule := fedmodule.New(fedmodule.Deps{DB: db, Issuer: issuer, Cipher: o.sealer, Transport: o.transport, Sessions: authenticationModule.Sessions, ActorID: server.OperatorID, Respond: s.RespondLogin})
	s.Federation = federationModule.HTTP
	provisioningModule := provmodule.New(provmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.ProvisioningControl = provisioningModule.Control
	s.Provisioning = provisioningModule.HTTP
	applicationModule := appmodule.New(appmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Applications = applicationModule.HTTP
	oauthModule := oauthmodule.New(oauthmodule.Deps{DB: db, Key: key, Issuer: issuer, HMACSecret: func() string { return os.Getenv("OIDC_HMAC_SECRET") }, Tokens: s.Tokens, ActorID: server.OperatorID})
	s.OAuth = oauthModule.HTTP
	hostedModule := hostedmodule.New(hostedmodule.Deps{DB: db, Authorizations: oauthModule.Flows, Authenticator: authenticationModule.Authenticator, Challenges: authenticationModule.Commands, Federation: federationModule.Flows, Invitations: invitations{invitationModule.Commands, invitationModule.Queries}, SecondFactor: mfaModule.Logins, Finish: oauthModule.HTTP.Finish, ActorID: server.OperatorID})
	s.Hosted = hostedModule.HTTP
	federationModule.HTTP.Continue(hostedModule.HTTP.Federated)
	// Rendered emails wear the environment's hosted login branding.
	authenticationModule.Brand(branding{hostedModule.Queries})
	serviceAccountModule := sacctmodule.New(sacctmodule.Deps{DB: db})
	s.ServiceAccounts = serviceAccountModule.HTTP
	s.Activity = managementModule.Activity
	impersonationModule := impmodule.New(impmodule.Deps{DB: db, Tokens: s.Tokens})
	s.Impersonation = impersonationModule.HTTP

	// /api/v1/* route group — JWT auth with scoped permissions.
	s.API = apiauth.New(authenticationModule.Validator)
	actor := apiauth.ActorID
	s.APIHandlers = server.APIHandlerSet{
		Users:           userhttp.New(userModule.Commands, userModule.Queries, actor),
		Organizations:   orghttp.New(organizationModule.Commands, organizationModule.Queries, actor),
		Structure:       orghttp.NewStructure(organizationModule.StructureCommands, organizationModule.StructureQueries, actor),
		Groups:          orghttp.NewGroups(organizationModule.GroupCommands, organizationModule.GroupQueries, actor),
		Domains:         orghttp.NewDomains(organizationModule.DomainCommands, organizationModule.DomainQueries, actor),
		Invitations:     invhttp.New(invitationModule.Commands, invitationModule.Queries, actor),
		Applications:    apphttp.New(applicationModule.Commands, applicationModule.Queries, actor),
		Authorization:   authzhttp.New(authorizationModule.ResourceCommands, authorizationModule.ResourceQueries, actor),
		Grants:          authzhttp.NewGrants(authorizationModule.GrantCommands, authorizationModule.GrantQueries, actor),
		ServiceAccounts: saccthttp.New(serviceAccountModule.Commands, serviceAccountModule.Queries),
		Factors:         mfaModule.HTTP.WithActor(actor),
		Delivery: authhttp.NewDeliveryHandler(authenticationModule.DeliveryService, authenticationModule.DeliveryService, actor).
			Templates(authenticationModule.DeliveryService, authenticationModule.DeliveryService),
	}
	return s
}
func Management(db *sqlx.DB) *mgmtsvc.Service {
	repo := mgmtpg.New(db)
	return mgmtsvc.New(repo, repo, mgmtsecret.Generator{}, nil)
}

// ManagementWithPasswords returns a management service that can also set
// passwords. Used by the auto-bootstrap flow where IAMKIT_BOOTSTRAP_PASSWORD
// is set.
func ManagementWithPasswords(db *sqlx.DB) *mgmtsvc.Service {
	repo := mgmtpg.New(db)
	return mgmtsvc.New(repo, repo, mgmtsecret.Generator{}, mgmtbcrypt.Hasher{})
}
func OpenDatabase() (*sqlx.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errx.Validation("DATABASE_URL is required")
	}
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, errx.Wrap(err, "database connection failed", errx.TypeInternal)
	}
	return db, nil
}
func FromEnvironment(db *sqlx.DB) (*server.Server, error) {
	issuer := os.Getenv("JWT_ISSUER")
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return nil, errx.Validation("JWT_ISSUER must be an HTTPS URL (HTTP allowed only on loopback)")
	}
	data, err := os.ReadFile(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if err != nil {
		return nil, errx.Wrap(err, "read signing key failed", errx.TypeInternal)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errx.Validation("invalid signing key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, errx.Wrap(e, "invalid signing key", errx.TypeValidation)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errx.Validation("RSA signing key required")
		}
	}
	if key.N.BitLen() < 2048 {
		return nil, errx.Validation("RSA key must be at least 2048 bits")
	}
	delivery, mail, err := mailFromEnv()
	if err != nil {
		return nil, err
	}
	sealer, err := cryptox.Parse(os.Getenv("IAMKIT_ENCRYPTION_KEY"), os.Getenv("IAMKIT_ENCRYPTION_KEYS_OLD"))
	if err != nil {
		return nil, err
	}
	sso, err := operatorSSOFromEnv()
	if err != nil {
		return nil, err
	}
	if len(sso.Settings.Providers) > 0 && u.Scheme != "https" {
		// Identity providers only redirect to HTTPS callbacks.
		return nil, errx.Validation("operator SSO requires an HTTPS JWT_ISSUER")
	}
	s := New(db, key, strings.TrimSuffix(issuer, "/"), delivery, WithSealer(sealer), WithMail(mail), WithOperatorSSO(sso))
	s.AllowedOrigins = os.Getenv("CORS_ALLOWED_ORIGINS")
	if v := os.Getenv("RATE_LIMIT_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.RateLimitPerMinute = n
		}
	}
	s.Console = console.Assets()
	return s, nil
}
func GenerateKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
