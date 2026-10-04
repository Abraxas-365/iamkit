// Package bootstrap is the composition root. Only here are concrete application
// services wired to persistence, cryptography and HTTP adapters.
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/cache/cacheredis"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagememory"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/console"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action/actionmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/application/adapters/apphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/application/appmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhibp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/adapters/authzhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/authzmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/event/eventmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/featuremodule"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedldap"
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
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/adapters/orgadminhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/orgadminmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/adapters/orghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/orgmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/provmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/samlmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/sacctmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/signingmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/usagemodule"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/usermodule"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/XSAM/otelsql"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
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
	origins   []string
	ldapDial  fedldap.Dialer
	retention time.Duration
	webhooks  http.RoundTripper
	actions   http.RoundTripper
	features  feature.Deployment
	limits    usage.Values
	redis     *cacheredis.Client
}

// WithRedis shares rate limits, per-minute limits and hot-read caches
// (feature overrides, action bindings, OIDC discovery) between replicas
// through Redis (REDIS_URL). The caller closes the client.
func WithRedis(c *cacheredis.Client) Option { return func(o *options) { o.redis = c } }

// WithLimits sets the deployment's limit caps (IAMKIT_LIMITS).
func WithLimits(v usage.Values) Option { return func(o *options) { o.limits = v } }

// WithFeatures sets the deployment's feature flag values (IAMKIT_FEATURES).
func WithFeatures(d feature.Deployment) Option { return func(o *options) { o.features = d } }

// WithActionTransport replaces the guarded transport action targets are
// called through (tests with a loopback receiver; IAMKIT_ALLOW_PRIVATE_DELIVERY).
func WithActionTransport(t http.RoundTripper) Option {
	return func(o *options) { o.actions = t }
}

// WithWebhookTransport replaces the guarded transport event webhooks are
// sent through (tests with a loopback receiver; IAMKIT_ALLOW_PRIVATE_DELIVERY).
func WithWebhookTransport(t http.RoundTripper) Option {
	return func(o *options) { o.webhooks = t }
}

// WithEventRetention sets how long the event log keeps events
// (IAMKIT_EVENT_RETENTION, default config.EventRetention).
func WithEventRetention(d time.Duration) Option { return func(o *options) { o.retention = d } }

// WithLDAPDialer replaces how LDAP directories are dialed (tests with a
// loopback directory); production dials through the guarded dialer or
// IAMKIT_LDAP_ALLOWED_HOSTS.
func WithLDAPDialer(d fedldap.Dialer) Option { return func(o *options) { o.ldapDial = d } }

// WithWebAuthnOrigins adds origins (besides the issuer's) that may run
// security key and passkey ceremonies: custom sign-in UIs on subdomains of
// the issuer host (IAMKIT_WEBAUTHN_ORIGINS, comma-separated).
func WithWebAuthnOrigins(origins []string) Option { return func(o *options) { o.origins = origins } }

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
// identity providers of sealed-secret connections and clients' jwks_uri
// (private_key_jwt), so tests can reach them on a loopback address.
func WithFederationTransport(t http.RoundTripper) Option {
	return func(o *options) { o.transport = t }
}

func New(db *sqlx.DB, key *rsa.PrivateKey, issuer string, delivery authentication.Delivery, opts ...Option) *server.Server {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.retention <= 0 {
		o.retention = config.EventRetention
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
	signingModule := signingmodule.New(signingmodule.Deps{DB: db, Key: key, Cipher: o.sealer, Sealing: o.sealer.Enabled, ActorID: server.OperatorID})
	s.SigningKeys = signingModule.HTTP
	// Built before authentication (its second factor); tokens are bound late.
	mfaModule := mfamodule.New(mfamodule.Deps{DB: db, Cipher: o.sealer, ActorID: server.OperatorID, Issuer: issuer, Origins: o.origins, Validate: func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
		return s.Tokens.Validate(c, environment, audience)
	}})
	s.Factors = mfaModule.HTTP
	// Without Redis nothing is cached: every replica reads the database.
	var shared cache.Store
	var window usage.Window
	if o.redis != nil {
		shared = o.redis.Store()
		window = o.redis.Window(usagememory.New())
		s.LimitStorage = o.redis.Storage()
		s.Cache = o.redis.Ping
	}
	featureModule := featuremodule.New(featuremodule.Deps{DB: db, Deployment: o.features, Cache: shared, ActorID: server.OperatorID})
	s.Features = featureModule.HTTP
	// Limits and usage: consulted on creates, sends, API requests and
	// action calls; counters flushed by Server.Start.
	usageModule := usagemodule.New(usagemodule.Deps{DB: db, Deployment: o.limits, Window: window, ActorID: server.OperatorID, Owner: server.Owner})
	s.Limits = usageModule.HTTP
	s.Meter = usageModule.Meter
	s.FlushUsage = usageModule.Commands.Flush
	// Actions (synchronous hooks) are consulted by authentication,
	// federation, OAuth, users and organizations.
	actionModule := actionmodule.New(actionmodule.Deps{DB: db, Cipher: o.sealer, Transport: o.actions, Features: featureModule.Queries, Usage: usageModule.Commands, Cache: shared, ActorID: server.OperatorID})
	s.Actions = actionModule.HTTP
	authenticationModule := authmodule.New(authmodule.Deps{DB: db, Actions: actionModule.Runner, Usage: usageModule.Commands, Keys: signingModule.Keyring, Issuer: issuer, Delivery: delivery, OAuthTokens: oauthfosite.AccessTokens{DB: db}, IssueSession: s.IssueSession, SecondFactor: mfaModule.SecondFactor, Passkeys: mfaModule.Passkeys, Cipher: o.sealer, Breaches: o.breaches, ActorID: server.OperatorID, Mail: o.mail})
	s.Tokens = authenticationModule.Tokens
	s.WaitDeliveries = authenticationModule.WaitDeliveries
	s.Auth = authenticationModule.HTTP
	s.PasswordPolicy = authenticationModule.PasswordPoliciesHTTP
	s.SignInPolicy = authenticationModule.SignInPoliciesHTTP
	s.Signup = authenticationModule.SignupHTTP
	s.Delivery = authhttp.NewDeliveryHandler(authenticationModule.DeliveryService, authenticationModule.DeliveryService, server.OperatorID).
		Templates(authenticationModule.DeliveryService, authenticationModule.DeliveryService)
	s.SMS = authenticationModule.SMSHTTP
	mfaModule.Deliver(authenticationModule.DeliveryService, authenticationModule.SMS)
	userModule := usermodule.New(usermodule.Deps{DB: db, Actions: actionModule.Runner, Quota: usageModule.Commands, ActorID: server.OperatorID, PasswordPolicy: authenticationModule.PasswordPolicies, SMS: authenticationModule.SMS})
	s.Users = userModule.HTTP
	s.AccessTokens = userModule.AccessTokens
	s.UserKeys = userModule.Keys
	s.Users.SetValidate(func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
		return s.Tokens.Validate(c, environment, audience)
	})
	organizationModule := orgmodule.New(orgmodule.Deps{DB: db, Actions: actionModule.Runner, Quota: usageModule.Commands, ActorID: server.OperatorID, Resolver: o.resolver})
	s.Structure = organizationModule.Structure
	s.Groups = organizationModule.Groups
	s.Domains = organizationModule.Domains
	s.Organizations = organizationModule.HTTP
	invitationModule := invmodule.New(invmodule.Deps{DB: db, Delivery: authenticationModule.DeliveryService, Quota: usageModule.Commands, ActorID: server.OperatorID, PasswordPolicy: authenticationModule.PasswordPolicies})
	s.Invitations = invitationModule.HTTP
	authorizationModule := authzmodule.New(authzmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Grants = authorizationModule.Grants
	s.Authorization = authorizationModule.HTTP
	s.ResourceGrants = authorizationModule.ResourceGrants
	federationModule := fedmodule.New(fedmodule.Deps{DB: db, Issuer: issuer, Cipher: o.sealer, Keys: signingModule.Keyring, Transport: o.transport, LDAPAllowed: list(os.Getenv("IAMKIT_LDAP_ALLOWED_HOSTS")), LDAPDial: o.ldapDial, Sessions: authenticationModule.Sessions, Actions: actionModule.Runner, Quota: usageModule.Commands, Discovery: shared, ActorID: server.OperatorID, Respond: s.RespondLogin})
	s.Federation = federationModule.HTTP
	provisioningModule := provmodule.New(provmodule.Deps{DB: db, Quota: usageModule.Commands, ActorID: server.OperatorID})
	s.ProvisioningControl = provisioningModule.Control
	s.Provisioning = provisioningModule.HTTP
	applicationModule := appmodule.New(appmodule.Deps{DB: db, Quota: usageModule.Commands, ActorID: server.OperatorID})
	s.Applications = applicationModule.HTTP
	oauthModule := oauthmodule.New(oauthmodule.Deps{DB: db, Keys: signingModule.Keyring, Issuer: issuer, HMACSecret: func() string { return os.Getenv("OIDC_HMAC_SECRET") }, Transport: o.transport, Tokens: s.Tokens, ActorID: server.OperatorID})
	s.OAuth = oauthModule.HTTP
	s.ClientOrigins = oauthModule.Queries
	s.LogoutDeliveries = oauthModule.Logouts
	s.LogoutDispatcher = oauthModule.Dispatcher
	eventModule := eventmodule.New(eventmodule.Deps{DB: db, Retention: o.retention, Cipher: o.sealer, Transport: o.webhooks, ActorID: server.OperatorID})
	s.Events = eventModule.HTTP
	s.Webhooks = eventModule.Webhooks
	s.WebhookDispatcher = eventModule.Dispatcher
	s.Workers = &worker.Runner{}
	s.Workers.Add(oauthModule.Jobs...)
	s.Workers.Add(eventModule.Jobs...)
	s.Workers.Add(actionModule.Jobs...)
	s.Workers.Add(usageModule.Jobs...)
	samlModule := samlmodule.New(samlmodule.Deps{DB: db, Keys: signingModule.Keyring, Issuer: issuer, ActorID: server.OperatorID})
	if on, ok := o.features[config.FeatureSAMLIdP]; !ok || on {
		s.SAML = samlModule.HTTP
	}
	hostedModule := hostedmodule.New(hostedmodule.Deps{DB: db, Authorizations: tickets{oauth: oauthModule.Flows, saml: samlModule.Flows}, Authenticator: authenticationModule.Authenticator, Challenges: authenticationModule.Commands, Federation: federationModule.Flows, Invitations: invitations{invitationModule.Commands, invitationModule.Queries}, SecondFactor: mfaModule.Logins, SignInPolicies: authenticationModule.SignInPolicies, Signups: authenticationModule.Signups, Passkeys: authenticationModule.Passkeys, Features: featureModule.Queries, Finish: finisher(oauthModule.HTTP.Finish, samlModule.HTTP), ActorID: server.OperatorID})
	s.Hosted = hostedModule.HTTP
	samlModule.HTTP.PostForm(hostedModule.HTTP.PostForm)
	federationModule.HTTP.Continue(hostedModule.HTTP.Federated)
	oauthModule.HTTP.SignedOut(hostedModule.HTTP.SignedOut)
	oauthModule.HTTP.ProfileClaims(userModule.Queries)
	oauthModule.HTTP.Actions(actionModule.Runner)
	oauthModule.HTTP.Usage(usageModule.Commands)
	// Device authorization grant: devices poll /oauth/token, users approve
	// at /hosted/device through the ordinary hosted login.
	hostedModule.HTTP.Devices(oauthModule.Devices)
	oauthModule.HTTP.Devices(oauthModule.Devices, hostedModule.HTTP.DeviceApproved)
	// Rendered emails wear the environment's hosted login branding.
	authenticationModule.Brand(branding{hostedModule.Queries})
	serviceAccountModule := sacctmodule.New(sacctmodule.Deps{DB: db, ActorID: server.OperatorID, Owner: server.Owner})
	s.ServiceAccounts = serviceAccountModule.HTTP
	s.Activity = managementModule.Activity
	impersonationModule := impmodule.New(impmodule.Deps{DB: db, Tokens: s.Tokens})
	s.Impersonation = impersonationModule.HTTP

	// /api/v1/* route group — JWT auth with scoped permissions.
	s.API = apiauth.New(authenticationModule.Validator)
	actor := apiauth.ActorID
	orgAdmin := orgadminmodule.New(orgadminmodule.Deps{
		DB: db, Caller: orgAdminCaller, Issuer: issuer, ActorID: server.OperatorID,
		Users: userModule.Commands, UserQueries: userModule.Queries,
		Organizations: organizationModule.Commands, OrganizationViews: organizationModule.Queries,
		Domains: organizationModule.DomainCommands, DomainViews: organizationModule.DomainQueries,
		Grants: authorizationModule.GrantCommands, GrantViews: authorizationModule.GrantQueries,
		ResourceViews: authorizationModule.ResourceQueries, ResourceGrants: authorizationModule.ResourceGrantCommands,
		ResourceGrantViews: authorizationModule.ResourceGrantQueries,
		Invitations:        invitationModule.Commands, InvitationViews: invitationModule.Queries,
		Connections: federationModule.Commands, ConnectionViews: federationModule.Queries,
		Branding: hostedModule.Commands, BrandingViews: hostedModule.Queries,
		PasswordPolicies: authenticationModule.PasswordPolicyCommands, PasswordPolicyViews: authenticationModule.PasswordPolicies,
	})
	s.APIHandlers = server.APIHandlerSet{
		Users:           userhttp.New(userModule.Commands, userModule.Queries, actor),
		AccessTokens:    userhttp.NewAccessTokens(userModule.AccessTokenCommands, userModule.AccessTokenQueries, actor),
		UserKeys:        userhttp.NewKeys(userModule.KeyCommands, userModule.KeyQueries, actor),
		Organizations:   orghttp.New(organizationModule.Commands, organizationModule.Queries, actor),
		Structure:       orghttp.NewStructure(organizationModule.StructureCommands, organizationModule.StructureQueries, actor),
		Groups:          orghttp.NewGroups(organizationModule.GroupCommands, organizationModule.GroupQueries, actor),
		Domains:         orghttp.NewDomains(organizationModule.DomainCommands, organizationModule.DomainQueries, actor),
		Invitations:     invhttp.New(invitationModule.Commands, invitationModule.Queries, actor),
		Applications:    apphttp.New(applicationModule.Commands, applicationModule.Queries, actor),
		Authorization:   authzhttp.New(authorizationModule.ResourceCommands, authorizationModule.ResourceQueries, actor),
		Grants:          authzhttp.NewGrants(authorizationModule.GrantCommands, authorizationModule.GrantQueries, actor),
		ResourceGrants:  authzhttp.NewResourceGrants(authorizationModule.ResourceGrantCommands, authorizationModule.ResourceGrantQueries, actor),
		ServiceAccounts: saccthttp.New(serviceAccountModule.Commands, serviceAccountModule.Queries, actor, nil),
		Factors:         mfaModule.HTTP.WithActor(actor),
		Delivery: authhttp.NewDeliveryHandler(authenticationModule.DeliveryService, authenticationModule.DeliveryService, actor).
			Templates(authenticationModule.DeliveryService, authenticationModule.DeliveryService),
		SMS:      authhttp.NewSMSHandler(authenticationModule.SMS, authenticationModule.SMSQueries, actor),
		OrgAdmin: orgAdmin.HTTP,
		Events:   eventModule.HTTP,
		Webhooks: eventModule.Webhooks.WithActor(actor),
		Usage:    usageModule.HTTP,
	}
	s.OrgAdminPortal = orgAdmin.PortalHTTP
	return s
}

// orgAdminCaller is the end user behind an /api/v1 token. Impersonated
// tokens administer nothing: the audit trail would name the user.
func orgAdminCaller(c *fiber.Ctx) orgadminhttp.Caller {
	t := apiauth.Token(c)
	if t.Impersonated() {
		return orgadminhttp.Caller{}
	}
	return orgadminhttp.Caller{User: t.Subject, Organization: t.OrganizationID, Permissions: t.Permissions}
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

// OpenDatabase connects to DATABASE_URL through an OpenTelemetry-wrapped
// driver: queries become spans (statement text only — values are bound
// parameters) and pool statistics become metrics, both no-ops until
// telemetry.Setup installs providers.
func OpenDatabase() (*sqlx.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errx.Validation("DATABASE_URL is required")
	}
	system := otelsql.WithAttributes(semconv.DBSystemNamePostgreSQL)
	raw, err := otelsql.Open("postgres", dsn, system, otelsql.WithSpanOptions(otelsql.SpanOptions{OmitConnResetSession: true, OmitRows: true}))
	if err != nil {
		return nil, errx.Wrap(err, "database connection failed", errx.TypeInternal)
	}
	db := sqlx.NewDb(raw, "postgres")
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, errx.Wrap(err, "database connection failed", errx.TypeInternal)
	}
	if _, err = otelsql.RegisterDBStatsMetrics(raw, system); err != nil {
		db.Close()
		return nil, errx.Wrap(err, "database metrics failed", errx.TypeInternal)
	}
	return db, nil
}
func FromEnvironment(db *sqlx.DB) (*server.Server, error) {
	issuer := os.Getenv("JWT_ISSUER")
	if err := identity.ValidateIssuer(issuer); err != nil {
		return nil, errx.Wrap(err, "invalid JWT_ISSUER", errx.TypeValidation)
	}
	u, _ := url.Parse(issuer) // validated above
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
	retention := config.EventRetention
	if v := os.Getenv("IAMKIT_EVENT_RETENTION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Hour {
			return nil, errx.Validation("IAMKIT_EVENT_RETENTION must be a duration of at least 1h (e.g. 2160h)")
		}
		retention = d
	}
	features, unknown, err := feature.ParseDeployment(os.Getenv("IAMKIT_FEATURES"))
	if err != nil {
		return nil, err
	}
	if len(unknown) > 0 {
		slog.Warn("IAMKIT_FEATURES names unknown features (ignored)", "names", unknown)
	}
	limits, err := usage.ParseDeployment(os.Getenv("IAMKIT_LIMITS"))
	if err != nil {
		return nil, err
	}
	proxies, err := trustedProxies(os.Getenv("IAMKIT_TRUSTED_PROXIES"))
	if err != nil {
		return nil, err
	}
	opts := []Option{WithSealer(sealer), WithMail(mail), WithOperatorSSO(sso), WithWebAuthnOrigins(list(os.Getenv("IAMKIT_WEBAUTHN_ORIGINS"))), WithEventRetention(retention), WithFeatures(features), WithLimits(limits)}
	var redis *cacheredis.Client
	if v := os.Getenv("REDIS_URL"); v != "" {
		if redis, err = cacheredis.Open(context.Background(), v); err != nil {
			return nil, err
		}
		opts = append(opts, WithRedis(redis))
	}
	if mail.WebhookClient != nil {
		opts = append(opts, privateDelivery(mail.WebhookClient)...)
	}
	s := New(db, key, strings.TrimSuffix(issuer, "/"), delivery, opts...)
	if redis != nil {
		s.CloseCache = redis.Close
	}
	s.AllowedOrigins = os.Getenv("CORS_ALLOWED_ORIGINS")
	s.TrustedProxies = proxies
	if v := os.Getenv("RATE_LIMIT_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.RateLimitPerMinute = n
		}
	}
	s.Console = console.Assets()
	if v := os.Getenv("IAMKIT_WORKERS"); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errx.Validation("IAMKIT_WORKERS must be true or false")
		}
		s.Workers.Disabled = !on
	}
	return s, nil
}
func GenerateKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
