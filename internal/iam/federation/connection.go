package federation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Enforcement values. An enforced organization connection makes SSO the only
// login method for emails on the organization's verified domains.
const (
	EnforcementOptional = "optional"
	EnforcementEnforced = "enforced"
)

// MaxClientSecret bounds a stored IdP client secret.
const MaxClientSecret = 4096

var secretName = regexp.MustCompile(`^IAMKIT_PROVIDER_[A-Z0-9_]+$`)

// Connection is an external OIDC provider. Organization is zero for a legacy
// environment-wide connection. The client secret is either a reference to an
// approved deployment variable (SecretEnv) or stored encrypted (Sealed).
type Connection struct {
	ID           identity.ConnectionID   `db:"id"`
	Environment  identity.EnvironmentID  `db:"environment_id"`
	Organization identity.OrganizationID `db:"organization_id"`
	Name         string                  `db:"name"`
	Issuer       string                  `db:"issuer"`
	Client       string                  `db:"client_id"`
	SecretEnv    string                  `db:"secret_env"`
	Sealed       string                  `db:"secret_sealed"`
	JIT          bool                    `db:"jit_provisioning"`
	JITGroup     identity.GroupID        `db:"jit_group_id"`
	Enforcement  string                  `db:"enforcement"`
	Provider     string                  `db:"provider"`
	Options      Options                 `db:"options"`
	// Signup and LinkEmail let unlinked identities of an environment
	// connection join: a new account in SignupOrganization (and
	// SignupGroup), or a link to the account with the same verified email.
	Signup             bool
	LinkEmail          bool
	SignupOrganization identity.OrganizationID
	SignupGroup        identity.GroupID
	// UpdateProfile refreshes a linked user's name (and verified email, see
	// Profile) from the provider at every sign-in.
	UpdateProfile bool
}

// Scoped reports whether the connection belongs to one organization.
func (c Connection) Scoped() bool { return !c.Organization.IsZero() }

// Validate checks the organization-only settings of an assembled connection.
func (c Connection) Validate() error {
	if c.Enforcement != EnforcementOptional && c.Enforcement != EnforcementEnforced {
		return errx.Validation("enforcement must be optional or enforced")
	}
	if !c.Scoped() && (c.JIT || !c.JITGroup.IsZero() || c.Enforcement == EnforcementEnforced) {
		return errx.Validation("organization_id is required for JIT provisioning and enforcement")
	}
	if !c.JIT && !c.JITGroup.IsZero() {
		return errx.Validation("jit_group_id requires jit_provisioning")
	}
	if err := validOptions(c.Provider, c.Options); err != nil {
		return err
	}
	if c.Provider == ProviderSAML && !c.Scoped() {
		return errx.Validation("SAML connections belong to an organization; organization_id is required")
	}
	if c.Provider == ProviderLDAP && !c.Scoped() {
		return errx.Validation("LDAP connections belong to an organization; organization_id is required")
	}
	if c.Scoped() && c.Signup {
		return errx.Validation("signup applies to environment connections; organization connections use jit_provisioning")
	}
	if c.Signup == c.SignupOrganization.IsZero() {
		return errx.Validation("signup requires signup_organization_id, which only applies with signup")
	}
	if !c.Signup && !c.SignupGroup.IsZero() {
		return errx.Validation("signup_group_id requires signup")
	}
	return nil
}

// ConnectionInput creates a connection. Exactly one of ClientSecret (stored
// encrypted) or SecretEnv (legacy approved deployment variable) is required.
// JIT defaults to on for organization connections. Provider defaults to
// oidc, which takes an Issuer; presets derive it (an Issuer given with a
// preset must match). For Apple the secret is the .p8 private key.
type ConnectionInput struct {
	Organization       identity.OrganizationID `json:"organization_id"`
	Name               string                  `json:"name"`
	Provider           string                  `json:"provider"`
	Options            Options                 `json:"options"`
	Issuer             string                  `json:"issuer"`
	Client             string                  `json:"client_id"`
	SecretEnv          string                  `json:"secret_env"`
	ClientSecret       string                  `json:"client_secret"`
	JIT                *bool                   `json:"jit_provisioning"`
	JITGroup           identity.GroupID        `json:"jit_group_id"`
	Enforcement        string                  `json:"enforcement"`
	Signup             bool                    `json:"signup"`
	LinkEmail          bool                    `json:"link_email"`
	SignupOrganization identity.OrganizationID `json:"signup_organization_id"`
	SignupGroup        identity.GroupID        `json:"signup_group_id"`
	UpdateProfile      bool                    `json:"update_profile"`
}

// provider is the input's provider, oidc by default.
func (i ConnectionInput) provider() string {
	if i.Provider == "" {
		return ProviderOIDC
	}
	return i.Provider
}

// issuer is the preset's issuer, or the given one for generic OIDC.
func (i ConnectionInput) issuer() string {
	if preset := Preset(i.provider(), i.Options.Normalized()); preset != "" {
		return preset
	}
	return i.Issuer
}

func (i ConnectionInput) Validate() error {
	if strings.TrimSpace(i.Name) == "" || len(i.Name) > 200 {
		return errx.Validation("name is required and at most 200 characters")
	}
	if err := validOptions(i.provider(), i.Options.Normalized()); err != nil {
		return err
	}
	if i.provider() == ProviderSAML {
		// The identity provider's metadata names its entity ID (the
		// issuer); the service provider needs no client credentials.
		if i.Issuer != "" || i.Client != "" || i.SecretEnv != "" || i.ClientSecret != "" {
			return errx.Validation("SAML connections take options.metadata_url or options.metadata_xml instead of issuer, client_id and a secret")
		}
		if i.Organization.IsZero() {
			return errx.Validation("SAML connections belong to an organization; organization_id is required")
		}
		if i.Enforcement != "" && i.Enforcement != EnforcementOptional && i.Enforcement != EnforcementEnforced {
			return errx.Validation("enforcement must be optional or enforced")
		}
		return nil
	}
	if i.provider() == ProviderLDAP {
		// The directory URL is the issuer and the user base DN the client
		// ID; the service account's password is the only secret.
		if i.Issuer != "" || i.Client != "" || i.SecretEnv != "" {
			return errx.Validation("LDAP connections take options.url and options.user_base_dn instead of issuer, client_id and secret_env")
		}
		if i.Organization.IsZero() {
			return errx.Validation("LDAP connections belong to an organization; organization_id is required")
		}
		if (i.Options.Normalized().BindDN == "") != (i.ClientSecret == "") {
			return errx.Validation("options.bind_dn and client_secret (its password) go together; omit both for an anonymous search")
		}
		if len(i.ClientSecret) > MaxClientSecret {
			return errx.Validation("client_secret is at most 4096 characters")
		}
		if i.Enforcement != "" && i.Enforcement != EnforcementOptional && i.Enforcement != EnforcementEnforced {
			return errx.Validation("enforcement must be optional or enforced")
		}
		return nil
	}
	if i.provider() != ProviderOIDC && i.Issuer != "" && i.Issuer != i.issuer() {
		return errx.Validation("issuer is set by the provider preset")
	}
	if err := validIssuer(i.issuer()); err != nil {
		return err
	}
	if i.provider() == ProviderApple && i.SecretEnv != "" {
		return errx.Validation("Apple connections store their private key as client_secret")
	}
	if strings.TrimSpace(i.Client) == "" || len(i.Client) > 512 {
		return errx.Validation("client_id is required and at most 512 characters")
	}
	if (i.SecretEnv == "") == (i.ClientSecret == "") {
		return errx.Validation("provide exactly one of client_secret or secret_env")
	}
	if i.SecretEnv != "" && !secretName.MatchString(i.SecretEnv) {
		return errx.Validation("secret_env must name an IAMKIT_PROVIDER_ variable")
	}
	if len(i.ClientSecret) > MaxClientSecret {
		return errx.Validation("client_secret is at most 4096 characters")
	}
	if i.Enforcement != "" && i.Enforcement != EnforcementOptional && i.Enforcement != EnforcementEnforced {
		return errx.Validation("enforcement must be optional or enforced")
	}
	if i.provider() == ProviderApple {
		if _, err := ParseAppleKey(i.ClientSecret); err != nil {
			return err
		}
	}
	return nil
}

// Connection applies defaults and returns the connection to store; the
// service seals ClientSecret separately.
func (i ConnectionInput) Connection(environment identity.EnvironmentID) Connection {
	c := Connection{Environment: environment, Organization: i.Organization, Name: strings.TrimSpace(i.Name), Issuer: i.issuer(), Client: strings.TrimSpace(i.Client), SecretEnv: i.SecretEnv, JIT: !i.Organization.IsZero(), JITGroup: i.JITGroup, Enforcement: i.Enforcement,
		Provider: i.provider(), Options: i.Options.Normalized(), Signup: i.Signup, LinkEmail: i.LinkEmail, SignupOrganization: i.SignupOrganization, SignupGroup: i.SignupGroup, UpdateProfile: i.UpdateProfile}
	if i.JIT != nil {
		c.JIT = *i.JIT
	}
	if c.Enforcement == "" {
		c.Enforcement = EnforcementOptional
	}
	if c.Provider == ProviderLDAP {
		c.Client = strings.ToLower(c.Options.UserBaseDN)
	}
	return c
}

func validIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errx.Validation("issuer must be an HTTPS URL without credentials, query or fragment")
	}
	return nil
}

// ConnectionUpdate changes a connection. Issuer, client ID, provider and
// organization are fixed because linked subjects are only meaningful for
// them. A non-nil JITGroup (or SignupGroup, SignupOrganization) holding the
// zero ID clears it. Setting ClientSecret on a legacy connection converts
// it to an encrypted secret. Options may change the Microsoft tenant
// allow-list (not the tenant policy, which fixes the issuer) and the Apple
// key ID (key rotation, with the new key as ClientSecret).
type ConnectionUpdate struct {
	Name               *string                  `json:"name"`
	ClientSecret       *string                  `json:"client_secret"`
	JIT                *bool                    `json:"jit_provisioning"`
	JITGroup           *identity.GroupID        `json:"jit_group_id"`
	Enforcement        *string                  `json:"enforcement"`
	Options            *Options                 `json:"options"`
	Signup             *bool                    `json:"signup"`
	LinkEmail          *bool                    `json:"link_email"`
	SignupOrganization *identity.OrganizationID `json:"signup_organization_id"`
	SignupGroup        *identity.GroupID        `json:"signup_group_id"`
	UpdateProfile      *bool                    `json:"update_profile"`
}

func (u ConnectionUpdate) Validate() error {
	if u.Name != nil && (strings.TrimSpace(*u.Name) == "" || len(*u.Name) > 200) {
		return errx.Validation("name is required and at most 200 characters")
	}
	if u.ClientSecret != nil && (*u.ClientSecret == "" || len(*u.ClientSecret) > MaxClientSecret) {
		return errx.Validation("client_secret must be non-empty and at most 4096 characters")
	}
	if u.Enforcement != nil && *u.Enforcement != EnforcementOptional && *u.Enforcement != EnforcementEnforced {
		return errx.Validation("enforcement must be optional or enforced")
	}
	return nil
}

// Apply returns c with the update's non-nil fields except the secret. It
// fails when the options would change what the connection is.
func (u ConnectionUpdate) Apply(c Connection) (Connection, error) {
	if u.Name != nil {
		c.Name = strings.TrimSpace(*u.Name)
	}
	if u.JIT != nil {
		c.JIT = *u.JIT
	}
	if u.JITGroup != nil {
		c.JITGroup = *u.JITGroup
	}
	if u.Enforcement != nil {
		c.Enforcement = *u.Enforcement
	}
	if u.Signup != nil {
		c.Signup = *u.Signup
	}
	if u.LinkEmail != nil {
		c.LinkEmail = *u.LinkEmail
	}
	if u.SignupOrganization != nil {
		c.SignupOrganization = *u.SignupOrganization
	}
	if u.SignupGroup != nil {
		c.SignupGroup = *u.SignupGroup
	}
	if u.UpdateProfile != nil {
		c.UpdateProfile = *u.UpdateProfile
	}
	// Turning sign-up off drops where it signed users up to.
	if u.Signup != nil && !*u.Signup {
		c.SignupOrganization, c.SignupGroup = identity.OrganizationID{}, identity.GroupID{}
	}
	if u.Options != nil {
		o := u.Options.Normalized()
		if o.Tenant != c.Options.Tenant || o.Team != c.Options.Team || o.BaseURL != c.Options.BaseURL {
			return c, errx.Validation("the tenant, Apple team and base URL of a connection cannot change; create another connection")
		}
		if c.Provider == ProviderOAuth2 && Preset(ProviderOAuth2, o) != c.Issuer {
			return c, errx.Validation("the authorize_url of an OAuth 2.0 connection must stay on the same host; create another connection")
		}
		if c.Provider == ProviderLDAP && (Preset(ProviderLDAP, o) != c.Issuer || strings.ToLower(o.UserBaseDN) != c.Client) {
			return c, errx.Validation("the directory host and user_base_dn of an LDAP connection cannot change; create another connection")
		}
		if o.Key != c.Options.Key && u.ClientSecret == nil {
			return c, errx.Validation("a new Apple key_id needs its private key as client_secret")
		}
		c.Options = o
	}
	if c.Provider == ProviderSAML && u.ClientSecret != nil {
		return c, errx.Validation("SAML connections have no client_secret")
	}
	if c.Provider == ProviderLDAP {
		if c.Options.BindDN == "" && u.ClientSecret != nil {
			return c, errx.Validation("an anonymous LDAP connection has no client_secret; set options.bind_dn with it")
		}
		if c.Options.BindDN != "" && c.Sealed == "" && u.ClientSecret == nil {
			return c, errx.Validation("options.bind_dn needs its password as client_secret")
		}
		if c.Options.BindDN == "" {
			c.Sealed = ""
		}
	}
	return c, nil
}

// Claims are the verified ID token claims federation uses. EmailVerified is
// nil when the provider omits the claim (Microsoft Entra ID usually does).
type Claims struct {
	Subject       string
	Email         string
	EmailVerified *bool
	Name          string
	// Picture is the provider's avatar URL (OIDC picture); only an https
	// URL is kept (Avatar).
	Picture string
	// HostedDomain is Google's hd claim: the Workspace domain of the
	// account, empty for personal Google accounts.
	HostedDomain string
	// Issuer identifies the account's issuer stably: the connection's
	// configured issuer (go-oidc also accepts Google's scheme-less
	// "accounts.google.com", which must not become a second identity), or
	// for Microsoft the verified per-tenant issuer. Empty for GitHub, which
	// has no ID token.
	Issuer string
	// Assertion is the ID of a SAML assertion and AssertionExpires when it
	// stops being acceptable; the service records it against replays.
	Assertion        string
	AssertionExpires time.Time
}

// Admit decides whether an unlinked provider identity may be provisioned just
// in time and returns its normalized email. The repository still requires the
// email's domain to be verified by the connection's organization.
//
// Without JIT, LinkEmail still lets the identity sign in to the existing
// account with that email (Provisioning.Create false).
func (c Connection) Admit(claims Claims) (string, error) {
	if !c.Scoped() || !c.JIT && !c.LinkEmail {
		return "", errx.Unauthorized("external identity is not linked")
	}
	email, err := identity.Email(claims.Email)
	if err != nil {
		return "", errx.Unauthorized("provider did not supply a valid email")
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return "", errx.Unauthorized("provider email is not verified")
	}
	return email, nil
}

// Profile refreshes a linked identity's user from the provider's claims on
// sign-in (Connection.UpdateProfile). Email is set only when the provider
// vouches for it (an environment connection's explicitly verified email, or
// an organization connection's email on a domain the organization verified,
// checked in the repository); it changes only passwordless accounts that no
// SCIM directory manages, and only when no other account has it.
type Profile struct {
	Connection   identity.ConnectionID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Subject      string
	Name         string
	Email        string
	// AvatarURL replaces the picture when the provider sent one.
	AvatarURL string
}

// Profile returns the refresh the claims allow.
func (c Connection) Profile(claims Claims) Profile {
	p := Profile{Connection: c.ID, Environment: c.Environment, Organization: c.Organization, Subject: claims.Subject, AvatarURL: claims.Avatar()}
	if name := strings.TrimSpace(claims.Name); len(name) <= 200 {
		p.Name = name
	}
	email, err := identity.Email(claims.Email)
	switch {
	case err != nil:
	case c.Scoped() && (claims.EmailVerified == nil || *claims.EmailVerified):
		p.Email = email
	case !c.Scoped() && claims.EmailVerified != nil && *claims.EmailVerified:
		p.Email = email
	}
	return p
}

// ErrProviderUnavailable is returned when the identity provider cannot be
// reached or serves no usable discovery document (502 PROVIDER_UNAVAILABLE),
// so callers can tell an outage apart from a rejected login.
func ErrProviderUnavailable(cause error) error {
	e := errx.Wrap(cause, "identity provider unavailable", errx.TypeExternal)
	e.Code = "PROVIDER_UNAVAILABLE"
	return e
}

// DisplayName is the provider's name claim, or the email's local part.
// Avatar is the provider's picture when it is an acceptable avatar URL,
// else "".
func (c Claims) Avatar() string {
	avatar, err := identity.AvatarURL(c.Picture)
	if err != nil {
		return ""
	}
	return avatar
}

func (c Claims) DisplayName(email string) string {
	if name := strings.TrimSpace(c.Name); name != "" && len(name) <= 200 {
		return name
	}
	return email[:strings.LastIndexByte(email, '@')]
}

// Provisioning links a provider identity on first login, adopting the user
// with Email or, when Create (JIT), creating one with ID User and making it
// a member of Organization (and Group). Without Create only an existing
// account is linked.
type Provisioning struct {
	Create       bool
	Connection   identity.ConnectionID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Group        identity.GroupID
	User         identity.UserID
	Subject      string
	Email        string
	Domain       string
	Name         string
	// AvatarURL is the provider's picture: a new user's avatar, and an
	// existing account's when it has none.
	AvatarURL string
}

// Discovery routes an email to its login method: "sso" when the email's
// domain is verified by an organization with an active SSO connection,
// otherwise "password". Required reports enforcement.
type Discovery struct {
	Method       string                   `json:"method"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Connection   *identity.ConnectionID   `json:"connection_id,omitempty"`
	Required     bool                     `json:"required"`
	// Provider is the connection's provider: "ldap" means the password is
	// posted to /identity/v1/federation/ldap/login instead of a redirect.
	Provider string `json:"provider,omitempty"`
}

// Discovery methods.
const (
	MethodPassword = "password"
	MethodSSO      = "sso"
)

type State struct {
	Connection identity.ConnectionID
	// Boundary.OrganizationID is zero for a hosted start through an
	// environment connection: the organization is chosen after the callback.
	Boundary        authentication.Context
	Binding         []byte
	Nonce, Verifier string
	// Continuation is the OAuth authorization ticket a hosted login start
	// resumes after the callback; empty for headless starts.
	Continuation string
	// Return sends a headless callback back to a custom sign-in UI.
	Return Return
}
type Start struct{ URL, Binding string }

// Return asks a headless federation callback to redirect back to a custom
// sign-in UI instead of answering JSON at IAMKit's own URL: To (an origin
// an OAuth client of the application allows) receives a one-time
// federation_result handle, which only the holder of the verifier of
// Challenge (S256, like PKCE) redeems for the login result. The zero value
// keeps the JSON callback.
type Return struct {
	To        string `json:"return_to"`
	Challenge string `json:"code_challenge"`
}

// Set reports whether the start asked for a redirect back.
func (r Return) Set() bool { return r.To != "" || r.Challenge != "" }

// Validate checks the shape: an absolute https URL (http only on a
// loopback host) without credentials or fragment, and an S256 challenge.
// Whether its origin is allowed is the service's check (Origin).
func (r Return) Validate() error {
	if _, err := r.Origin(); err != nil {
		return err
	}
	if len(r.Challenge) != 43 || strings.Trim(r.Challenge, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return errx.Validation("code_challenge must be the S256 challenge (43 base64url characters) of a verifier the sign-in UI keeps")
	}
	return nil
}

// Origin is the scheme://host[:port] of To, lowercased.
func (r Return) Origin() (string, error) {
	u, err := url.Parse(r.To)
	invalid := errx.Validation("return_to must be an absolute https URL (http only on localhost) without credentials or fragment")
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" || len(r.To) > 2048 {
		return "", invalid
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if scheme != "https" && (scheme != "http" || !loopback) {
		return "", invalid
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// ResultPrefix starts the one-time handle a callback hands to return_to.
const ResultPrefix = "ik_fedres_"

// ResultTTL bounds the time between the callback and the redemption.
const ResultTTL = time.Minute

// Result is a verified headless federated sign-in parked for a custom
// sign-in UI: the session is issued only when the UI redeems it.
type Result struct {
	Boundary        authentication.Context
	User            identity.UserID
	Email           string
	OrganizationSSO bool
	// NoAccess turns a refused session into 403 (the provider proved the
	// identity; access is what is missing).
	NoAccess  bool
	Challenge string
}

// Verifies reports whether verifier is the S256 verifier of the
// challenge, in constant time.
func (r Result) Verifies(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(r.Challenge)) == 1
}

// Outcome of a federation callback: the session of a headless start, or,
// for a hosted login start, the verified user and the authorization ticket
// to resume. Continuation is set even when the callback fails after the
// state was consumed, so the hosted pages can show the error.
type Outcome struct {
	Issued       authentication.Issued
	Continuation string
	Verified     authentication.Verified
	// MFA is set instead of Issued when the headless login needs a second
	// factor.
	MFA *authentication.MFA
	// ReturnTo is the custom sign-in UI a headless start asked to return
	// to (set even when the callback fails after the state was consumed);
	// Result is then the one-time handle to redeem instead of a session.
	ReturnTo, Result string
}

// Hosted reports whether the callback belongs to a hosted login.
func (o Outcome) Hosted() bool { return o.Continuation != "" }

// ConnectionSummary is what a sign-in page shows for a connection.
type ConnectionSummary struct {
	ID       identity.ConnectionID `json:"id" db:"id"`
	Name     string                `json:"name" db:"name"`
	Provider string                `json:"provider" db:"provider"`
}
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Connection scopes: environment connections (social login) or
// organization connections (organization SSO).
const (
	ScopeEnvironment  = "environment"
	ScopeOrganization = "organization"
)

// ConnectionFilter narrows the connection list to one organization, or to
// one Scope (empty for both).
type ConnectionFilter struct {
	Organization identity.OrganizationID
	Scope        string
}

func (f ConnectionFilter) Validate() error {
	if f.Scope != "" && f.Scope != ScopeEnvironment && f.Scope != ScopeOrganization {
		return errx.Validation("scope must be environment or organization")
	}
	return nil
}

type ConnectionView struct {
	ID           identity.ConnectionID    `json:"id" db:"id"`
	Organization *identity.OrganizationID `json:"organization_id" db:"organization_id"`
	// OrganizationName labels Organization for display; empty for
	// environment connections.
	OrganizationName string `json:"organization_name" db:"organization_name"`
	Name             string `json:"name" db:"name"`
	Provider         string `json:"provider" db:"provider"`
	Issuer           string `json:"issuer" db:"issuer"`
	ClientID         string `json:"client_id" db:"client_id"`
	Active           bool   `json:"active" db:"active"`
	JIT              bool   `json:"jit_provisioning" db:"jit_provisioning"`
	Enforcement      string `json:"enforcement" db:"enforcement"`
	Signup           bool   `json:"signup" db:"signup"`
	LinkEmail        bool   `json:"link_email" db:"link_email"`
	UpdateProfile    bool   `json:"update_profile" db:"update_profile"`
	Linked           int    `json:"linked" db:"linked"`
}

// ConnectionDetail never exposes the secret. SecretSource is "env",
// "sealed", or "none" (SAML, anonymous LDAP); SecretEnv is set only for the
// legacy source.
type ConnectionDetail struct {
	ID                 identity.ConnectionID    `json:"id" db:"id"`
	Organization       *identity.OrganizationID `json:"organization_id" db:"organization_id"`
	OrganizationName   string                   `json:"organization_name" db:"organization_name"`
	Name               string                   `json:"name" db:"name"`
	Provider           string                   `json:"provider" db:"provider"`
	Options            Options                  `json:"options" db:"-"`
	Issuer             string                   `json:"issuer" db:"issuer"`
	ClientID           string                   `json:"client_id" db:"client_id"`
	SecretEnv          string                   `json:"secret_env" db:"secret_env"`
	SecretSource       string                   `json:"secret_source" db:"secret_source"`
	Active             bool                     `json:"active" db:"active"`
	JIT                bool                     `json:"jit_provisioning" db:"jit_provisioning"`
	JITGroup           *identity.GroupID        `json:"jit_group_id" db:"jit_group_id"`
	Enforcement        string                   `json:"enforcement" db:"enforcement"`
	Signup             bool                     `json:"signup" db:"signup"`
	LinkEmail          bool                     `json:"link_email" db:"link_email"`
	SignupOrganization *identity.OrganizationID `json:"signup_organization_id" db:"signup_organization_id"`
	SignupGroup        *identity.GroupID        `json:"signup_group_id" db:"signup_group_id"`
	UpdateProfile      bool                     `json:"update_profile" db:"update_profile"`
	// Callback is the redirect URI to register at the provider (for SAML the
	// assertion consumer service).
	Callback string `json:"callback_url" db:"-"`
	// SAML is the service provider of a SAML connection.
	SAML    *ServiceProvider `json:"saml,omitempty" db:"-"`
	Created time.Time        `json:"created_at" db:"created_at"`
	Linked  int              `json:"linked" db:"linked"`
}
type ExternalIdentityView struct {
	ConnectionID identity.ConnectionID `json:"connection_id" db:"connection_id"`
	Subject      string                `json:"subject" db:"subject"`
	UserID       identity.UserID       `json:"user_id" db:"user_id"`
	UserName     string                `json:"user_name" db:"user_name"`
	UserEmail    string                `json:"user_email" db:"user_email"`
	Origin       string                `json:"origin" db:"origin"`
	Created      time.Time             `json:"created_at" db:"created_at"`
}
