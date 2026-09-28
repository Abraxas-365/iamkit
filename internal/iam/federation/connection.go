package federation

import (
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
	if c.Scoped() && (c.Signup || c.LinkEmail) {
		return errx.Validation("signup and link_email apply to environment connections; organization connections use jit_provisioning")
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
		Provider: i.provider(), Options: i.Options.Normalized(), Signup: i.Signup, LinkEmail: i.LinkEmail, SignupOrganization: i.SignupOrganization, SignupGroup: i.SignupGroup}
	if i.JIT != nil {
		c.JIT = *i.JIT
	}
	if c.Enforcement == "" {
		c.Enforcement = EnforcementOptional
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
	// Turning sign-up off drops where it signed users up to.
	if u.Signup != nil && !*u.Signup {
		c.SignupOrganization, c.SignupGroup = identity.OrganizationID{}, identity.GroupID{}
	}
	if u.Options != nil {
		o := u.Options.Normalized()
		if o.Tenant != c.Options.Tenant || o.Team != c.Options.Team {
			return c, errx.Validation("the tenant and Apple team of a connection cannot change; create another connection")
		}
		if o.Key != c.Options.Key && u.ClientSecret == nil {
			return c, errx.Validation("a new Apple key_id needs its private key as client_secret")
		}
		c.Options = o
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
}

// Admit decides whether an unlinked provider identity may be provisioned just
// in time and returns its normalized email. The repository still requires the
// email's domain to be verified by the connection's organization.
func (c Connection) Admit(claims Claims) (string, error) {
	if !c.Scoped() || !c.JIT {
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

// ErrProviderUnavailable is returned when the identity provider cannot be
// reached or serves no usable discovery document (502 PROVIDER_UNAVAILABLE),
// so callers can tell an outage apart from a rejected login.
func ErrProviderUnavailable(cause error) error {
	e := errx.Wrap(cause, "identity provider unavailable", errx.TypeExternal)
	e.Code = "PROVIDER_UNAVAILABLE"
	return e
}

// DisplayName is the provider's name claim, or the email's local part.
func (c Claims) DisplayName(email string) string {
	if name := strings.TrimSpace(c.Name); name != "" && len(name) <= 200 {
		return name
	}
	return email[:strings.LastIndexByte(email, '@')]
}

// Provisioning links a provider identity on first login, adopting the user
// with Email or creating one with ID User.
type Provisioning struct {
	Connection   identity.ConnectionID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Group        identity.GroupID
	User         identity.UserID
	Subject      string
	Email        string
	Domain       string
	Name         string
}

// Discovery routes an email to its login method: "sso" when the email's
// domain is verified by an organization with an active SSO connection,
// otherwise "password". Required reports enforcement.
type Discovery struct {
	Method       string                   `json:"method"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Connection   *identity.ConnectionID   `json:"connection_id,omitempty"`
	Required     bool                     `json:"required"`
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
}
type Start struct{ URL, Binding string }

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

// ConnectionFilter narrows the connection list to one organization.
type ConnectionFilter struct {
	Organization identity.OrganizationID
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
	Linked           int    `json:"linked" db:"linked"`
}

// ConnectionDetail never exposes the secret. SecretSource is "env" or
// "sealed"; SecretEnv is set only for the legacy source.
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
	// Callback is the redirect URI to register at the provider.
	Callback string    `json:"callback_url" db:"-"`
	Created  time.Time `json:"created_at" db:"created_at"`
	Linked   int       `json:"linked" db:"linked"`
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
