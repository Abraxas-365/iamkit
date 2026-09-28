package management

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Operator single sign-on provider types. The deployment configures them at
// startup; operators never create them.
const (
	SSOTypeOIDC      = "oidc"
	SSOTypeGoogle    = "google"
	SSOTypeMicrosoft = "microsoft"
)

// Microsoft tenant policy of an operator provider: a tenant ID, or
// "organizations" restricted to an explicit list of tenant IDs.
const SSOTenantOrganizations = "organizations"

// MaxSSOTenants bounds the tenant allow-list of a Microsoft provider, and
// MaxSSODomains the allowed domains of any provider.
const (
	MaxSSOTenants = 100
	MaxSSODomains = 100
)

var (
	ssoID       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	ssoTenantID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// SSOProvider is one identity provider operators may sign in with. It holds
// no secret: the client secret stays with the adapter that talks to the
// provider.
type SSOProvider struct {
	// ID names the provider in URLs and configuration (lowercase).
	ID string
	// Name is the button label.
	Name string
	Type string
	// Issuer is the OIDC issuer of an oidc provider; presets derive theirs.
	Issuer string
	Client string
	// Tenant and Tenants are the Microsoft tenant policy.
	Tenant  string
	Tenants []string
	// AllowedDomains restricts sign-in to emails of these domains on every
	// login (and, for Google, to Workspace accounts of them). Required.
	AllowedDomains []string
}

// Validate checks a configured provider. Types that would let accounts
// outside the organization reach the control plane are refused.
func (p SSOProvider) Validate() error {
	if !ssoID.MatchString(p.ID) {
		return errx.Validation("operator SSO provider IDs are 1-32 lowercase letters, digits or dashes")
	}
	if name := strings.TrimSpace(p.Name); name == "" || len(name) > 100 {
		return errx.Validation("operator SSO provider " + p.ID + ": name is required and at most 100 characters")
	}
	if strings.TrimSpace(p.Client) == "" || len(p.Client) > 512 {
		return errx.Validation("operator SSO provider " + p.ID + ": client ID is required and at most 512 characters")
	}
	switch p.Type {
	case SSOTypeOIDC, SSOTypeGoogle, SSOTypeMicrosoft:
	case "github":
		return errx.Validation("operator SSO provider " + p.ID + ": github is not supported for operators (personal accounts outlive offboarding)")
	case "apple":
		return errx.Validation("operator SSO provider " + p.ID + ": apple is not supported for operators")
	default:
		return errx.Validation("operator SSO provider " + p.ID + ": type must be oidc, google or microsoft")
	}
	// Every provider needs allowed domains: the first sign-in links by
	// email, and an email the provider does not verify (a directory
	// attribute any tenant administrator can set) must not reach operators
	// outside the organization's own domains.
	if len(p.AllowedDomains) == 0 || len(p.AllowedDomains) > MaxSSODomains {
		return errx.Validation("operator SSO provider " + p.ID + ": allowed domains are required (1-100), otherwise any account of the provider could claim an operator's email")
	}
	for _, d := range p.AllowedDomains {
		if normalized, err := identity.Domain(d); err != nil || normalized != d {
			return errx.Validation("operator SSO provider " + p.ID + ": allowed domains must be normalized DNS domains such as example.com")
		}
	}
	microsoft := p.Tenant != "" || len(p.Tenants) > 0
	if microsoft && p.Type != SSOTypeMicrosoft {
		return errx.Validation("operator SSO provider " + p.ID + ": tenants apply to microsoft providers only")
	}
	if p.Issuer != "" && p.Type != SSOTypeOIDC {
		return errx.Validation("operator SSO provider " + p.ID + ": the issuer is set by the " + p.Type + " preset")
	}
	switch p.Type {
	case SSOTypeOIDC:
		return validSSOIssuer(p.ID, p.Issuer)
	case SSOTypeMicrosoft:
		return validSSOTenants(p.ID, p.Tenant, p.Tenants)
	}
	return nil
}

func validSSOIssuer(id, raw string) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errx.Validation("operator SSO provider " + id + ": issuer must be an HTTPS URL without credentials, query or fragment")
	}
	return nil
}

func validSSOTenants(id, tenant string, tenants []string) error {
	switch {
	case ssoTenantID.MatchString(tenant):
		if len(tenants) > 0 {
			return errx.Validation("operator SSO provider " + id + ": a tenant list only applies to the organizations tenant")
		}
		return nil
	case tenant == SSOTenantOrganizations:
		if len(tenants) == 0 || len(tenants) > MaxSSOTenants {
			return errx.Validation("operator SSO provider " + id + ": the organizations tenant requires a list of 1-100 tenant IDs")
		}
		for _, t := range tenants {
			if !ssoTenantID.MatchString(t) {
				return errx.Validation("operator SSO provider " + id + ": tenants must be tenant IDs")
			}
		}
		return nil
	}
	return errx.Validation("operator SSO provider " + id + ": tenant must be a tenant ID, or organizations with a tenant list (common and consumers accept any Microsoft account)")
}

// TrustsDirectory reports whether an email the provider leaves unverified
// (no email_verified claim) may still link an operator: a single
// organization's directory vouches for its own accounts, within the allowed
// domains only. Google must say verified, and multi-tenant Microsoft only
// counts tenant-verified domains.
func (p SSOProvider) TrustsDirectory() bool {
	return p.Type == SSOTypeOIDC || p.Type == SSOTypeMicrosoft && p.Tenant != SSOTenantOrganizations
}

// SSOClaims are the verified identity a provider returned.
type SSOClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified *bool
	Name          string
	// HostedDomain is Google's hd claim.
	HostedDomain string
}

// Admit applies the provider's rules to a verified identity and returns its
// normalized email. Domain restrictions apply on every login; the email
// rules apply when the identity is not linked yet (linked is false), because
// only then does the email decide which operator it is. The error messages
// are for the server log: callers show every refusal the same way.
func (p SSOProvider) Admit(c SSOClaims, linked bool) (string, error) {
	if c.Issuer == "" || c.Subject == "" || len(c.Subject) > 512 {
		return "", ErrSSONotAuthorized("provider identity has no issuer or subject")
	}
	email, err := identity.Email(c.Email)
	// The domain gate applies on every login, linked or not.
	if err != nil || !slices.Contains(p.AllowedDomains, identity.EmailDomain(email)) {
		return "", ErrSSONotAuthorized("email domain is not allowed")
	}
	if p.Type == SSOTypeGoogle && !slices.Contains(p.AllowedDomains, strings.ToLower(c.HostedDomain)) {
		return "", ErrSSONotAuthorized("google account is not a Workspace account of an allowed domain")
	}
	if linked {
		return email, nil
	}
	if c.EmailVerified == nil && !p.TrustsDirectory() || c.EmailVerified != nil && !*c.EmailVerified {
		return "", ErrSSONotAuthorized("provider email is not verified")
	}
	return email, nil
}

// PasswordMode is who may sign in to the console with an email and password
// (IAMKIT_OPERATOR_PASSWORD_LOGIN).
type PasswordMode string

const (
	// PasswordEnabled lets every operator with a password use it.
	PasswordEnabled PasswordMode = "enabled"
	// PasswordBreakGlass requires single sign-on, except for the operators
	// an owner granted emergency access (password_allowed).
	PasswordBreakGlass PasswordMode = "break_glass"
	// PasswordDisabled is single sign-on only.
	PasswordDisabled PasswordMode = "disabled"
)

// Permits reports whether an operator may use a password: allowed is the
// operator's emergency access grant, used in break-glass mode only. The
// zero mode is PasswordEnabled.
func (m PasswordMode) Permits(allowed bool) bool {
	switch m {
	case PasswordDisabled:
		return false
	case PasswordBreakGlass:
		return allowed
	}
	return true
}

// SSOSettings is the deployment's operator sign-in configuration.
type SSOSettings struct {
	// Password is who may sign in with an email and password.
	Password  PasswordMode
	Providers []SSOProvider
}

// Validate checks every provider, their IDs are unique, and the console has
// at least one way to sign in.
func (s SSOSettings) Validate() error {
	switch s.Password {
	case PasswordEnabled, PasswordBreakGlass, PasswordDisabled:
	default:
		return errx.Validation("operator password login must be enabled, break_glass or disabled")
	}
	seen := map[string]bool{}
	for _, p := range s.Providers {
		if err := p.Validate(); err != nil {
			return err
		}
		if seen[p.ID] {
			return errx.Validation("operator SSO provider " + p.ID + " is configured twice")
		}
		seen[p.ID] = true
	}
	if s.Password != PasswordEnabled && len(s.Providers) == 0 {
		return errx.Validation("operator password login can only be restricted (break_glass) or disabled when an SSO provider is configured")
	}
	return nil
}

// Provider returns the configured provider with the ID.
func (s SSOSettings) Provider(id string) (SSOProvider, bool) {
	for _, p := range s.Providers {
		if p.ID == id {
			return p, true
		}
	}
	return SSOProvider{}, false
}

// Options is what the console login page shows.
func (s SSOSettings) Options() LoginOptions {
	mode := s.Password
	if mode == "" {
		mode = PasswordEnabled
	}
	out := LoginOptions{Password: mode != PasswordDisabled, PasswordMode: mode, Providers: make([]SSOProviderView, 0, len(s.Providers))}
	for _, p := range s.Providers {
		out.Providers = append(out.Providers, SSOProviderView{ID: p.ID, Name: p.Name, Type: p.Type})
	}
	return out
}

// LoginOptions are the console's sign-in methods. Password is whether the
// password form exists at all (true in break-glass mode too, for emergency
// access).
type LoginOptions struct {
	Password     bool              `json:"password"`
	PasswordMode PasswordMode      `json:"password_mode"`
	Providers    []SSOProviderView `json:"providers"`
}

// SSOProviderView is the public view of a provider: a login button.
type SSOProviderView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// SSOState is a started sign-in awaiting the provider's callback. Binding
// is the hash of the browser cookie that must come back with it.
type SSOState struct {
	Provider string
	Binding  []byte
	Nonce    string
	Verifier string
}

// SSOStart is where to send the browser, and the binding cookie to set.
type SSOStart struct{ URL, Binding string }

// OperatorIdentity is a provider identity linked to an operator.
type OperatorIdentity struct {
	Provider  string     `json:"provider" db:"provider"`
	Issuer    string     `json:"issuer" db:"issuer"`
	Email     string     `json:"email" db:"email"`
	Created   time.Time  `json:"created_at" db:"created_at"`
	LastLogin *time.Time `json:"last_login_at" db:"last_login_at"`
}

// Operator SSO error codes.
const (
	CodeSSONotAuthorized      = "SSO_NOT_AUTHORIZED"
	CodeSSOExpired            = "SSO_EXPIRED"
	CodePasswordLoginDisabled = "PASSWORD_LOGIN_DISABLED"
	CodeSSORequired           = "SSO_REQUIRED"
	// CodePasswordChangeRequired: the password was set by someone else and
	// must be replaced (send new_password with the login).
	CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"
	// CodeReauthenticationRequired: a password change needs the current
	// password, or a recent sign-in when none is set.
	CodeReauthenticationRequired = "REAUTHENTICATION_REQUIRED"
)

// ErrPasswordChangeRequired is returned by Login, only after the password
// matched, when the password must be replaced.
func ErrPasswordChangeRequired() error {
	e := errx.Forbidden("choose a new password to finish signing in")
	e.Code = CodePasswordChangeRequired
	return e
}

// ErrReauthenticationRequired refuses a password change without proof.
func ErrReauthenticationRequired(message string) error {
	e := errx.Forbidden(message)
	e.Code = CodeReauthenticationRequired
	return e
}

// ErrSSORequired refuses the password of an operator without emergency
// access in break-glass mode. Login returns it only after the password
// matched, so it never reveals which emails are operators.
func ErrSSORequired() error {
	e := errx.Forbidden("this operator signs in with single sign-on")
	e.Code = CodeSSORequired
	return e
}

// ErrSSONotAuthorized refuses a provider identity. The reason is for the
// server log; the browser only learns the code.
func ErrSSONotAuthorized(reason string) error {
	e := errx.Unauthorized(reason)
	e.Code = CodeSSONotAuthorized
	return e
}

// ErrSSOExpired refuses a callback whose sign-in is unknown, used, expired
// or started in another browser.
func ErrSSOExpired() error {
	e := errx.Unauthorized("sign-in expired or was started elsewhere")
	e.Code = CodeSSOExpired
	return e
}

// ErrPasswordLoginDisabled refuses operator passwords when the deployment
// only allows single sign-on.
func ErrPasswordLoginDisabled() error {
	e := errx.Forbidden("password sign-in is disabled; use single sign-on")
	e.Code = CodePasswordLoginDisabled
	return e
}
