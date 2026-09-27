package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Providers. A preset fixes the issuer and how IAMKit talks to the
// provider; ProviderOIDC is any OpenID Connect provider found by discovery.
const (
	ProviderOIDC      = "oidc"
	ProviderGoogle    = "google"
	ProviderMicrosoft = "microsoft"
	ProviderGitHub    = "github"
	ProviderApple     = "apple"
)

// Microsoft tenants: which accounts a Microsoft connection accepts. A
// tenant ID (UUID) accepts that tenant only.
const (
	TenantCommon        = "common"        // work, school and personal accounts
	TenantOrganizations = "organizations" // work and school accounts
	TenantConsumers     = "consumers"     // personal Microsoft accounts
	// ConsumerTenant is the tenant ID of personal Microsoft accounts.
	ConsumerTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	// MaxTenants bounds the allow-list of a multi-tenant connection.
	MaxTenants = 100
)

var (
	tenantID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	appleID  = regexp.MustCompile(`^[A-Z0-9]{10}$`)
)

// Options are the non-secret settings of a preset.
type Options struct {
	// Tenant is the Microsoft tenant policy (common, organizations,
	// consumers or a tenant ID); Tenants optionally restricts common or
	// organizations to these tenant IDs.
	Tenant  string   `json:"tenant,omitempty"`
	Tenants []string `json:"tenants,omitempty"`
	// Team and Key identify the Sign in with Apple private key.
	Team string `json:"team_id,omitempty"`
	Key  string `json:"key_id,omitempty"`
}

// Preset returns the issuer of a preset provider; generic OIDC connections
// keep the issuer they were given.
func Preset(provider string, o Options) string {
	switch provider {
	case ProviderGoogle:
		return "https://accounts.google.com"
	case ProviderMicrosoft:
		return "https://login.microsoftonline.com/" + o.Tenant + "/v2.0"
	case ProviderGitHub:
		return "https://github.com"
	case ProviderApple:
		return "https://appleid.apple.com"
	}
	return ""
}

// Normalized lowercases and orders the options' identifiers.
func (o Options) Normalized() Options {
	o.Tenant = strings.ToLower(strings.TrimSpace(o.Tenant))
	tenants := make([]string, 0, len(o.Tenants))
	for _, t := range o.Tenants {
		tenants = append(tenants, strings.ToLower(strings.TrimSpace(t)))
	}
	slices.Sort(tenants)
	o.Tenants = slices.Compact(tenants)
	if len(o.Tenants) == 0 {
		o.Tenants = nil
	}
	o.Team, o.Key = strings.ToUpper(strings.TrimSpace(o.Team)), strings.ToUpper(strings.TrimSpace(o.Key))
	return o
}

// validOptions checks the options a provider takes; other providers take
// none.
func validOptions(provider string, o Options) error {
	microsoft := o.Tenant != "" || len(o.Tenants) > 0
	apple := o.Team != "" || o.Key != ""
	switch provider {
	case ProviderOIDC, ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderApple:
	default:
		return errx.Validation("provider must be oidc, google, microsoft, github or apple")
	}
	if microsoft && provider != ProviderMicrosoft || apple && provider != ProviderApple {
		return errx.Validation("options do not apply to this provider")
	}
	switch provider {
	case ProviderMicrosoft:
		switch {
		case o.Tenant == TenantCommon || o.Tenant == TenantOrganizations:
		case o.Tenant == TenantConsumers || tenantID.MatchString(o.Tenant):
			if len(o.Tenants) > 0 {
				return errx.Validation("options.tenants only restricts the common and organizations tenants")
			}
		default:
			return errx.Validation("options.tenant must be common, organizations, consumers or a tenant ID")
		}
		if len(o.Tenants) > MaxTenants {
			return errx.Validation("options.tenants has at most 100 tenant IDs")
		}
		for _, t := range o.Tenants {
			if !tenantID.MatchString(t) {
				return errx.Validation("options.tenants must be tenant IDs")
			}
		}
	case ProviderApple:
		if !appleID.MatchString(o.Team) || !appleID.MatchString(o.Key) {
			return errx.Validation("options.team_id and options.key_id are the 10-character Apple team and key IDs")
		}
	}
	return nil
}

// MultiTenant reports whether a Microsoft connection accepts more than one
// tenant, so the token issuer depends on the user's tenant.
func (o Options) MultiTenant() bool {
	return o.Tenant == TenantCommon || o.Tenant == TenantOrganizations
}

// AcceptsTenant reports whether a Microsoft connection accepts users of the
// tenant.
func (o Options) AcceptsTenant(tenant string) bool {
	if !tenantID.MatchString(tenant) {
		return false
	}
	switch o.Tenant {
	case TenantConsumers:
		return tenant == ConsumerTenant
	case TenantOrganizations:
		if tenant == ConsumerTenant {
			return false
		}
	case TenantCommon:
	default:
		return tenant == o.Tenant
	}
	return len(o.Tenants) == 0 || slices.Contains(o.Tenants, tenant)
}

// ParseAppleKey reads a Sign in with Apple private key: the PKCS #8 P-256
// key of the downloaded .p8 file.
//
// A key pasted into a single-line field (newlines turned into spaces) is
// accepted too.
func ParseAppleKey(raw string) (*ecdsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		const begin, end = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
		if body, ok := strings.CutPrefix(raw, begin); ok {
			if body, ok = strings.CutSuffix(body, end); ok {
				block, _ = pem.Decode([]byte(begin + "\n" + strings.Join(strings.Fields(body), "\n") + "\n" + end + "\n"))
			}
		}
	}
	if block == nil {
		return nil, errx.Validation("client_secret must be the PEM contents of the Apple .p8 key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errx.Validation("client_secret must be the PEM contents of the Apple .p8 key")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errx.Validation("the Apple key must be a P-256 key")
	}
	return ec, nil
}

// Social reports whether an unlinked identity of the connection may join
// on its own: environment connections that sign up new users or link by
// verified email.
func (c Connection) Social() bool { return !c.Scoped() && (c.Signup || c.LinkEmail) }

// Joining decides whether an unlinked provider identity of an environment
// connection may sign up or link by email, and returns its normalized
// email. Unlike organization JIT (whose domain the organization verified)
// the provider must explicitly confirm the email: otherwise anyone could
// claim an address at a provider that does not verify it.
func (c Connection) Joining(claims Claims) (string, error) {
	if !c.Social() {
		return "", errx.Unauthorized("external identity is not linked")
	}
	email, err := identity.Email(claims.Email)
	if err != nil {
		return "", errx.Unauthorized("provider did not supply a valid email")
	}
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return "", errx.Unauthorized("provider email is not verified")
	}
	return email, nil
}

// Joining is an unlinked environment-connection identity joining: linked to
// the active user with Email when Link, otherwise created as user ID User
// in Organization (and Group) when Signup.
type Joining struct {
	Connection   identity.ConnectionID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Group        identity.GroupID
	User         identity.UserID
	Subject      string
	Email        string
	Name         string
	Link         bool
	Signup       bool
}

// Account is the local user a provider identity is linked to.
type Account struct {
	ID    identity.UserID `db:"id"`
	Email string          `db:"email"`
}

// ErrAccountExists is returned when a provider identity's email belongs to
// an account the connection does not link to.
func ErrAccountExists() error {
	e := errx.Unauthorized("an account with this email already exists; sign in with it")
	e.Code = "ACCOUNT_EXISTS"
	return e
}
