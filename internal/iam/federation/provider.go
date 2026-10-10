package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
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
	// ProviderGitLab is GitLab's OpenID Connect (gitlab.com, or a
	// self-managed instance at Options.BaseURL).
	ProviderGitLab = "gitlab"
	// ProviderGitHubEnterprise is GitHub Enterprise Server at
	// Options.BaseURL, read like GitHub.
	ProviderGitHubEnterprise = "github_enterprise"
	// ProviderOAuth2 is any OAuth 2.0 provider without OpenID Connect: the
	// options name its endpoints and where the userinfo response keeps the
	// subject, email and name.
	ProviderOAuth2 = "oauth2"
	// ProviderSAML is a SAML 2.0 identity provider, described by its
	// metadata (Options.MetadataURL or Options.MetadataXML). SAML
	// connections belong to an organization.
	ProviderSAML = "saml"
	// ProviderLDAP is an LDAP directory (Active Directory, OpenLDAP…) that
	// checks the user's password: IAMKit binds as the user found by
	// Options.UserFilter. LDAP connections belong to an organization.
	ProviderLDAP = "ldap"
)

// MaxLDAPCA bounds the PEM CA bundle of an LDAP connection.
const MaxLDAPCA = 64 << 10

// DefaultUserFilter finds a directory user by email or user principal name.
const DefaultUserFilter = "(|(mail={email})(userPrincipalName={email}))"

// SAML NameID formats a connection requests (Options.NameIDFormat).
const (
	NameIDUnspecified = "unspecified"
	NameIDPersistent  = "persistent"
	NameIDEmail       = "email"
	NameIDTransient   = "transient"
)

// MaxMetadata bounds a SAML identity provider's metadata document.
const MaxMetadata = 512 << 10

// GitLabURL is gitlab.com, the default GitLab instance.
const GitLabURL = "https://gitlab.com"

// MaxScopes bounds the scopes of an OAuth 2.0 connection.
const MaxScopes = 20

var claimPath = regexp.MustCompile(`^[A-Za-z0-9_:\-]+(\.[A-Za-z0-9_:\-]+){0,4}$`)

// Microsoft tenants: which accounts a Microsoft connection accepts. A
// tenant ID (UUID) accepts that tenant only.
const (
	TenantCommon        = "common"        // work, school and personal accounts
	TenantOrganizations = "organizations" // work and school accounts
	TenantConsumers     = "consumers"     // personal Microsoft accounts
	// ConsumerTenant is the tenant ID of personal Microsoft accounts.
	ConsumerTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	// PromptSelectAccount and PromptLogin are the Options.Prompt values.
	PromptSelectAccount = "select_account"
	PromptLogin         = "login"
	// MaxTenants bounds the allow-list of a multi-tenant connection.
	MaxTenants = 100
	// MaxDomains bounds the Workspace domains of a Google connection.
	MaxDomains = 100
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
	// Prompt is sent as the OIDC prompt of every authorization of a
	// Microsoft, Google or generic OIDC connection: select_account makes
	// the provider show its account picker even with one signed-in
	// account, login asks for the credentials again. "" lets the provider
	// reuse its session silently.
	Prompt string `json:"prompt,omitempty"`
	// Domains restricts a Google connection to Google Workspace accounts of
	// these domains (the ID token's hd claim); empty accepts any account.
	Domains []string `json:"domains,omitempty"`
	// Team and Key identify the Sign in with Apple private key.
	Team string `json:"team_id,omitempty"`
	Key  string `json:"key_id,omitempty"`
	// BaseURL is the instance of a self-managed GitLab (optional, default
	// gitlab.com) or of GitHub Enterprise Server (required). It is the
	// connection's issuer.
	BaseURL string `json:"base_url,omitempty"`
	// AuthorizeURL, TokenURL and UserinfoURL are the endpoints of an OAuth
	// 2.0 connection; Scopes are requested at authorization; Claims says
	// where the userinfo JSON keeps the identity.
	AuthorizeURL string        `json:"authorize_url,omitempty"`
	TokenURL     string        `json:"token_url,omitempty"`
	UserinfoURL  string        `json:"userinfo_url,omitempty"`
	Scopes       []string      `json:"scopes,omitempty"`
	Claims       *ClaimMapping `json:"claims,omitempty"`
	// MetadataURL is where a SAML identity provider publishes its metadata,
	// fetched when the connection is saved; MetadataXML is that metadata
	// (given directly, or the last fetched copy). NameIDFormat is the NameID
	// format requested; Attributes says where the assertion keeps the
	// identity. SignRequests signs authentication requests with the
	// environment's signing key.
	MetadataURL  string            `json:"metadata_url,omitempty"`
	MetadataXML  string            `json:"metadata_xml,omitempty"`
	NameIDFormat string            `json:"name_id_format,omitempty"`
	Attributes   *AttributeMapping `json:"attributes,omitempty"`
	SignRequests bool              `json:"sign_requests,omitempty"`
	// URL is an LDAP directory (ldaps://host[:port], or ldap:// with
	// StartTLS); BindDN is the service account that searches it (its
	// password is the connection's client_secret; neither means an
	// anonymous search); UserBaseDN and UserFilter find the user ({email}
	// and {username}, the email's local part, are escaped); CAPEM trusts a
	// private certificate authority. Attributes map the directory entry.
	URL        string `json:"url,omitempty"`
	StartTLS   bool   `json:"start_tls,omitempty"`
	BindDN     string `json:"bind_dn,omitempty"`
	UserBaseDN string `json:"user_base_dn,omitempty"`
	UserFilter string `json:"user_filter,omitempty"`
	CAPEM      string `json:"ca_pem,omitempty"`
}

// AttributeMapping names the SAML attributes (Name or FriendlyName) holding
// a user's identity. Subject empty uses the NameID, which must then be
// persistent (a transient NameID changes every sign-in). Email and Name
// empty look for the usual attributes (mail, email, the emailaddress and
// name claims, displayName, givenName and sn); an email NameID is the
// email when no attribute has it.
type AttributeMapping struct {
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
}

// SAML reports whether the options configure a SAML connection.
func (o Options) SAML() bool {
	return o.MetadataURL != "" || o.MetadataXML != "" || o.NameIDFormat != "" || o.SignRequests
}

// LDAP reports whether the options configure an LDAP connection.
func (o Options) LDAP() bool {
	return o.URL != "" || o.StartTLS || o.BindDN != "" || o.UserBaseDN != "" || o.UserFilter != "" || o.CAPEM != ""
}

// LDAPServer is the scheme, host and port of the directory URL (the port
// defaults to 636 for ldaps and 389 for ldap); it is the connection's
// issuer.
func LDAPServer(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "636"
		if u.Scheme == "ldap" {
			port = "389"
		}
	}
	return u.Scheme + "://" + strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// validLDAP checks the options of an LDAP connection.
func validLDAP(o Options) error {
	u, err := url.Parse(o.URL)
	if err != nil || LDAPServer(o.URL) == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errx.Validation("options.url must be ldaps://host[:port] or ldap://host[:port]")
	}
	if u.Scheme == "ldap" && !o.StartTLS {
		return errx.Validation("options.url ldap:// requires options.start_tls; passwords never cross the network in clear text")
	}
	if u.Scheme == "ldaps" && o.StartTLS {
		return errx.Validation("options.start_tls applies to ldap:// URLs only")
	}
	if o.UserBaseDN == "" {
		return errx.Validation("options.user_base_dn is required")
	}
	for _, f := range []struct{ value, field string }{{o.BindDN, "options.bind_dn"}, {o.UserBaseDN, "options.user_base_dn"}, {o.UserFilter, "options.user_filter"}} {
		if len(f.value) > 1024 || strings.ContainsFunc(f.value, func(r rune) bool { return r < ' ' }) {
			return errx.Validation(f.field + " must be at most 1024 characters without control characters")
		}
	}
	if o.UserFilter != "" {
		if !strings.HasPrefix(o.UserFilter, "(") || !strings.HasSuffix(o.UserFilter, ")") || strings.Count(o.UserFilter, "(") != strings.Count(o.UserFilter, ")") {
			return errx.Validation("options.user_filter must be a parenthesized LDAP filter")
		}
		if !strings.Contains(o.UserFilter, "{email}") && !strings.Contains(o.UserFilter, "{username}") {
			return errx.Validation("options.user_filter must contain {email} or {username}")
		}
	}
	if o.CAPEM != "" {
		if len(o.CAPEM) > MaxLDAPCA {
			return errx.Validation("options.ca_pem is at most 64 KiB")
		}
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(o.CAPEM)) {
			return errx.Validation("options.ca_pem must hold PEM certificates")
		}
	}
	return validAttributes(o.Attributes)
}

// validAttributes checks an attribute mapping (SAML and LDAP).
func validAttributes(a *AttributeMapping) error {
	if a == nil {
		return nil
	}
	for _, name := range []string{a.Subject, a.Email, a.Name} {
		if len(name) > 512 || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' }) {
			return errx.Validation("options.attributes must be attribute names of at most 512 characters")
		}
	}
	return nil
}

// validSAML checks the options of a SAML connection.
func validSAML(o Options) error {
	if o.MetadataURL == "" && o.MetadataXML == "" {
		return errx.Validation("options.metadata_url or options.metadata_xml is required")
	}
	if o.MetadataURL != "" {
		if err := validEndpoint(o.MetadataURL, "options.metadata_url"); err != nil {
			return err
		}
	}
	if len(o.MetadataXML) > MaxMetadata {
		return errx.Validation("options.metadata_xml is at most 512 KiB")
	}
	switch o.NameIDFormat {
	case "", NameIDUnspecified, NameIDPersistent, NameIDEmail:
	case NameIDTransient:
		if o.Attributes == nil || o.Attributes.Subject == "" {
			return errx.Validation("a transient NameID changes every sign-in; options.attributes.subject must name a stable attribute")
		}
	default:
		return errx.Validation("options.name_id_format must be unspecified, persistent, email or transient")
	}
	return validAttributes(o.Attributes)
}

// SAML endpoints of a connection, under the deployment's issuer.
type ServiceProvider struct {
	// EntityID is the SP entity ID, which is also its metadata URL.
	EntityID string `json:"entity_id"`
	// ACS is the assertion consumer service (HTTP-POST) of every SAML
	// connection.
	ACS string `json:"acs_url"`
	// Metadata is the SP metadata to give the identity provider.
	Metadata string `json:"metadata_url"`
}

// SAMLServiceProvider returns the SP endpoints of a SAML connection.
func SAMLServiceProvider(issuer string, environment identity.EnvironmentID, connection identity.ConnectionID) ServiceProvider {
	metadata := issuer + "/identity/v1/federation/saml/" + environment.String() + "/" + connection.String() + "/metadata"
	return ServiceProvider{EntityID: metadata, ACS: issuer + "/identity/v1/federation/saml/acs", Metadata: metadata}
}

// ClaimMapping names the userinfo members (dotted paths into nested
// objects, such as "data.id") holding an OAuth 2.0 user's identity. Subject
// is required and must be stable. The email counts as verified only when
// EmailVerified names a member that is true: without it, the email never
// signs anyone up or links an account.
type ClaimMapping struct {
	Subject       string `json:"subject"`
	Email         string `json:"email,omitempty"`
	EmailVerified string `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

// validClaims checks the claim mapping of an OAuth 2.0 connection.
func validClaims(m *ClaimMapping) error {
	if m == nil || m.Subject == "" {
		return errx.Validation("options.claims.subject is required")
	}
	for _, p := range []string{m.Subject, m.Email, m.EmailVerified, m.Name, m.Picture} {
		if p != "" && !claimPath.MatchString(p) {
			return errx.Validation("options.claims must be member names or dotted paths such as data.id")
		}
	}
	if m.EmailVerified != "" && m.Email == "" {
		return errx.Validation("options.claims.email_verified requires options.claims.email")
	}
	return nil
}

// validEndpoint checks an HTTPS endpoint of a provider.
func validEndpoint(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return errx.Validation(field + " must be an HTTPS URL without credentials or fragment")
	}
	return nil
}

// origin is the scheme and host of an endpoint URL.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
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
	case ProviderGitLab:
		if o.BaseURL != "" {
			return o.BaseURL
		}
		return GitLabURL
	case ProviderGitHubEnterprise:
		return o.BaseURL
	case ProviderOAuth2:
		// No issuer: the authorization server's origin identifies it.
		return origin(o.AuthorizeURL)
	case ProviderLDAP:
		return LDAPServer(o.URL)
	}
	return ""
}

// Normalized lowercases and orders the options' identifiers.
func (o Options) Normalized() Options {
	o.Tenant = strings.ToLower(strings.TrimSpace(o.Tenant))
	o.Prompt = strings.TrimSpace(o.Prompt)
	tenants := make([]string, 0, len(o.Tenants))
	for _, t := range o.Tenants {
		tenants = append(tenants, strings.ToLower(strings.TrimSpace(t)))
	}
	slices.Sort(tenants)
	o.Tenants = slices.Compact(tenants)
	if len(o.Tenants) == 0 {
		o.Tenants = nil
	}
	domains := make([]string, 0, len(o.Domains))
	for _, d := range o.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if ascii, err := identity.Domain(d); err == nil {
			d = ascii
		}
		domains = append(domains, d)
	}
	slices.Sort(domains)
	o.Domains = slices.Compact(domains)
	if len(o.Domains) == 0 {
		o.Domains = nil
	}
	o.Team, o.Key = strings.ToUpper(strings.TrimSpace(o.Team)), strings.ToUpper(strings.TrimSpace(o.Key))
	o.BaseURL = strings.TrimRight(strings.TrimSpace(o.BaseURL), "/")
	o.AuthorizeURL, o.TokenURL, o.UserinfoURL = strings.TrimSpace(o.AuthorizeURL), strings.TrimSpace(o.TokenURL), strings.TrimSpace(o.UserinfoURL)
	scopes := make([]string, 0, len(o.Scopes))
	for _, s := range o.Scopes {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	o.Scopes = scopes
	if len(o.Scopes) == 0 {
		o.Scopes = nil
	}
	o.MetadataURL, o.MetadataXML = strings.TrimSpace(o.MetadataURL), strings.TrimSpace(o.MetadataXML)
	o.NameIDFormat = strings.ToLower(strings.TrimSpace(o.NameIDFormat))
	o.URL, o.BindDN, o.UserBaseDN, o.UserFilter, o.CAPEM = strings.TrimRight(strings.TrimSpace(o.URL), "/"), strings.TrimSpace(o.BindDN), strings.TrimSpace(o.UserBaseDN), strings.TrimSpace(o.UserFilter), strings.TrimSpace(o.CAPEM)
	if o.Attributes != nil {
		a := AttributeMapping{Subject: strings.TrimSpace(o.Attributes.Subject), Email: strings.TrimSpace(o.Attributes.Email), Name: strings.TrimSpace(o.Attributes.Name)}
		o.Attributes = &a
		if a == (AttributeMapping{}) {
			o.Attributes = nil
		}
	}
	if o.Claims != nil {
		m := ClaimMapping{Subject: strings.TrimSpace(o.Claims.Subject), Email: strings.TrimSpace(o.Claims.Email), EmailVerified: strings.TrimSpace(o.Claims.EmailVerified), Name: strings.TrimSpace(o.Claims.Name), Picture: strings.TrimSpace(o.Claims.Picture)}
		o.Claims = &m
	}
	return o
}

// validOptions checks the options a provider takes; other providers take
// none.
func validOptions(provider string, o Options) error {
	microsoft := o.Tenant != "" || len(o.Tenants) > 0
	apple := o.Team != "" || o.Key != ""
	google := len(o.Domains) > 0
	oauth2 := o.AuthorizeURL != "" || o.TokenURL != "" || o.UserinfoURL != "" || len(o.Scopes) > 0 || o.Claims != nil
	switch provider {
	case ProviderOIDC, ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderApple, ProviderGitLab, ProviderGitHubEnterprise, ProviderOAuth2, ProviderSAML, ProviderLDAP:
	default:
		return errx.Validation("provider must be oidc, google, microsoft, github, apple, gitlab, github_enterprise, oauth2, saml or ldap")
	}
	switch {
	case o.Prompt == "":
	case provider != ProviderMicrosoft && provider != ProviderGoogle && provider != ProviderOIDC:
		return errx.Validation("options.prompt applies to microsoft, google and oidc connections")
	case o.Prompt != PromptSelectAccount && o.Prompt != PromptLogin:
		return errx.Validation("options.prompt must be select_account, login or empty")
	}
	if microsoft && provider != ProviderMicrosoft || apple && provider != ProviderApple || google && provider != ProviderGoogle ||
		oauth2 && provider != ProviderOAuth2 || o.SAML() && provider != ProviderSAML || o.LDAP() && provider != ProviderLDAP ||
		o.Attributes != nil && provider != ProviderSAML && provider != ProviderLDAP || o.BaseURL != "" && provider != ProviderGitLab && provider != ProviderGitHubEnterprise {
		return errx.Validation("options do not apply to this provider")
	}
	switch provider {
	case ProviderGitLab:
		if o.BaseURL != "" {
			if err := validIssuer(o.BaseURL); err != nil {
				return errx.Validation("options.base_url must be the HTTPS URL of the GitLab instance")
			}
		}
	case ProviderGitHubEnterprise:
		if err := validIssuer(o.BaseURL); err != nil || o.BaseURL == "https://github.com" {
			return errx.Validation("options.base_url must be the HTTPS URL of the GitHub Enterprise Server")
		}
	case ProviderOAuth2:
		for _, e := range []struct{ raw, field string }{{o.AuthorizeURL, "options.authorize_url"}, {o.TokenURL, "options.token_url"}, {o.UserinfoURL, "options.userinfo_url"}} {
			if err := validEndpoint(e.raw, e.field); err != nil {
				return err
			}
		}
		if len(o.Scopes) > MaxScopes {
			return errx.Validation("options.scopes has at most 20 scopes")
		}
		for _, s := range o.Scopes {
			if len(s) > 200 || strings.ContainsAny(s, " \t\r\n\"\\") {
				return errx.Validation("options.scopes must be scope tokens")
			}
		}
		if err := validClaims(o.Claims); err != nil {
			return err
		}
	case ProviderSAML:
		if err := validSAML(o); err != nil {
			return err
		}
	case ProviderLDAP:
		if err := validLDAP(o); err != nil {
			return err
		}
	}
	switch provider {
	case ProviderGoogle:
		if len(o.Domains) > MaxDomains {
			return errx.Validation("options.domains has at most 100 domains")
		}
		for _, d := range o.Domains {
			if valid, err := identity.Domain(d); err != nil || valid != d {
				return errx.Validation("options.domains must be domains such as example.com")
			}
		}
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

// AcceptsHostedDomain reports whether a Google connection accepts an
// account of the Workspace domain hd (empty for personal accounts).
func (o Options) AcceptsHostedDomain(hd string) bool {
	return len(o.Domains) == 0 || hd != "" && slices.Contains(o.Domains, strings.ToLower(hd))
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
	AvatarURL    string
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
