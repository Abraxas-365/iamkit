package iamclient

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

// ── Shared admin types ──

type UserPatch struct {
	OTPEnabled *bool          `json:"otp_enabled,omitempty"`
	Name       *string        `json:"name,omitempty"`
	Active     *bool          `json:"active,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	// Phone sets the user's number in E.164 ("" clears it); a changed
	// number is unverified until the user confirms it with a texted code.
	Phone *string `json:"phone,omitempty"`
	// PhoneVerified marks the number verified or not (audited); true
	// needs a number.
	PhoneVerified *bool `json:"phone_verified,omitempty"`
	// AvatarURL sets the picture, an https URL ("" removes it).
	AvatarURL *string `json:"avatar_url,omitempty"`
	// Username sets the username ("" removes it).
	Username *string `json:"username,omitempty"`
	// HomeOrganizationID moves the record to another organization the
	// user belongs to ("" clears it).
	HomeOrganizationID *string `json:"home_organization_id,omitempty"`
}

type MemberProfile struct {
	OrgUnitID *string `json:"org_unit_id"`
	ManagerID *string `json:"manager_id"`
}

type PositionAssignment struct {
	ID         string  `json:"id,omitempty"`
	PositionID string  `json:"position_id"`
	UserID     string  `json:"user_id"`
	OrgUnitID  *string `json:"org_unit_id"`
}

type ServiceAccount struct {
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name"`
	ApplicationID string   `json:"application_id"`
	ResourceID    string   `json:"resource_id"`
	Permissions   []string `json:"permissions"`
	ExpiresIn     string   `json:"expires_in,omitempty"`
	// CanImpersonate: the account may exchange a user ID for that user's
	// token (token exchange). Read-only here; see SetServiceAccountImpersonation.
	CanImpersonate bool `json:"can_impersonate,omitempty"`
	// ClientAuthentication is how the account authenticates at /oauth/token
	// (client_credentials); client_secret_basic when empty.
	ClientAuthentication
}

// Token endpoint authentication methods.
const (
	AuthClientSecretBasic = "client_secret_basic"
	AuthClientSecretPost  = "client_secret_post"
	AuthPrivateKeyJWT     = "private_key_jwt"
)

// ClientAuthentication is how an OAuth client or a service account
// authenticates at /oauth/token. private_key_jwt needs JWKS (a JSON Web
// Key Set of public keys) or JWKSURI (HTTPS); SigningAlg defaults to RS256.
type ClientAuthentication struct {
	Method     string          `json:"token_endpoint_auth_method,omitempty"`
	SigningAlg string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	JWKS       json.RawMessage `json:"jwks,omitempty"`
	JWKSURI    string          `json:"jwks_uri,omitempty"`
}

type ServiceAccountKey struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Credential struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	ConnectionID string    `json:"connection_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	// AdoptExistingMembers links SCIM-created users to existing organization
	// members with the same email instead of failing with 409.
	AdoptExistingMembers *bool `json:"adopt_existing_members,omitempty"`
	// AdoptScope is "any" or "verified_domains" (adopt only emails on the
	// organization's verified domains). nil keeps the current setting.
	AdoptScope *string `json:"adopt_scope,omitempty"`
	// MapPhone maps SCIM phoneNumbers[type eq "mobile"] to the user's
	// phone number (off by default). nil keeps the current setting.
	MapPhone *bool `json:"map_phone,omitempty"`
}

type OAuthClient struct {
	ApplicationID string   `json:"application_id"`
	ResourceID    string   `json:"resource_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	Public        bool     `json:"public"`
	// HostedLogin sends /oauth/authorize to IAMKit's hosted sign-in pages
	// instead of returning the authorization ticket to your UI.
	HostedLogin bool `json:"hosted_login,omitempty"`
	// PostLogoutRedirectURIs are where /oauth/end_session may send the
	// browser back (exact match on post_logout_redirect_uri).
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// AllowedOrigins are browser origins (https://app.example.com) of a
	// custom sign-in UI or single-page application, allowed to call
	// /identity/v1 and the browser-facing /oauth endpoints with CORS.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AccessTokenFormat is AccessTokenJWT (default) or AccessTokenOpaque.
	// Opaque tokens are resolved only by /oauth/introspect and
	// /oauth/userinfo: resource APIs and authclient.Validator accept JWTs.
	AccessTokenFormat string `json:"access_token_format,omitempty"`
	// GrantTypes are the grants the client may use (empty: authorization
	// code + refresh token). GrantDeviceCode needs HostedLogin; a client
	// without GrantAuthorizationCode needs no RedirectURIs.
	GrantTypes []string `json:"grant_types,omitempty"`
	// BackchannelLogoutURI receives an OpenID Connect Back-Channel Logout
	// token (form field logout_token) whenever a session this client signed
	// in ends. See authclient.ValidateLogoutToken.
	BackchannelLogoutURI             string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required,omitempty"`
	// ClientAuthentication of confidential clients (client_secret_basic
	// when empty; public clients always use none).
	ClientAuthentication
}

// OAuth client grant types.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	// GrantTokenExchange (RFC 8693) is for confidential clients only.
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// OAuth access token formats.
const (
	AccessTokenJWT    = "jwt"
	AccessTokenOpaque = "opaque"
)

// OAuthClientPatch changes an OAuth client; nil fields are unchanged.
type OAuthClientPatch struct {
	HostedLogin            *bool     `json:"hosted_login,omitempty"`
	RedirectURIs           *[]string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs *[]string `json:"post_logout_redirect_uris,omitempty"`
	AccessTokenFormat      *string   `json:"access_token_format,omitempty"`
	// GrantTypes replaces the client's grants.
	GrantTypes *[]string `json:"grant_types,omitempty"`
	// AllowedOrigins replaces the client's CORS origins.
	AllowedOrigins *[]string `json:"allowed_origins,omitempty"`
	// BackchannelLogoutURI "" turns back-channel logout off.
	BackchannelLogoutURI             *string `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired *bool   `json:"backchannel_logout_session_required,omitempty"`
	// Authentication, when set, replaces the token endpoint
	// authentication (switching away from private_key_jwt drops the keys).
	TokenEndpointAuthMethod *string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthAlg    *string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	JWKS                    *json.RawMessage `json:"jwks,omitempty"`
	JWKSURI                 *string          `json:"jwks_uri,omitempty"`
}

type OAuthCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Federation providers. Presets derive their issuer; ProviderOIDC (the
// default) needs Issuer.
const (
	ProviderOIDC             = "oidc"
	ProviderGoogle           = "google"
	ProviderMicrosoft        = "microsoft"
	ProviderGitHub           = "github"
	ProviderApple            = "apple"
	ProviderGitLab           = "gitlab"
	ProviderGitHubEnterprise = "github_enterprise"
	ProviderOAuth2           = "oauth2"
	// ProviderSAML is a SAML 2.0 identity provider; organization
	// connections only, configured by MetadataURL or MetadataXML.
	ProviderSAML = "saml"
	// ProviderLDAP is an LDAP / Active Directory server; organization
	// connections only, configured by URL and UserBaseDN.
	ProviderLDAP = "ldap"
)

// SAML NameID formats for FederationOptions.NameIDFormat.
const (
	NameIDUnspecified = "unspecified"
	NameIDPersistent  = "persistent"
	NameIDEmail       = "email"
	NameIDTransient   = "transient"
)

// FederationOptions configures a preset provider. Microsoft requires Tenant
// ("common", "organizations", "consumers" or a tenant ID) and takes Tenants
// to restrict common/organizations. Google takes Domains to accept only
// Google Workspace accounts of those domains. Apple requires TeamID and KeyID.
// GitLab takes BaseURL for a self-managed instance (gitlab.com otherwise);
// GitHub Enterprise requires it. OAuth 2.0 requires the three endpoints and
// Claims; its issuer is the authorization endpoint's origin. SAML requires
// MetadataURL (HTTPS, fetched on create and on every update that sends it)
// or MetadataXML; its issuer is the identity provider's entity ID, which
// cannot change. A transient NameIDFormat needs Attributes.Subject. LDAP
// requires URL (ldaps://, or ldap:// with StartTLS) and UserBaseDN; BindDN
// takes its password as the connection's ClientSecret (omit both for an
// anonymous search). UserFilter holds {email} or {username} (default
// "(|(mail={email})(userPrincipalName={email}))"); CAPEM trusts a private
// CA; Attributes map the subject, email and name attributes. The directory
// host and UserBaseDN cannot change.
type FederationOptions struct {
	Tenant       string              `json:"tenant,omitempty"`
	Tenants      []string            `json:"tenants,omitempty"`
	Domains      []string            `json:"domains,omitempty"`
	TeamID       string              `json:"team_id,omitempty"`
	KeyID        string              `json:"key_id,omitempty"`
	BaseURL      string              `json:"base_url,omitempty"`
	AuthorizeURL string              `json:"authorize_url,omitempty"`
	TokenURL     string              `json:"token_url,omitempty"`
	UserinfoURL  string              `json:"userinfo_url,omitempty"`
	Scopes       []string            `json:"scopes,omitempty"`
	Claims       *FederationClaimMap `json:"claims,omitempty"`
	MetadataURL  string              `json:"metadata_url,omitempty"`
	MetadataXML  string              `json:"metadata_xml,omitempty"`
	NameIDFormat string              `json:"name_id_format,omitempty"`
	Attributes   *SAMLAttributes     `json:"attributes,omitempty"`
	SignRequests bool                `json:"sign_requests,omitempty"`
	URL          string              `json:"url,omitempty"`
	StartTLS     bool                `json:"start_tls,omitempty"`
	BindDN       string              `json:"bind_dn,omitempty"`
	UserBaseDN   string              `json:"user_base_dn,omitempty"`
	UserFilter   string              `json:"user_filter,omitempty"`
	CAPEM        string              `json:"ca_pem,omitempty"`
}

// SAMLAttributes names the assertion (SAML) or entry (LDAP) attributes
// holding the identity.
// Empty Subject uses the NameID; empty Email and Name use the usual
// attributes (mail, email, displayName, givenName + sn, their OIDs…).
type SAMLAttributes struct {
	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
}

// SAMLServiceProvider is what a SAML identity provider is configured with:
// the SP entity ID (audience), the HTTP-POST ACS URL and the SP metadata
// URL (the same as the entity ID).
type SAMLServiceProvider struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"metadata_url"`
}

// FederationClaimMap says where an OAuth 2.0 provider's user info JSON keeps
// the identity: dotted member paths such as "data.id". Subject is required.
// Without EmailVerified the email is never trusted for sign-up or linking.
type FederationClaimMap struct {
	Subject       string `json:"subject"`
	Email         string `json:"email,omitempty"`
	EmailVerified string `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// Federation is an identity provider connection. Set OrganizationID for an
// organization connection (SSO, JIT provisioning, enforcement); leave it
// empty for an environment (social login) connection, which may sign up
// new users into SignupOrganizationID and link existing users by verified
// email. On create, provide exactly one of ClientSecret (stored encrypted;
// requires IAMKIT_ENCRYPTION_KEY; for Apple the .p8 PEM) or SecretEnv (an
// approved deployment variable). ClientSecret is never returned.
type Federation struct {
	ID             string             `json:"id,omitempty"`
	OrganizationID string             `json:"organization_id,omitempty"`
	Name           string             `json:"name"`
	Provider       string             `json:"provider,omitempty"`
	Options        *FederationOptions `json:"options,omitempty"`
	// Issuer is required for ProviderOIDC; presets return the derived one.
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id"`
	SecretEnv    string `json:"secret_env,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	// LinkEmail links existing users by verified email; on an organization
	// connection only members whose email is on its verified domains.
	LinkEmail bool `json:"link_email,omitempty"`
	// UpdateProfile refreshes a linked user's name, and the email of a
	// passwordless account, from the provider at every sign-in.
	UpdateProfile bool `json:"update_profile,omitempty"`
	// Environment connections only.
	Signup               bool   `json:"signup,omitempty"`
	SignupOrganizationID string `json:"signup_organization_id,omitempty"`
	SignupGroupID        string `json:"signup_group_id,omitempty"`
	// JITProvisioning defaults to true for organization connections.
	JITProvisioning *bool  `json:"jit_provisioning,omitempty"`
	JITGroupID      string `json:"jit_group_id,omitempty"`
	// Enforcement is "optional" (default) or "enforced".
	Enforcement string `json:"enforcement,omitempty"`
	// Read-only. SecretSource is "env", "sealed" or "none" (SAML); SAML
	// is set on SAML connections.
	CallbackURL  string               `json:"callback_url,omitempty"`
	SAML         *SAMLServiceProvider `json:"saml,omitempty"`
	SecretSource string               `json:"secret_source,omitempty"`
	Active       bool                 `json:"active,omitempty"`
	Linked       int                  `json:"linked,omitempty"`
	CreatedAt    *time.Time           `json:"created_at,omitempty"`
}

// FederationPatch changes a connection; nil fields are left unchanged.
// JITGroupID and SignupGroupID set to "" clear the group; Signup false also
// clears the sign-up organization and group. Setting ClientSecret on a
// secret_env connection converts it to an encrypted secret. Options replace
// the options whole; the Microsoft tenant, Apple team and BaseURL cannot
// change, an OAuth 2.0 AuthorizeURL must keep its host, and a new Apple
// KeyID needs a new ClientSecret.
type FederationPatch struct {
	Name                 *string            `json:"name,omitempty"`
	ClientSecret         *string            `json:"client_secret,omitempty"`
	JITProvisioning      *bool              `json:"jit_provisioning,omitempty"`
	JITGroupID           *string            `json:"jit_group_id,omitempty"`
	Enforcement          *string            `json:"enforcement,omitempty"`
	Options              *FederationOptions `json:"options,omitempty"`
	Signup               *bool              `json:"signup,omitempty"`
	LinkEmail            *bool              `json:"link_email,omitempty"`
	UpdateProfile        *bool              `json:"update_profile,omitempty"`
	SignupOrganizationID *string            `json:"signup_organization_id,omitempty"`
	SignupGroupID        *string            `json:"signup_group_id,omitempty"`
}

type ExternalIdentity struct {
	ConnectionID string `json:"connection_id"`
	UserID       string `json:"user_id"`
	Subject      string `json:"subject"`
	// Read-only: "linked" by an operator, "jit" on an organization
	// connection's first login, "email" (linked by verified email) or
	// "signup" on an environment connection's first login.
	Origin    string     `json:"origin,omitempty"`
	UserName  string     `json:"user_name,omitempty"`
	UserEmail string     `json:"user_email,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// Domain is an organization's email domain. Verified domains route email
// discovery to the organization's SSO and bound JIT provisioning.
type Domain struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Domain         string     `json:"domain"`
	Verified       bool       `json:"verified"`
	VerifiedAt     *time.Time `json:"verified_at"`
	Method         *string    `json:"verification_method"`
	CreatedAt      time.Time  `json:"created_at"`
	VerifiedBy     *string    `json:"verified_by"`
	Record         DNSRecord  `json:"verification"`
}

// DNSRecord is the TXT record that proves domain ownership.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MemberPatch changes a membership. SSOBypass lets the member keep using
// password login where the organization enforces SSO (break-glass).
type MemberPatch struct {
	SSOBypass *bool `json:"sso_bypass,omitempty"`
}

type Session struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	OrganizationID string     `json:"organization_id"`
	ApplicationID  string     `json:"application_id"`
	ResourceID     string     `json:"resource_id"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
}

type AuditEvent struct {
	ID        int64     `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Impersonation struct {
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
	UserID         string `json:"user_id"`
	Reason         string `json:"reason"`
}

type UnitImpact struct {
	HasChildren   bool     `json:"has_children"`
	UserIDs       []string `json:"affected_user_ids"`
	AssignmentIDs []string `json:"assignment_ids"`
}

type ReportingMember struct {
	UserID    string  `json:"user_id"`
	ManagerID *string `json:"manager_id"`
	OrgUnitID *string `json:"org_unit_id"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
}

// ── Domains ──

// AddDomain registers a domain; publish its Record in DNS, then call
// VerifyDomain.
func (e Environment) AddDomain(ctx context.Context, org, domain string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains"}, map[string]string{"domain": domain}, &out)
	return out, err
}

func (e Environment) Domains(ctx context.Context, org string) ([]Domain, error) {
	return listOp[Domain](e, ctx, []string{"organizations", org, "domains"})
}

func (e Environment) Domain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "GET", []string{"organizations", org, "domains", id}, nil, &out)
	return out, err
}

// VerifyDomain checks the DNS TXT record now.
func (e Environment) VerifyDomain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains", id, "verify"}, nil, &out)
	return out, err
}

// ForceVerifyDomain marks the domain verified without DNS (audited).
func (e Environment) ForceVerifyDomain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains", id, "force-verify"}, nil, &out)
	return out, err
}

func (e Environment) DeleteDomain(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "domains", id}, nil, nil)
}

// UpdateMember changes a membership, e.g. the SSO break-glass bypass.
func (e Environment) UpdateMember(ctx context.Context, org, user string, input MemberPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", org, "members", user}, input, nil)
}

// ── Invitations ──

// Invitation invites an email address into an organization. Status is one
// of pending, accepted, revoked or expired.
type Invitation struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	RoleIDs        []string   `json:"role_ids"`
	GroupIDs       []string   `json:"group_ids"`
	Inviter        string     `json:"inviter"`
	ExpiresAt      time.Time  `json:"expires_at"`
	AcceptedAt     *time.Time `json:"accepted_at"`
	AcceptedUserID string     `json:"accepted_user_id,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
	Status         string     `json:"status"`
}

// IssuedInvitation is returned once by Invite and ResendInvitation: Token
// (and Link, when the environment has an invitation_url) are never shown
// again. Delivery is "sent", "failed" or "skipped".
type IssuedInvitation struct {
	Invitation
	Token    string `json:"token"`
	Link     string `json:"link,omitempty"`
	Delivery string `json:"delivery"`
}

type InvitationInput struct {
	Email    string   `json:"email"`
	RoleIDs  []string `json:"role_ids,omitempty"`
	GroupIDs []string `json:"group_ids,omitempty"`
}

func (e Environment) Invite(ctx context.Context, org string, input InvitationInput) (IssuedInvitation, error) {
	var out IssuedInvitation
	err := e.operation(ctx, "POST", []string{"organizations", org, "invitations"}, input, &out)
	return out, err
}

// Invitations lists an organization's invitations; status "" returns all
// (filtered client-side on the first page).
func (e Environment) Invitations(ctx context.Context, org, status string) ([]Invitation, error) {
	all, err := listOp[Invitation](e, ctx, []string{"organizations", org, "invitations"})
	if err != nil || status == "" {
		return all, err
	}
	out := []Invitation{}
	for _, inv := range all {
		if inv.Status == status {
			out = append(out, inv)
		}
	}
	return out, nil
}

func (e Environment) Invitation(ctx context.Context, org, id string) (Invitation, error) {
	var out Invitation
	err := e.operation(ctx, "GET", []string{"organizations", org, "invitations", id}, nil, &out)
	return out, err
}

// ResendInvitation issues a new token (the previous one stops working) and
// restarts the expiry.
func (e Environment) ResendInvitation(ctx context.Context, org, id string) (IssuedInvitation, error) {
	var out IssuedInvitation
	err := e.operation(ctx, "POST", []string{"organizations", org, "invitations", id, "resend"}, nil, &out)
	return out, err
}

func (e Environment) RevokeInvitation(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "invitations", id}, nil, nil)
}

// ── operation helper for safe path composition ──

func (e Environment) operation(ctx context.Context, method string, parts []string, input, output any) error {
	for _, part := range parts {
		if err := safeSegment(part); err != nil {
			return err
		}
	}
	return e.client.Do(ctx, method, e.path(strings.Join(parts, "/")), input, output)
}

// ── Service Accounts ──

func (e Environment) CreateServiceAccount(ctx context.Context, input ServiceAccount) (ServiceAccountKey, error) {
	var out ServiceAccountKey
	err := e.operation(ctx, "POST", []string{"service-accounts"}, input, &out)
	return out, err
}

func (e Environment) ServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return listOp[ServiceAccount](e, ctx, []string{"service-accounts"})
}

// ServiceAccount reads one service account (never its secret).
func (e Environment) ServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	var out ServiceAccount
	err := e.operation(ctx, "GET", []string{"service-accounts", id}, nil, &out)
	return out, err
}

// SetServiceAccountAuthentication changes how the account authenticates at
// /oauth/token (client_credentials).
func (e Environment) SetServiceAccountAuthentication(ctx context.Context, id string, input ClientAuthentication) (ServiceAccount, error) {
	var out ServiceAccount
	err := e.operation(ctx, "PUT", []string{"service-accounts", id, "authentication"}, input, &out)
	return out, err
}

// SetServiceAccountImpersonation allows or forbids the account to
// impersonate users through token exchange. Only workspace owners may
// change it; forbidding it ends the sessions the account opened.
func (e Environment) SetServiceAccountImpersonation(ctx context.Context, id string, allowed bool) (ServiceAccount, error) {
	var out ServiceAccount
	err := e.operation(ctx, "PUT", []string{"service-accounts", id, "impersonation"}, map[string]bool{"allowed": allowed}, &out)
	return out, err
}

func (e Environment) RevokeServiceAccount(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"service-accounts", id}, nil, nil)
}

// ── Provisioning Credentials ──

func (e Environment) CreateProvisioningCredential(ctx context.Context, input Credential) (Credential, error) {
	var out Credential
	err := e.operation(ctx, "POST", []string{"provisioning-credentials"}, input, &out)
	return out, err
}

func (e Environment) ProvisioningCredentials(ctx context.Context) ([]Credential, error) {
	return listOp[Credential](e, ctx, []string{"provisioning-credentials"})
}

func (e Environment) RevokeProvisioningCredential(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"provisioning-credentials", id}, nil, nil)
}

// ── OAuth Clients ──

func (e Environment) CreateOAuthClient(ctx context.Context, input OAuthClient) (OAuthCredential, error) {
	var out OAuthCredential
	err := e.operation(ctx, "POST", []string{"oauth-clients"}, input, &out)
	return out, err
}

func (e Environment) OAuthClients(ctx context.Context) ([]OAuthCredential, error) {
	return listOp[OAuthCredential](e, ctx, []string{"oauth-clients"})
}

func (e Environment) DisableOAuthClient(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"oauth-clients", id}, nil, nil)
}

func (e Environment) UpdateOAuthClient(ctx context.Context, id string, input OAuthClientPatch) error {
	return e.operation(ctx, "PATCH", []string{"oauth-clients", id}, input, nil)
}

// ── Federation ──

func (e Environment) CreateFederation(ctx context.Context, input Federation) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"federation-connections"}, input, &out)
	return out, err
}

func (e Environment) FederationConnections(ctx context.Context) ([]Federation, error) {
	return listOp[Federation](e, ctx, []string{"federation-connections"})
}

// OrganizationFederations lists the connections of one organization.
func (e Environment) OrganizationFederations(ctx context.Context, org string) ([]Federation, error) {
	if err := safeSegment(org); err != nil {
		return nil, err
	}
	all, err := e.FederationConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := []Federation{}
	for _, f := range all {
		if f.OrganizationID == org {
			out = append(out, f)
		}
	}
	return out, nil
}

func (e Environment) UpdateFederation(ctx context.Context, id string, input FederationPatch) error {
	return e.operation(ctx, "PATCH", []string{"federation-connections", id}, input, nil)
}

func (e Environment) FederationConnection(ctx context.Context, id string) (Federation, error) {
	var out Federation
	err := e.operation(ctx, "GET", []string{"federation-connections", id}, nil, &out)
	return out, err
}

func (e Environment) FederationIdentities(ctx context.Context, id string) ([]ExternalIdentity, error) {
	return listOp[ExternalIdentity](e, ctx, []string{"federation-connections", id, "identities"})
}

func (e Environment) DisableFederation(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"federation-connections", id}, nil, nil)
}

func (e Environment) LinkExternalIdentity(ctx context.Context, input ExternalIdentity) error {
	return e.operation(ctx, "POST", []string{"external-identities"}, input, nil)
}

func (e Environment) UnlinkExternalIdentity(ctx context.Context, connection, user string) error {
	return e.operation(ctx, "DELETE", []string{"external-identities", connection, user}, nil, nil)
}

// ── Provisioned Identities ──

func (e Environment) LinkProvisionedIdentity(ctx context.Context, connection, user, external string) error {
	return e.operation(ctx, "POST", []string{"provisioned-identities"}, map[string]string{"connection_id": connection, "user_id": user, "external_id": external}, nil)
}

// ── Sessions & Audit ──

func (e Environment) Sessions(ctx context.Context) ([]Session, error) {
	return listOp[Session](e, ctx, []string{"sessions"})
}

func (e Environment) RevokeSession(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"sessions", id}, nil, nil)
}

func (e Environment) AuditEvents(ctx context.Context) ([]AuditEvent, error) {
	return listOp[AuditEvent](e, ctx, []string{"audit-events"})
}

// LogoutDelivery is a back-channel logout notification. Status is
// "pending" (queued or retrying), "delivered" or "failed" (given up).
type LogoutDelivery struct {
	ID              string     `json:"id"`
	ClientID        string     `json:"client_id"`
	ApplicationName string     `json:"application_name"`
	SessionID       string     `json:"session_id"`
	UserID          string     `json:"user_id"`
	UserEmail       string     `json:"user_email"`
	Status          string     `json:"status"`
	Attempts        int        `json:"attempts"`
	LastError       string     `json:"last_error"`
	CreatedAt       time.Time  `json:"created_at"`
	NextAttemptAt   *time.Time `json:"next_attempt_at"`
	DeliveredAt     *time.Time `json:"delivered_at"`
	FailedAt        *time.Time `json:"failed_at"`
}

// LogoutDeliveries lists back-channel logout notifications, newest first;
// status "" lists all.
func (e Environment) LogoutDeliveries(ctx context.Context, status string) ([]LogoutDelivery, error) {
	collection := "logout-deliveries"
	if status != "" {
		if err := safeSegment(status); err != nil {
			return nil, err
		}
		collection += "?status=" + status
	}
	return list[LogoutDelivery](e, ctx, collection)
}

// RetryLogoutDelivery queues a failed notification again.
func (e Environment) RetryLogoutDelivery(ctx context.Context, id string) error {
	return e.operation(ctx, "POST", []string{"logout-deliveries", id, "retry"}, map[string]any{}, nil)
}

// ── Impersonation ──

func (e Environment) Impersonate(ctx context.Context, input Impersonation) (authclient.TokenPair, error) {
	var out authclient.TokenPair
	err := e.operation(ctx, "POST", []string{"impersonations"}, input, &out)
	return out, err
}

// ── Signing keys ──

// SigningKey is an environment signing key. State is "next" (published,
// not signing yet), "active" (signs the environment's tokens), "retiring"
// (replaced, verifies until RetireAfter) or "retired". An environment
// without an active key signs with the deployment key.
type SigningKey struct {
	ID          string          `json:"kid"`
	Environment string          `json:"environment_id"`
	Algorithm   string          `json:"alg"`
	State       string          `json:"state"`
	CreatedAt   time.Time       `json:"created_at"`
	ActivatedAt *time.Time      `json:"activated_at,omitempty"`
	RetireAfter *time.Time      `json:"retire_after,omitempty"`
	RetiredAt   *time.Time      `json:"retired_at,omitempty"`
	PublicJWK   json.RawMessage `json:"public_jwk,omitempty"`
}

// SigningKeys lists the environment's keys, active first.
func (e Environment) SigningKeys(ctx context.Context) ([]SigningKey, error) {
	return listOp[SigningKey](e, ctx, []string{"signing-keys"})
}

// SigningKey returns one key by kid.
func (e Environment) SigningKey(ctx context.Context, kid string) (SigningKey, error) {
	var out SigningKey
	err := e.operation(ctx, "GET", []string{"signing-keys", kid}, nil, &out)
	return out, err
}

// CreateSigningKey generates a "next" key, published in the JWKS at once.
// Needs IAMKIT_ENCRYPTION_KEY (ENCRYPTION_KEY_REQUIRED otherwise). Audited
// as signing_key.create.
func (e Environment) CreateSigningKey(ctx context.Context) (SigningKey, error) {
	var out SigningKey
	err := e.operation(ctx, "POST", []string{"signing-keys"}, nil, &out)
	return out, err
}

// ActivateSigningKey makes kid sign the environment's tokens; the previous
// active key becomes "retiring". Activate a key some minutes after
// creating it so relying parties caching the JWKS have fetched it.
// Audited as signing_key.activate.
func (e Environment) ActivateSigningKey(ctx context.Context, kid string) (SigningKey, error) {
	var out SigningKey
	err := e.operation(ctx, "POST", []string{"signing-keys", kid, "activate"}, nil, &out)
	return out, err
}

// RetireSigningKey unpublishes a next or retiring key. A retiring key needs
// force before its RetireAfter (tokens it signed stop validating at once):
// KEY_IN_USE otherwise. Audited as signing_key.retire.
func (e Environment) RetireSigningKey(ctx context.Context, kid string, force bool) (SigningKey, error) {
	var out SigningKey
	err := e.operation(ctx, "POST", []string{"signing-keys", kid, "retire"}, map[string]bool{"force": force}, &out)
	return out, err
}

// ── SAML applications (IAMKit as the identity provider) ──

// SAMLIdentityProvider is what a service provider needs to trust the
// environment: its metadata URL, or the entity ID, SSO URL and signing
// certificate (PEM; it changes when the signing key is rotated).
type SAMLIdentityProvider struct {
	EntityID    string `json:"entity_id"`
	SSOURL      string `json:"sso_url"`
	MetadataURL string `json:"metadata_url"`
	Certificate string `json:"certificate"`
}

// SAMLApp is a SAML service provider (an application that signs users in
// with SAML 2.0, IAMKit being the identity provider).
// NameIDFormat is "email" or "persistent" (the user ID); Attributes maps
// SAML attribute names to "email", "name", "user_id", "organization_id" or
// "permissions" (the user's permissions on the resource).
type SAMLApp struct {
	ID              string            `json:"id"`
	Environment     string            `json:"environment_id"`
	Name            string            `json:"name"`
	Application     string            `json:"application_id"`
	ApplicationName string            `json:"application_name"`
	Resource        string            `json:"resource_id"`
	ResourceName    string            `json:"resource_name"`
	EntityID        string            `json:"entity_id"`
	ACSURLs         []string          `json:"acs_urls"`
	NameIDFormat    string            `json:"name_id_format"`
	Attributes      map[string]string `json:"attributes"`
	CreatedAt       time.Time         `json:"created_at"`
}

// CreateSAMLApp registers a service provider. The resource must
// be linked to the application; ACS URLs must be HTTPS.
type CreateSAMLApp struct {
	Name         string            `json:"name"`
	Application  string            `json:"application_id"`
	Resource     string            `json:"resource_id"`
	EntityID     string            `json:"entity_id"`
	ACSURLs      []string          `json:"acs_urls"`
	NameIDFormat string            `json:"name_id_format,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

// UpdateSAMLApp changes the non-nil fields; Attributes
// replaces the whole map.
type UpdateSAMLApp struct {
	Name         *string            `json:"name,omitempty"`
	ACSURLs      *[]string          `json:"acs_urls,omitempty"`
	NameIDFormat *string            `json:"name_id_format,omitempty"`
	Attributes   *map[string]string `json:"attributes,omitempty"`
}

// SAMLIdentityProvider returns the environment's IdP settings.
func (e Environment) SAMLIdentityProvider(ctx context.Context) (SAMLIdentityProvider, error) {
	var out SAMLIdentityProvider
	err := e.operation(ctx, "GET", []string{"saml", "identity-provider"}, nil, &out)
	return out, err
}

// SAMLApps lists the registered service providers.
func (e Environment) SAMLApps(ctx context.Context) ([]SAMLApp, error) {
	return listOp[SAMLApp](e, ctx, []string{"saml", "service-providers"})
}

// SAMLApp returns one service provider.
func (e Environment) SAMLApp(ctx context.Context, id string) (SAMLApp, error) {
	var out SAMLApp
	err := e.operation(ctx, "GET", []string{"saml", "service-providers", id}, nil, &out)
	return out, err
}

// CreateSAMLApp registers a service provider (409 when the
// entity ID is taken or the resource is not linked to the application).
// Audited as saml_service_provider.create.
func (e Environment) CreateSAMLApp(ctx context.Context, input CreateSAMLApp) (SAMLApp, error) {
	var out SAMLApp
	err := e.operation(ctx, "POST", []string{"saml", "service-providers"}, input, &out)
	return out, err
}

// UpdateSAMLApp changes a service provider. Audited as
// saml_service_provider.update.
func (e Environment) UpdateSAMLApp(ctx context.Context, id string, input UpdateSAMLApp) (SAMLApp, error) {
	var out SAMLApp
	err := e.operation(ctx, "PATCH", []string{"saml", "service-providers", id}, input, &out)
	return out, err
}

// DeleteSAMLApp removes a service provider; its pending
// sign-ins fail. Audited as saml_service_provider.delete.
func (e Environment) DeleteSAMLApp(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"saml", "service-providers", id}, nil, nil)
}
