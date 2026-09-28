package iamclient

import (
	"context"
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
}

type OAuthClient struct {
	ApplicationID string   `json:"application_id"`
	ResourceID    string   `json:"resource_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	Public        bool     `json:"public"`
	// HostedLogin sends /oauth/authorize to IAMKit's hosted sign-in pages
	// instead of returning the authorization ticket to your UI.
	HostedLogin bool `json:"hosted_login,omitempty"`
}

// OAuthClientPatch changes an OAuth client; nil fields are unchanged.
type OAuthClientPatch struct {
	HostedLogin *bool `json:"hosted_login,omitempty"`
}

type OAuthCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Federation providers. Presets derive their issuer; ProviderOIDC (the
// default) needs Issuer.
const (
	ProviderOIDC      = "oidc"
	ProviderGoogle    = "google"
	ProviderMicrosoft = "microsoft"
	ProviderGitHub    = "github"
	ProviderApple     = "apple"
)

// FederationOptions configures a preset provider. Microsoft requires Tenant
// ("common", "organizations", "consumers" or a tenant ID) and takes Tenants
// to restrict common/organizations. Google takes Domains to accept only
// Google Workspace accounts of those domains. Apple requires TeamID and KeyID.
type FederationOptions struct {
	Tenant  string   `json:"tenant,omitempty"`
	Tenants []string `json:"tenants,omitempty"`
	Domains []string `json:"domains,omitempty"`
	TeamID  string   `json:"team_id,omitempty"`
	KeyID   string   `json:"key_id,omitempty"`
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
	// Environment connections only.
	Signup               bool   `json:"signup,omitempty"`
	LinkEmail            bool   `json:"link_email,omitempty"`
	SignupOrganizationID string `json:"signup_organization_id,omitempty"`
	SignupGroupID        string `json:"signup_group_id,omitempty"`
	// JITProvisioning defaults to true for organization connections.
	JITProvisioning *bool  `json:"jit_provisioning,omitempty"`
	JITGroupID      string `json:"jit_group_id,omitempty"`
	// Enforcement is "optional" (default) or "enforced".
	Enforcement string `json:"enforcement,omitempty"`
	// Read-only.
	CallbackURL  string     `json:"callback_url,omitempty"`
	SecretSource string     `json:"secret_source,omitempty"`
	Active       bool       `json:"active,omitempty"`
	Linked       int        `json:"linked,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
}

// FederationPatch changes a connection; nil fields are left unchanged.
// JITGroupID and SignupGroupID set to "" clear the group; Signup false also
// clears the sign-up organization and group. Setting ClientSecret on a
// secret_env connection converts it to an encrypted secret. Options replace
// the options whole; the Microsoft tenant cannot change, and a new Apple
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

// ── Impersonation ──

func (e Environment) Impersonate(ctx context.Context, input Impersonation) (authclient.TokenPair, error) {
	var out authclient.TokenPair
	err := e.operation(ctx, "POST", []string{"impersonations"}, input, &out)
	return out, err
}
