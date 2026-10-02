package apiclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// ── Organization administration ──
//
// OrgAdmin calls /organizations/<id>/admin/* with the token of an end user
// who signed in to that organization for the environment's IAM resource.
// The user's iam:org:* permissions (from the built-in roles Organization
// owner, Organization viewer, User manager, Settings manager and Resource
// manager) decide what each call may do:
//
//	admin := apiclient.New(base, userToken).Environment(env).OrgAdmin(org)
//	members, err := admin.Members(ctx)
//
// Administrators assign roles of the IAM resource whose permissions they
// hold and roles of resources the organization owns or was granted; only
// owners grant or act on ownership, the last owner stays, and user-record
// writes apply to users homed in the organization.

// OrgAdmin returns the administration handle of one organization.
func (e Environment) OrgAdmin(organization string) OrgAdmin {
	return OrgAdmin{env: e, org: organization}
}

// OrgAdmin administers one organization; see Environment.OrgAdmin.
type OrgAdmin struct {
	env Environment
	org string
}

func (a OrgAdmin) path(segments ...string) string {
	return a.env.path(append([]string{"organizations", a.org, "admin"}, segments...)...)
}

// OrgSettings are the organization fields its administrators may change
// (iam:org:settings:write); nil fields stay unchanged.
type OrgSettings struct {
	Name            *string  `json:"name,omitempty"`
	MFARequired     *bool    `json:"mfa_required,omitempty"`
	MFAForFederated *bool    `json:"mfa_for_federated,omitempty"`
	AllowPassword   *bool    `json:"allow_password,omitempty"`
	AllowEmailCode  *bool    `json:"allow_email_code,omitempty"`
	AllowSocial     *bool    `json:"allow_social,omitempty"`
	AllowPasskey    *bool    `json:"allow_passkey,omitempty"`
	AllowedFactors  []string `json:"allowed_factors,omitempty"`
}

// AdminOrganization is the organization as its administrators see it.
type AdminOrganization struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Active          bool     `json:"active"`
	MFARequired     bool     `json:"mfa_required"`
	MFAForFederated bool     `json:"mfa_for_federated"`
	AllowPassword   bool     `json:"allow_password"`
	AllowEmailCode  bool     `json:"allow_email_code"`
	AllowSocial     bool     `json:"allow_social"`
	AllowPasskey    bool     `json:"allow_passkey"`
	AllowedFactors  []string `json:"allowed_factors"`
}

// OrgMember is a member of the organization.
type OrgMember struct {
	UserID    string `json:"user_id"`
	UserName  string `json:"user_name"`
	UserEmail string `json:"user_email"`
	Active    bool   `json:"active"`
	SSOBypass bool   `json:"sso_bypass"`
}

// OrgUser is a user homed in the organization.
type OrgUser struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Name               string `json:"name"`
	Username           string `json:"username,omitempty"`
	AvatarURL          string `json:"avatar_url,omitempty"`
	Active             bool   `json:"active"`
	State              string `json:"state,omitempty"`
	HomeOrganizationID string `json:"home_organization_id,omitempty"`
}

// CreateOrgUser creates a user homed in (and a member of) the organization.
type CreateOrgUser struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Password  string `json:"password,omitempty"`
	Username  string `json:"username,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// UpdateOrgUser changes a home user's record; nil fields stay unchanged.
type UpdateOrgUser struct {
	Name      *string `json:"name,omitempty"`
	Username  *string `json:"username,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
	Phone     *string `json:"phone,omitempty"`
}

// OrgRole is a role organization administrators may assign.
type OrgRole struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	ResourceID  string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
	// ResourceName is the role's resource: the IAM resource, or one the
	// organization owns or was granted.
	ResourceName string `json:"resource_name,omitempty"`
	// SystemRole names a built-in role: org_owner, org_viewer,
	// org_user_manager, org_settings_manager or org_resource_manager ("" for
	// custom roles).
	SystemRole string `json:"system_role,omitempty"`
}

// OrgRoleAssignment is a role a member holds in the organization.
type OrgRoleAssignment struct {
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
	UserID   string `json:"user_id"`
}

// OrgInvite invites someone into the organization; roles and groups need
// iam:org:roles:assign and must be assignable by the caller.
type OrgInvite struct {
	Email    string   `json:"email"`
	RoleIDs  []string `json:"role_ids,omitempty"`
	GroupIDs []string `json:"group_ids,omitempty"`
}

// OrgInvitation is an invitation; Token is returned once, on creation or
// resend.
type OrgInvitation struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Status    string   `json:"status"`
	RoleIDs   []string `json:"role_ids"`
	GroupIDs  []string `json:"group_ids"`
	Token     string   `json:"token,omitempty"`
	Link      string   `json:"link,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

// OrgDomain is a domain of the organization; Verification is the DNS
// record to publish before VerifyDomain.
type OrgDomain struct {
	ID           string `json:"id"`
	Domain       string `json:"domain"`
	Verified     bool   `json:"verified"`
	Verification struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"verification"`
}

// OrgConnection is one of the organization's SSO connections. Client
// secrets are sent sealed (ClientSecret); secret_env is not available to
// organization administrators.
type OrgConnection struct {
	ID            string         `json:"id,omitempty"`
	Name          string         `json:"name"`
	Provider      string         `json:"provider,omitempty"`
	Issuer        string         `json:"issuer,omitempty"`
	ClientID      string         `json:"client_id,omitempty"`
	ClientSecret  string         `json:"client_secret,omitempty"`
	Options       map[string]any `json:"options,omitempty"`
	Enforcement   string         `json:"enforcement,omitempty"`
	Active        bool           `json:"active,omitempty"`
	LinkEmail     bool           `json:"link_email,omitempty"`
	UpdateProfile bool           `json:"update_profile,omitempty"`
}

// OrgEvent is an audit event of the organization. ActorKind is operator,
// user, service_account or system; operators carry no label.
type OrgEvent struct {
	ID         string `json:"id"`
	ActorID    string `json:"actor_id"`
	ActorKind  string `json:"actor_kind"`
	ActorLabel string `json:"actor_label"`
	Action     string `json:"action"`
	TargetID   string `json:"target_id"`
	CreatedAt  string `json:"created_at"`
}

// Organization reads the organization (iam:org:read).
func (a OrgAdmin) Organization(ctx context.Context) (AdminOrganization, error) {
	var out AdminOrganization
	return out, a.env.client.Do(ctx, "GET", a.path(), nil, &out)
}

// UpdateSettings changes the organization (iam:org:settings:write).
func (a OrgAdmin) UpdateSettings(ctx context.Context, input OrgSettings) error {
	return a.env.client.Do(ctx, "PATCH", a.path(), input, nil)
}

// Members lists the first page of members (iam:org:members:read).
func (a OrgAdmin) Members(ctx context.Context) ([]OrgMember, error) {
	return list[OrgMember](ctx, a.env.client, a.path("members"), nil)
}

// SetSSOBypass lets a member skip SSO enforcement (iam:org:members:write).
func (a OrgAdmin) SetSSOBypass(ctx context.Context, user string, bypass bool) error {
	return a.env.client.Do(ctx, "PATCH", a.path("members", user), map[string]bool{"sso_bypass": bypass}, nil)
}

// RemoveMember ends a membership (iam:org:members:write).
func (a OrgAdmin) RemoveMember(ctx context.Context, user string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("members", user), nil, nil)
}

// Users lists the first page of users homed in the organization,
// optionally in one state (iam:org:members:read).
func (a OrgAdmin) Users(ctx context.Context, state string) ([]OrgUser, error) {
	var query url.Values
	if state != "" {
		query = url.Values{"state": {state}}
	}
	return list[OrgUser](ctx, a.env.client, a.path("users"), query)
}

// User reads a member (iam:org:members:read).
func (a OrgAdmin) User(ctx context.Context, user string) (OrgUser, error) {
	var out OrgUser
	return out, a.env.client.Do(ctx, "GET", a.path("users", user), nil, &out)
}

// CreateUser creates a home user (iam:org:users:write).
func (a OrgAdmin) CreateUser(ctx context.Context, input CreateOrgUser) (Created, error) {
	var out Created
	return out, a.env.client.Do(ctx, "POST", a.path("users"), input, &out)
}

// UpdateUser changes a home user (iam:org:users:write).
func (a OrgAdmin) UpdateUser(ctx context.Context, user string, input UpdateOrgUser) error {
	return a.env.client.Do(ctx, "PATCH", a.path("users", user), input, nil)
}

// DeactivateUser suspends a home user (iam:org:users:write).
func (a OrgAdmin) DeactivateUser(ctx context.Context, user string) error {
	return a.env.client.Do(ctx, "POST", a.path("users", user, "deactivate"), nil, nil)
}

// ReactivateUser lifts the suspension (iam:org:users:write).
func (a OrgAdmin) ReactivateUser(ctx context.Context, user string) error {
	return a.env.client.Do(ctx, "POST", a.path("users", user, "reactivate"), nil, nil)
}

// UnlockUser clears a home user's lockout (iam:org:users:write).
func (a OrgAdmin) UnlockUser(ctx context.Context, user string) error {
	return a.env.client.Do(ctx, "POST", a.path("users", user, "unlock"), nil, nil)
}

// Roles lists the IAM resource's roles, built-in first (iam:org:roles:read).
func (a OrgAdmin) Roles(ctx context.Context) ([]OrgRole, error) {
	return list[OrgRole](ctx, a.env.client, a.path("roles"), nil)
}

// MemberRoles lists a member's roles in the organization (iam:org:roles:read).
func (a OrgAdmin) MemberRoles(ctx context.Context, user string) ([]OrgRoleAssignment, error) {
	return list[OrgRoleAssignment](ctx, a.env.client, a.path("members", user, "roles"), nil)
}

// AssignRole gives a member a role (iam:org:roles:assign).
func (a OrgAdmin) AssignRole(ctx context.Context, user, role string) error {
	return a.env.client.Do(ctx, "POST", a.path("role-assignments"), map[string]string{"user_id": user, "role_id": role}, nil)
}

// UnassignRole removes a member's role (iam:org:roles:assign).
func (a OrgAdmin) UnassignRole(ctx context.Context, user, role string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("role-assignments", user, role), nil, nil)
}

// Invitations lists the first page of invitations, optionally with one
// status (iam:org:members:read).
func (a OrgAdmin) Invitations(ctx context.Context, status string) ([]OrgInvitation, error) {
	var query url.Values
	if status != "" {
		query = url.Values{"status": {status}}
	}
	return list[OrgInvitation](ctx, a.env.client, a.path("invitations"), query)
}

// Invite invites someone (iam:org:invitations:write).
func (a OrgAdmin) Invite(ctx context.Context, input OrgInvite) (OrgInvitation, error) {
	var out OrgInvitation
	return out, a.env.client.Do(ctx, "POST", a.path("invitations"), input, &out)
}

// ResendInvitation issues a new token (iam:org:invitations:write).
func (a OrgAdmin) ResendInvitation(ctx context.Context, invitation string) (OrgInvitation, error) {
	var out OrgInvitation
	return out, a.env.client.Do(ctx, "POST", a.path("invitations", invitation, "resend"), nil, &out)
}

// RevokeInvitation revokes a pending invitation (iam:org:invitations:write).
func (a OrgAdmin) RevokeInvitation(ctx context.Context, invitation string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("invitations", invitation), nil, nil)
}

// Domains lists the organization's domains (iam:org:read).
func (a OrgAdmin) Domains(ctx context.Context) ([]OrgDomain, error) {
	return list[OrgDomain](ctx, a.env.client, a.path("domains"), nil)
}

// AddDomain adds a domain to verify by DNS (iam:org:domains:write).
func (a OrgAdmin) AddDomain(ctx context.Context, domain string) (OrgDomain, error) {
	var out OrgDomain
	return out, a.env.client.Do(ctx, "POST", a.path("domains"), map[string]string{"domain": domain}, &out)
}

// VerifyDomain checks the domain's DNS TXT record (iam:org:domains:write).
func (a OrgAdmin) VerifyDomain(ctx context.Context, domain string) (OrgDomain, error) {
	var out OrgDomain
	return out, a.env.client.Do(ctx, "POST", a.path("domains", domain, "verify"), nil, &out)
}

// DeleteDomain removes a domain (iam:org:domains:write).
func (a OrgAdmin) DeleteDomain(ctx context.Context, domain string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("domains", domain), nil, nil)
}

// Connections lists the organization's SSO connections (iam:org:read).
func (a OrgAdmin) Connections(ctx context.Context) ([]OrgConnection, error) {
	return list[OrgConnection](ctx, a.env.client, a.path("connections"), nil)
}

// Connection reads one SSO connection (iam:org:read).
func (a OrgAdmin) Connection(ctx context.Context, connection string) (OrgConnection, error) {
	var out OrgConnection
	return out, a.env.client.Do(ctx, "GET", a.path("connections", connection), nil, &out)
}

// CreateConnection creates an SSO connection (iam:org:sso:write).
func (a OrgAdmin) CreateConnection(ctx context.Context, input OrgConnection) (Created, error) {
	var out Created
	return out, a.env.client.Do(ctx, "POST", a.path("connections"), input, &out)
}

// UpdateConnection changes an SSO connection; input holds the fields to
// change (iam:org:sso:write).
func (a OrgAdmin) UpdateConnection(ctx context.Context, connection string, input map[string]any) error {
	return a.env.client.Do(ctx, "PATCH", a.path("connections", connection), input, nil)
}

// DisableConnection disables an SSO connection (iam:org:sso:write).
func (a OrgAdmin) DisableConnection(ctx context.Context, connection string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("connections", connection), nil, nil)
}

// Events lists the first page of the organization's audit events, newest
// first, optionally those whose action starts with action
// (iam:org:audit:read).
func (a OrgAdmin) Events(ctx context.Context, action string) ([]OrgEvent, error) {
	var query url.Values
	if action != "" {
		query = url.Values{"action": {action}}
	}
	return list[OrgEvent](ctx, a.env.client, a.path("events"), query)
}

// Resources lists the resources the organization owns
// (iam:org:resources:read).
func (a OrgAdmin) Resources(ctx context.Context) ([]Resource, error) {
	return list[Resource](ctx, a.env.client, a.path("resources"), nil)
}

// ResourceGrants lists the grants of the organization's own resources,
// optionally of one resource (iam:org:resources:read).
func (a OrgAdmin) ResourceGrants(ctx context.Context, resource string) ([]ResourceGrant, error) {
	q := url.Values{}
	if resource != "" {
		q.Set("resource_id", resource)
	}
	return list[ResourceGrant](ctx, a.env.client, a.path("resource-grants"), q)
}

// GrantedResources lists the resource grants the organization received
// (iam:org:resources:read).
func (a OrgAdmin) GrantedResources(ctx context.Context) ([]ResourceGrant, error) {
	return list[ResourceGrant](ctx, a.env.client, a.path("granted-resources"), nil)
}

// PutResourceGrant grants one of the organization's resources to another
// organization, or replaces the granted roles (iam:org:resources:write).
func (a OrgAdmin) PutResourceGrant(ctx context.Context, input ResourceGrant) (ResourceGrant, error) {
	var out ResourceGrant
	return out, a.env.client.Do(ctx, "PUT", a.path("resource-grants"), input, &out)
}

// DeleteResourceGrant revokes a grant of one of the organization's
// resources (iam:org:resources:write).
func (a OrgAdmin) DeleteResourceGrant(ctx context.Context, grant string) error {
	return a.env.client.Do(ctx, "DELETE", a.path("resource-grants", grant), nil, nil)
}

// OrgBranding is an organization's overrides of the hosted sign-in and
// invitation pages. Nil fields inherit the OAuth client's style or the
// environment default; Theme replaces the inherited theme whole.
type OrgBranding struct {
	OrganizationID string          `json:"organization_id,omitempty"`
	DisplayName    *string         `json:"display_name"`
	LogoURL        *string         `json:"logo_url"`
	AccentColor    *string         `json:"accent_color"`
	Theme          json.RawMessage `json:"theme,omitempty"`
	// Locale is the language of the organization's pages and invitation
	// emails (one of the environment's enabled languages); nil inherits.
	Locale *string `json:"locale,omitempty"`
}

// Branding reads the organization's overrides (iam:org:read).
func (a OrgAdmin) Branding(ctx context.Context) (OrgBranding, error) {
	var out OrgBranding
	return out, a.env.client.Do(ctx, "GET", a.path("branding"), nil, &out)
}

// SaveBranding replaces the organization's overrides
// (iam:org:settings:write).
func (a OrgAdmin) SaveBranding(ctx context.Context, input OrgBranding) (OrgBranding, error) {
	var out OrgBranding
	return out, a.env.client.Do(ctx, "PUT", a.path("branding"), input, &out)
}

// DeleteBranding removes the overrides, so everything inherits
// (iam:org:settings:write).
func (a OrgAdmin) DeleteBranding(ctx context.Context) error {
	return a.env.client.Do(ctx, "DELETE", a.path("branding"), nil, nil)
}

// OrgPasswordRequirements are what the organization adds to the
// environment's password policy for its members; they only tighten it
// (0 keeps the environment's minimum length or expiry).
type OrgPasswordRequirements struct {
	MinLength     int  `json:"min_length"`
	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	MaxAgeDays    int  `json:"max_age_days"`
	BreachCheck   bool `json:"breach_check"`
	// Custom is false when the organization adds nothing (read only).
	Custom bool `json:"custom,omitempty"`
}

// PasswordPolicy reads the organization's password requirements
// (iam:org:read).
func (a OrgAdmin) PasswordPolicy(ctx context.Context) (OrgPasswordRequirements, error) {
	var out OrgPasswordRequirements
	return out, a.env.client.Do(ctx, "GET", a.path("password-policy"), nil, &out)
}

// SetPasswordPolicy replaces the organization's password requirements
// (iam:org:settings:write).
func (a OrgAdmin) SetPasswordPolicy(ctx context.Context, input OrgPasswordRequirements) (OrgPasswordRequirements, error) {
	var out OrgPasswordRequirements
	return out, a.env.client.Do(ctx, "PUT", a.path("password-policy"), input, &out)
}

// DeletePasswordPolicy removes the organization's password requirements
// (iam:org:settings:write).
func (a OrgAdmin) DeletePasswordPolicy(ctx context.Context) error {
	return a.env.client.Do(ctx, "DELETE", a.path("password-policy"), nil, nil)
}
