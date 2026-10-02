package iamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Environment scopes management calls to a single IAMKit environment.
// Use Client.Environment to obtain one.
type Environment struct {
	client *Client
	id     string
}

// Environment returns a handle scoped to the given environment ID.
// All subsequent calls through the handle include /environments/<id>/ in the path.
func (c *Client) Environment(id string) Environment {
	return Environment{client: c, id: id}
}

func (e Environment) path(collection string) string {
	return "/environments/" + e.id + "/" + collection
}

// paginated wraps the list response envelope: {"items":[...],"page":{...}}.
type paginated[T any] struct {
	Items []T `json:"items"`
}

// list fetches a paginated collection and unwraps the items.
func list[T any](e Environment, ctx context.Context, collection string) ([]T, error) {
	var out paginated[T]
	err := e.client.Do(ctx, "GET", e.path(collection), nil, &out)
	if err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []T{}, nil
	}
	return out.Items, nil
}

// listOp is like list but uses operation (path segments with validation).
func listOp[T any](e Environment, ctx context.Context, parts []string) ([]T, error) {
	for _, part := range parts {
		if err := safeSegment(part); err != nil {
			return nil, err
		}
	}
	var out paginated[T]
	err := e.client.Do(ctx, "GET", e.path(strings.Join(parts, "/")), nil, &out)
	if err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []T{}, nil
	}
	return out.Items, nil
}

// ── Shared types ──

type Created struct {
	ID string `json:"id"`
}

type User struct {
	ID string `json:"id"`
	// Kind is "human" or "machine" (no email, password or second factor;
	// authenticates with personal access tokens only).
	Kind  string `json:"kind,omitempty"`
	Email string `json:"email"`
	Name  string `json:"name"`
	// Username is the optional second sign-in identifier ("" when none).
	Username string `json:"username,omitempty"`
	// AvatarURL is an https URL to the user's picture ("" when none).
	AvatarURL string `json:"avatar_url,omitempty"`
	// Phone is the user's number in E.164 ("" when none); PhoneVerified
	// once the user entered a code texted to it or an operator marked it.
	Phone         string `json:"phone,omitempty"`
	PhoneVerified bool   `json:"phone_verified,omitempty"`
	// HomeOrganizationID is the organization owning the record ("" when
	// none): its administrators may edit the user.
	HomeOrganizationID string `json:"home_organization_id,omitempty"`
	Active             bool   `json:"active"`
	// State is derived: suspended, locked, initial (never signed in),
	// inactive (no active membership in an active organization) or active.
	State          string     `json:"state,omitempty"`
	LastSignedInAt *time.Time `json:"last_signed_in_at,omitempty"`
	// TermsAcceptedAt is when the user accepted the terms at sign-up
	// (SignInPolicy.RequireTerms).
	TermsAcceptedAt *time.Time `json:"terms_accepted_at,omitempty"`
	// Metadata and Profile are returned when one user is read.
	Metadata map[string]any `json:"metadata,omitempty"`
	Profile  map[string]any `json:"profile,omitempty"`
}

// User states (User.State, UsersInState).
const (
	UserSuspended = "suspended"
	UserLocked    = "locked"
	UserInitial   = "initial"
	UserInactive  = "inactive"
	UserActive    = "active"
)

type CreateUser struct {
	OTPEnabled bool   `json:"otp_enabled"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	// AvatarURL is an https URL to the user's picture (optional).
	AvatarURL string `json:"avatar_url,omitempty"`
	// Username is optional: lowercase letters, digits, ".", "_" or "-",
	// unique in the environment; users may sign in with it.
	Username string `json:"username,omitempty"`
	// HomeOrganizationID makes the user a member of that organization
	// whose administrators may then edit the record (optional).
	HomeOrganizationID string `json:"home_organization_id,omitempty"`
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// The MFA policy and sign-in methods are filled by Organization(id)
	// only; list results leave them false.
	MFARequired     bool `json:"mfa_required,omitempty"`
	MFAForFederated bool `json:"mfa_for_federated,omitempty"`
	// AllowPassword, AllowEmailCode, AllowSocial and AllowPasskey narrow
	// the environment's SignInPolicy for this organization (never widen it).
	AllowPassword  bool `json:"allow_password,omitempty"`
	AllowEmailCode bool `json:"allow_email_code,omitempty"`
	AllowSocial    bool `json:"allow_social,omitempty"`
	AllowPasskey   bool `json:"allow_passkey,omitempty"`
	// AllowedFactors narrow the environment's allowed second factors.
	AllowedFactors []string `json:"allowed_factors,omitempty"`
}

// Factor is a user's second factor. Kind is totp, email, sms or webauthn;
// Name labels security keys and passkeys.
type Factor struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Name        string     `json:"name,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type UserFactors struct {
	Factors                []Factor `json:"factors"`
	RecoveryCodesRemaining int      `json:"recovery_codes_remaining"`
	// LockedUntil is set while wrong codes lock every factor of the user.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

type Membership struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           string `json:"role"`
}

type Application struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Active       bool     `json:"active,omitempty"`
}

type Resource struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
	// OwnerOrganizationID is the vendor organization owning the resource
	// ("" = the environment); RequireGrant limits access to the owner and
	// organizations holding a ResourceGrant. Set both with SetResourceAccess.
	OwnerOrganizationID string `json:"owner_organization_id,omitempty"`
	RequireGrant        bool   `json:"require_grant,omitempty"`
}

// ResourceAccess sets a resource's owner organization (nil = the
// environment) and grant requirement.
type ResourceAccess struct {
	OwnerOrganizationID *string `json:"owner_organization_id"`
	RequireGrant        bool    `json:"require_grant"`
}

// ResourceGrant lets an organization use a resource it does not own; a nil
// RoleIDs grants every role of the resource.
type ResourceGrant struct {
	ID               string   `json:"id,omitempty"`
	ResourceID       string   `json:"resource_id"`
	ResourceName     string   `json:"resource_name,omitempty"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationName string   `json:"organization_name,omitempty"`
	RoleIDs          []string `json:"role_ids"`
	CreatedAt        string   `json:"created_at,omitempty"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
}

type Grant struct {
	ID             string   `json:"id,omitempty"`
	OrganizationID string   `json:"organization_id"`
	UserID         string   `json:"user_id"`
	ResourceID     string   `json:"resource_id"`
	Permissions    []string `json:"permissions"`
}

type Role struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	ResourceID  string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
	// SystemRole names a built-in organization-administration role
	// (org_owner, org_viewer, org_user_manager, org_settings_manager) of
	// the IAM resource; those cannot be changed or deleted. Read-only.
	SystemRole string `json:"system_role,omitempty"`
}

type RoleAssignment struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	RoleID         string `json:"role_id"`
}

type OrgUnit struct {
	ID       string  `json:"id,omitempty"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	ParentID *string `json:"parent_id,omitempty"`
}

type Position struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Code string `json:"code"`
}

// ── Users ──

func (e Environment) CreateUser(ctx context.Context, input CreateUser) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "POST", e.path("users"), input, &out)
	return out, err
}

func (e Environment) Users(ctx context.Context) ([]User, error) {
	return list[User](e, ctx, "users")
}

func (e Environment) User(ctx context.Context, id string) (User, error) {
	var out User
	err := e.operation(ctx, "GET", []string{"users", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateUser(ctx context.Context, id string, input UserPatch) error {
	return e.operation(ctx, "PATCH", []string{"users", id}, input, nil)
}

// UsersInState lists the first page of users in state (see UserActive…).
func (e Environment) UsersInState(ctx context.Context, state string) ([]User, error) {
	var out paginated[User]
	if err := e.client.do(ctx, "GET", e.path("users"), url.Values{"state": {state}}, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []User{}, nil
	}
	return out.Items, nil
}

func (e Environment) SuspendUser(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"users", id}, nil, nil)
}

// DeactivateUser suspends the user (audited user.deactivated): sessions
// end and nothing signs in until ReactivateUser.
func (e Environment) DeactivateUser(ctx context.Context, id string) error {
	return e.operation(ctx, "POST", []string{"users", id, "deactivate"}, nil, nil)
}

// ReactivateUser lifts a suspension (audited user.reactivated).
func (e Environment) ReactivateUser(ctx context.Context, id string) error {
	return e.operation(ctx, "POST", []string{"users", id, "reactivate"}, nil, nil)
}

// UnlockUser clears a user's wrong-password count and lockout.
func (e Environment) UnlockUser(ctx context.Context, id string) error {
	return e.operation(ctx, "POST", []string{"users", id, "unlock"}, nil, nil)
}

// ── Machine users ──

// CreateMachineUser creates a user of kind "machine": no email, password
// or second factor. It joins organizations and receives roles and grants
// like a person and authenticates with personal access tokens.
func (e Environment) CreateMachineUser(ctx context.Context, name, homeOrganization string) (Created, error) {
	body := map[string]string{"kind": "machine", "name": name}
	if homeOrganization != "" {
		body["home_organization_id"] = homeOrganization
	}
	var out Created
	err := e.client.Do(ctx, "POST", e.path("users"), body, &out)
	return out, err
}

// MachineUsers lists the first page of machine users.
func (e Environment) MachineUsers(ctx context.Context) ([]User, error) {
	var out paginated[User]
	if err := e.client.do(ctx, "GET", e.path("users"), url.Values{"kind": {"machine"}}, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []User{}, nil
	}
	return out.Items, nil
}

// AccessToken is a machine user's personal access token (never its secret).
type AccessToken struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	OrganizationID string     `json:"organization_id"`
	ApplicationID  string     `json:"application_id"`
	ResourceID     string     `json:"resource_id"`
	Name           string     `json:"name"`
	ExpiresAt      time.Time  `json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
	// Names are filled when tokens are listed.
	OrganizationName string `json:"organization_name,omitempty"`
	ApplicationName  string `json:"application_name,omitempty"`
	ResourceName     string `json:"resource_name,omitempty"`
}

// IssuedAccessToken is a new personal access token; Token (ik_pat_…) is
// returned only here.
type IssuedAccessToken struct {
	AccessToken
	Token string `json:"token"`
}

// CreateAccessToken asks for a personal access token acting as the machine
// user in OrganizationID (one it belongs to) for ResourceID of
// ApplicationID. ExpiresIn is 1h–8760h or "never" (default 24h).
type CreateAccessToken struct {
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
	ExpiresIn      string `json:"expires_in,omitempty"`
}

// CreateAccessToken issues a personal access token for a machine user.
// Use it as a bearer (live permissions, no session) or trade it for an
// access JWT with authclient.Client.ExchangeAccessToken.
func (e Environment) CreateAccessToken(ctx context.Context, user string, input CreateAccessToken) (IssuedAccessToken, error) {
	var out IssuedAccessToken
	err := e.operation(ctx, "POST", []string{"users", user, "access-tokens"}, input, &out)
	return out, err
}

// AccessTokens lists the first page of a machine user's tokens.
func (e Environment) AccessTokens(ctx context.Context, user string) ([]AccessToken, error) {
	return listOp[AccessToken](e, ctx, []string{"users", user, "access-tokens"})
}

// RevokeAccessToken revokes a token and the sessions exchanged from it.
func (e Environment) RevokeAccessToken(ctx context.Context, user, token string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "access-tokens", token}, nil, nil)
}

// UserKey is a machine user's public key for the JWT-bearer grant; its ID
// is the kid of the assertions it signs.
type UserKey struct {
	ID         string          `json:"id"`
	UserID     string          `json:"user_id"`
	PublicKey  json.RawMessage `json:"public_key"`
	ExpiresAt  time.Time       `json:"expires_at"`
	LastUsedAt *time.Time      `json:"last_used_at"`
	CreatedAt  time.Time       `json:"created_at"`
}

// IssuedUserKey is a new key; PrivateKey (PEM, PKCS #8) is set only when
// IAMKit generated the pair, and returned only here.
type IssuedUserKey struct {
	UserKey
	PrivateKey string `json:"private_key,omitempty"`
}

// AddUserKey asks for a key: PublicKey is an RSA (2048 bits or more) or EC
// public JSON Web Key; leave it empty to have IAMKit generate an RSA pair.
// ExpiresIn is 1h–8760h or "never" (default 8760h).
type AddUserKey struct {
	PublicKey json.RawMessage `json:"public_key,omitempty"`
	ExpiresIn string          `json:"expires_in,omitempty"`
}

// AddUserKey adds a key to a machine user (at most 10). Sign in with it
// using authclient.NewKeyLogin.
func (e Environment) AddUserKey(ctx context.Context, user string, input AddUserKey) (IssuedUserKey, error) {
	var out IssuedUserKey
	err := e.operation(ctx, "POST", []string{"users", user, "keys"}, input, &out)
	return out, err
}

// UserKeys lists the first page of a machine user's keys.
func (e Environment) UserKeys(ctx context.Context, user string) ([]UserKey, error) {
	return listOp[UserKey](e, ctx, []string{"users", user, "keys"})
}

// RemoveUserKey deletes a key and ends the sessions opened with it.
func (e Environment) RemoveUserKey(ctx context.Context, user, key string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "keys", key}, nil, nil)
}

// ── Organizations ──

func (e Environment) CreateOrganization(ctx context.Context, name string) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "POST", e.path("organizations"), map[string]string{"name": name}, &out)
	return out, err
}

func (e Environment) Organizations(ctx context.Context) ([]Organization, error) {
	return list[Organization](e, ctx, "organizations")
}

func (e Environment) Organization(ctx context.Context, id string) (Organization, error) {
	var out Organization
	err := e.operation(ctx, "GET", []string{"organizations", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateOrganization(ctx context.Context, id string, input UserPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", id}, input, nil)
}

// OrganizationMFA is an organization's second-factor policy; nil fields
// are left unchanged.
type OrganizationMFA struct {
	// Required: password and email-code logins need a second factor; users
	// without one enroll while signing in.
	Required *bool `json:"mfa_required,omitempty"`
	// ForFederated: SSO logins follow the same rule instead of trusting
	// the identity provider.
	ForFederated *bool `json:"mfa_for_federated,omitempty"`
}

// SetOrganizationMFA changes an organization's second-factor policy.
func (e Environment) SetOrganizationMFA(ctx context.Context, id string, input OrganizationMFA) error {
	return e.operation(ctx, "PATCH", []string{"organizations", id}, input, nil)
}

// OrganizationMethods narrows the sign-in methods the environment allows
// for one organization; nil fields are left unchanged. The organization's
// own SSO follows its enforcement instead.
type OrganizationMethods struct {
	Password  *bool `json:"allow_password,omitempty"`
	EmailCode *bool `json:"allow_email_code,omitempty"`
	Social    *bool `json:"allow_social,omitempty"`
	Passkey   *bool `json:"allow_passkey,omitempty"`
}

// OrganizationFactors narrows the environment's allowed second factors
// for one organization (totp, webauthn, sms, email).
type OrganizationFactors struct {
	AllowedFactors []string `json:"allowed_factors"`
}

// SetOrganizationFactors changes the second factors an organization's
// members may use; a user whose factors are all refused enrolls another.
func (e Environment) SetOrganizationFactors(ctx context.Context, id string, input OrganizationFactors) error {
	return e.operation(ctx, "PATCH", []string{"organizations", id}, input, nil)
}

// SetOrganizationMethods changes the sign-in methods an organization
// accepts. Refused methods answer apierror CodeMethodNotAllowed.
func (e Environment) SetOrganizationMethods(ctx context.Context, id string, input OrganizationMethods) error {
	return e.operation(ctx, "PATCH", []string{"organizations", id}, input, nil)
}

// UserFactors lists a user's second factors (never secrets) and remaining
// recovery codes.
func (e Environment) UserFactors(ctx context.Context, user string) (UserFactors, error) {
	var out UserFactors
	err := e.operation(ctx, "GET", []string{"users", user, "factors"}, nil, &out)
	return out, err
}

// ResetUserFactors removes every second factor and recovery code of a user
// (lost device). Audited as mfa.reset.
func (e Environment) ResetUserFactors(ctx context.Context, user string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "factors"}, nil, nil)
}

func (e Environment) AddMember(ctx context.Context, input Membership) error {
	return e.client.Do(ctx, "POST", e.path("memberships"), input, nil)
}

func (e Environment) Members(ctx context.Context, org string) ([]Membership, error) {
	return listOp[Membership](e, ctx, []string{"organizations", org, "members"})
}

func (e Environment) RemoveMember(ctx context.Context, org, user string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "members", user}, nil, nil)
}

func (e Environment) SetMemberProfile(ctx context.Context, org, user string, input MemberProfile) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "members", user, "profile"}, input, nil)
}

// ── Applications ──

func (e Environment) CreateApplication(ctx context.Context, input Application) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "POST", e.path("applications"), input, &out)
	return out, err
}

func (e Environment) Applications(ctx context.Context) ([]Application, error) {
	return list[Application](e, ctx, "applications")
}

func (e Environment) Application(ctx context.Context, id string) (Application, error) {
	var out Application
	err := e.operation(ctx, "GET", []string{"applications", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateApplication(ctx context.Context, id string, input Application) error {
	return e.operation(ctx, "PATCH", []string{"applications", id}, input, nil)
}

// ── Resources ──

func (e Environment) CreateResource(ctx context.Context, input Resource) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "POST", e.path("resources"), input, &out)
	return out, err
}

func (e Environment) Resources(ctx context.Context) ([]Resource, error) {
	return list[Resource](e, ctx, "resources")
}

func (e Environment) Resource(ctx context.Context, id string) (Resource, error) {
	var out Resource
	err := e.operation(ctx, "GET", []string{"resources", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateResource(ctx context.Context, id string, input Resource) error {
	return e.operation(ctx, "PUT", []string{"resources", id}, input, nil)
}

func (e Environment) BindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "POST", e.path("application-resources"), map[string]string{"application_id": application, "resource_id": resource}, nil)
}

func (e Environment) UnbindResource(ctx context.Context, application, resource string) error {
	return e.operation(ctx, "DELETE", []string{"application-resources", application, resource}, nil, nil)
}

func (e Environment) ApplicationResources(ctx context.Context, application string) ([]Resource, error) {
	return listOp[Resource](e, ctx, []string{"applications", application, "resources"})
}

// ── Resource grants ──

// SetResourceAccess sets the resource's owner organization and whether it
// requires a grant; organizations losing access have their sessions ended.
func (e Environment) SetResourceAccess(ctx context.Context, resource string, input ResourceAccess) error {
	return e.operation(ctx, "PUT", []string{"resources", resource, "access"}, input, nil)
}

// ResourceGrants lists every resource grant of the environment.
func (e Environment) ResourceGrants(ctx context.Context) ([]ResourceGrant, error) {
	return list[ResourceGrant](e, ctx, "resource-grants")
}

func (e Environment) ResourceGrant(ctx context.Context, id string) (ResourceGrant, error) {
	var out ResourceGrant
	err := e.operation(ctx, "GET", []string{"resource-grants", id}, nil, &out)
	return out, err
}

// PutResourceGrant grants the resource to the organization, or replaces
// the granted roles; narrowing ends the organization's sessions for it.
func (e Environment) PutResourceGrant(ctx context.Context, input ResourceGrant) (ResourceGrant, error) {
	var out ResourceGrant
	err := e.client.Do(ctx, "PUT", e.path("resource-grants"), input, &out)
	return out, err
}

func (e Environment) DeleteResourceGrant(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"resource-grants", id}, nil, nil)
}

// ── Grants ──

func (e Environment) PutGrant(ctx context.Context, input Grant) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "PUT", e.path("grants"), input, &out)
	return out, err
}

func (e Environment) Grants(ctx context.Context) ([]Grant, error) {
	return list[Grant](e, ctx, "grants")
}

func (e Environment) Grant(ctx context.Context, id string) (Grant, error) {
	var out Grant
	err := e.operation(ctx, "GET", []string{"grants", id}, nil, &out)
	return out, err
}

func (e Environment) DeleteGrant(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"grants", id}, nil, nil)
}

// ── Roles ──

func (e Environment) CreateRole(ctx context.Context, input Role) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "POST", e.path("roles"), input, &out)
	return out, err
}

func (e Environment) Roles(ctx context.Context) ([]Role, error) {
	return list[Role](e, ctx, "roles")
}

func (e Environment) Role(ctx context.Context, id string) (Role, error) {
	var out Role
	err := e.operation(ctx, "GET", []string{"roles", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateRole(ctx context.Context, id string, input Role) error {
	return e.operation(ctx, "PUT", []string{"roles", id}, input, nil)
}

func (e Environment) DeleteRole(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"roles", id}, nil, nil)
}

// ── Role Assignments ──

func (e Environment) AssignRole(ctx context.Context, input RoleAssignment) error {
	return e.client.Do(ctx, "POST", e.path("role-assignments"), input, nil)
}

func (e Environment) RoleAssignments(ctx context.Context) ([]RoleAssignment, error) {
	return list[RoleAssignment](e, ctx, "role-assignments")
}

func (e Environment) UnassignRole(ctx context.Context, input RoleAssignment) error {
	return e.operation(ctx, "DELETE", []string{"role-assignments", input.RoleID, input.OrganizationID, input.UserID}, nil, nil)
}

// ── Org Structure ──

func safeSegment(id string) error {
	if id == "" || strings.ContainsAny(id, "/?#.%\\") {
		return fmt.Errorf("invalid resource ID")
	}
	return nil
}

func (e Environment) CreateOrgUnit(ctx context.Context, organization string, input OrgUnit) (Created, error) {
	var out Created
	if err := safeSegment(organization); err != nil {
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("organizations/"+organization+"/org-units"), input, &out)
	return out, err
}

func (e Environment) OrgUnits(ctx context.Context, organization string) ([]OrgUnit, error) {
	if err := safeSegment(organization); err != nil {
		return nil, err
	}
	return list[OrgUnit](e, ctx, "organizations/"+organization+"/org-units")
}

func (e Environment) OrgUnit(ctx context.Context, org, id string) (OrgUnit, error) {
	var out OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateOrgUnit(ctx context.Context, org, id string, input OrgUnit) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "org-units", id}, input, nil)
}

func (e Environment) DeleteOrgUnit(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "org-units", id}, nil, nil)
}

func (e Environment) OrgUnitAncestors(ctx context.Context, org, id string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "org-units", id, "ancestors"})
}

func (e Environment) OrgUnitDescendants(ctx context.Context, org, id string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "org-units", id, "descendants"})
}

func (e Environment) OrgUnitDeleteImpact(ctx context.Context, org, id string) (UnitImpact, error) {
	var out UnitImpact
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "delete-impact"}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitTree(ctx context.Context, org string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "tree"})
}

func (e Environment) OrgChart(ctx context.Context, org string) ([]ReportingMember, error) {
	return listOp[ReportingMember](e, ctx, []string{"organizations", org, "org-chart"})
}

// ── Positions ──

func (e Environment) CreatePosition(ctx context.Context, organization string, input Position) (Created, error) {
	var out Created
	if err := safeSegment(organization); err != nil {
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("organizations/"+organization+"/positions"), input, &out)
	return out, err
}

func (e Environment) Positions(ctx context.Context, org string) ([]Position, error) {
	return listOp[Position](e, ctx, []string{"organizations", org, "positions"})
}

func (e Environment) UpdatePosition(ctx context.Context, org, id string, input Position) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "positions", id}, input, nil)
}

func (e Environment) DeletePosition(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "positions", id}, nil, nil)
}

func (e Environment) AssignPosition(ctx context.Context, org string, input PositionAssignment) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"organizations", org, "position-assignments"}, input, &out)
	return out, err
}

func (e Environment) PositionAssignments(ctx context.Context, org string) ([]PositionAssignment, error) {
	return listOp[PositionAssignment](e, ctx, []string{"organizations", org, "position-assignments"})
}

func (e Environment) UnassignPosition(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "position-assignments", id}, nil, nil)
}

// ── Delivery Config ──

// Email delivery providers of an environment.
const (
	DeliveryWebhook = "webhook" // IAMKit posts JSON to your endpoint, which writes and sends the email
	DeliverySMTP    = "smtp"    // IAMKit renders the email and sends it through an SMTP server
	DeliveryResend  = "resend"  // IAMKit renders the email and sends it through the Resend API
)

// DeliveryConfig is the per-environment email delivery configuration.
// Secrets are never returned: HasToken says a webhook token is stored,
// HasSecret an SMTP password or Resend API key.
type DeliveryConfig struct {
	EnvironmentID string `json:"environment_id"`
	// Provider is DeliveryWebhook, DeliverySMTP or DeliveryResend.
	Provider      string `json:"provider"`
	WebhookURL    string `json:"webhook_url"`
	HasToken      bool   `json:"has_token"`
	InvitationURL string `json:"invitation_url"`
	FromEmail     string `json:"from_email"`
	FromName      string `json:"from_name"`
	ReplyTo       string `json:"reply_to"`
	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	SMTPUsername  string `json:"smtp_username"`
	SMTPTLS       string `json:"smtp_tls"`
	HasSecret     bool   `json:"has_secret"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// SetDeliveryConfig creates or replaces the per-environment delivery.
// Set only the fields of the chosen Provider (empty = DeliveryWebhook):
//
//   - webhook: WebhookURL, WebhookToken
//   - smtp: FromEmail, FromName, ReplyTo, SMTPHost, SMTPPort (default 587),
//     SMTPUsername, SMTPPassword, SMTPTLS ("starttls" or "tls"; 465 implies tls)
//   - resend: FromEmail, FromName, ReplyTo, APIKey
//
// An empty SMTPPassword or APIKey keeps the stored one when the provider is
// unchanged. Storing either needs IAMKIT_ENCRYPTION_KEY on the server.
type SetDeliveryConfig struct {
	Provider     string `json:"provider,omitempty"`
	WebhookURL   string `json:"webhook_url,omitempty"`
	WebhookToken string `json:"webhook_token,omitempty"`
	// InvitationURL is the app page that accepts invitations; the token is
	// added as the "token" query parameter. Optional: with smtp or resend
	// and no URL, invitations link to IAMKit's hosted invite page.
	InvitationURL string `json:"invitation_url,omitempty"`
	FromEmail     string `json:"from_email,omitempty"`
	FromName      string `json:"from_name,omitempty"`
	ReplyTo       string `json:"reply_to,omitempty"`
	SMTPHost      string `json:"smtp_host,omitempty"`
	SMTPPort      int    `json:"smtp_port,omitempty"`
	SMTPUsername  string `json:"smtp_username,omitempty"`
	SMTPPassword  string `json:"smtp_password,omitempty"`
	SMTPTLS       string `json:"smtp_tls,omitempty"`
	APIKey        string `json:"api_key,omitempty"`
}

// DeliveryConfig returns the delivery configuration for this environment.
func (e Environment) DeliveryConfig(ctx context.Context) (DeliveryConfig, error) {
	var out DeliveryConfig
	err := e.client.Do(ctx, "GET", e.path("delivery"), nil, &out)
	return out, err
}

// SetDeliveryConfig creates or replaces the delivery for this environment.
func (e Environment) SetDeliveryConfig(ctx context.Context, input SetDeliveryConfig) error {
	return e.client.Do(ctx, "PUT", e.path("delivery"), input, nil)
}

// DeleteDeliveryConfig removes the per-environment delivery, falling back
// to the global sender (EMAIL_PROVIDER and related settings).
func (e Environment) DeleteDeliveryConfig(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("delivery"), nil, nil)
}

// ── Password policy ──

// PasswordPolicy governs end-user passwords in an environment. New passwords
// (user creation, invitations, resets, expiry) must satisfy it; rejections
// are apierror CodePasswordPolicy with Rule() naming the failed rule.
type PasswordPolicy struct {
	MinLength     int  `json:"min_length"` // 8-72 bytes
	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	// MaxAgeDays: older passwords must be replaced at the next password
	// sign-in (CodePasswordChangeRequired). 0 never expires.
	MaxAgeDays int `json:"max_age_days"`
	// LockoutThreshold wrong passwords in a row lock the account for
	// LockoutMinutes, doubling per further lockout up to 24 h. 0 never locks.
	LockoutThreshold int `json:"lockout_threshold"`
	LockoutMinutes   int `json:"lockout_minutes"`
	// BreachCheck rejects passwords found in Have I Been Pwned (k-anonymity);
	// they are accepted when the service is unreachable.
	BreachCheck bool `json:"breach_check"`
	// Custom is false for the built-in default (read-only).
	Custom    bool   `json:"custom,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// PasswordPolicy returns the environment's policy, or the default when none
// is saved.
func (e Environment) PasswordPolicy(ctx context.Context) (PasswordPolicy, error) {
	var out PasswordPolicy
	err := e.client.Do(ctx, "GET", e.path("password-policy"), nil, &out)
	return out, err
}

// SetPasswordPolicy replaces the whole policy (Custom and UpdatedAt are
// ignored). Audited as password_policy.update.
func (e Environment) SetPasswordPolicy(ctx context.Context, input PasswordPolicy) (PasswordPolicy, error) {
	input.Custom, input.UpdatedAt = false, ""
	var out PasswordPolicy
	err := e.client.Do(ctx, "PUT", e.path("password-policy"), input, &out)
	return out, err
}

// DeletePasswordPolicy restores the default policy. Audited as
// password_policy.delete.
func (e Environment) DeletePasswordPolicy(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("password-policy"), nil, nil)
}

// PasswordRequirements is what an organization adds to the environment's
// PasswordPolicy for its members: it only tightens (the longer minimum,
// every required class, the shorter expiry). Users are environment-wide, so
// a member of several organizations meets all of them. Zero values keep the
// environment's rule.
type PasswordRequirements struct {
	MinLength     int  `json:"min_length"` // 0 or 8-72
	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	MaxAgeDays    int  `json:"max_age_days"`
	BreachCheck   bool `json:"breach_check"`
	// Custom is false when the organization adds nothing (read-only).
	Custom    bool   `json:"custom,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// OrganizationPasswordPolicy returns what the organization adds to the
// environment's password policy.
func (e Environment) OrganizationPasswordPolicy(ctx context.Context, organization string) (PasswordRequirements, error) {
	var out PasswordRequirements
	err := e.operation(ctx, "GET", []string{"organizations", organization, "password-policy"}, nil, &out)
	return out, err
}

// SetOrganizationPasswordPolicy replaces the organization's requirements.
// Audited as organization_password_policy.update.
func (e Environment) SetOrganizationPasswordPolicy(ctx context.Context, organization string, input PasswordRequirements) (PasswordRequirements, error) {
	input.Custom, input.UpdatedAt = false, ""
	var out PasswordRequirements
	err := e.operation(ctx, "PUT", []string{"organizations", organization, "password-policy"}, input, &out)
	return out, err
}

// DeleteOrganizationPasswordPolicy drops the organization's requirements.
// Audited as organization_password_policy.delete.
func (e Environment) DeleteOrganizationPasswordPolicy(ctx context.Context, organization string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", organization, "password-policy"}, nil, nil)
}

// ── Organization branding ──

// OrganizationBranding is an organization's overrides of the hosted
// sign-in and invitation pages. Nil fields inherit the OAuth client's
// style or the environment default; Theme (the login-settings theme
// object) replaces the inherited theme whole. Sign-in pages use it once
// they know the organization: the authorize request's organization_id
// parameter or urn:iamkit:org:id:<id> scope (which also limit the sign-in
// to that organization), the organization the user chose, or a verified
// domain of the typed email.
type OrganizationBranding struct {
	OrganizationID string          `json:"organization_id,omitempty"`
	DisplayName    *string         `json:"display_name"`
	LogoURL        *string         `json:"logo_url"`
	AccentColor    *string         `json:"accent_color"`
	Theme          json.RawMessage `json:"theme,omitempty"`
	// Locale is the language of the organization's pages and invitation
	// emails (one of the environment's enabled languages); nil inherits.
	Locale    *string `json:"locale,omitempty"`
	UpdatedAt string  `json:"updated_at,omitempty"`
}

// OrganizationBranding returns the organization's overrides (every field
// nil when it has none).
func (e Environment) OrganizationBranding(ctx context.Context, organization string) (OrganizationBranding, error) {
	var out OrganizationBranding
	err := e.operation(ctx, "GET", []string{"login-settings", "organizations", organization}, nil, &out)
	return out, err
}

// SetOrganizationBranding replaces the organization's overrides.
func (e Environment) SetOrganizationBranding(ctx context.Context, organization string, input OrganizationBranding) (OrganizationBranding, error) {
	input.OrganizationID, input.UpdatedAt = "", ""
	var out OrganizationBranding
	err := e.operation(ctx, "PUT", []string{"login-settings", "organizations", organization}, input, &out)
	return out, err
}

// DeleteOrganizationBranding removes the overrides (everything inherits).
func (e Environment) DeleteOrganizationBranding(ctx context.Context, organization string) error {
	return e.operation(ctx, "DELETE", []string{"login-settings", "organizations", organization}, nil, nil)
}

// ── Sign-in policy ──

// SignInPolicy is which sign-in methods an environment allows and its
// default second-factor rules. Organizations narrow the methods
// (SetOrganizationMethods); hosted applications narrow them further.
// Organization single sign-on is not governed by it. Refusals answer
// apierror CodeMethodNotAllowed / CodePasswordResetDisabled.
type SignInPolicy struct {
	AllowPassword  bool `json:"allow_password"`
	AllowEmailCode bool `json:"allow_email_code"`
	// AllowSocial covers environment connections (Google, Microsoft, ...).
	AllowSocial bool `json:"allow_social"`
	// AllowPasskey allows passkey sign-in (default true); it also needs
	// "webauthn" in AllowedFactors. Nil keeps the stored value.
	AllowPasskey *bool `json:"allow_passkey,omitempty"`
	// AllowPasswordReset needs AllowPassword.
	AllowPasswordReset bool `json:"allow_password_reset"`
	// MFARequired and MFAForFederated apply to every organization on top of
	// its own MFA policy.
	MFARequired     bool `json:"mfa_required"`
	MFAForFederated bool `json:"mfa_for_federated"`
	// AllowedFactors are the second factors users may use: totp, webauthn,
	// sms, email (default totp, webauthn — email and SMS codes are opt-in).
	// Nil keeps the stored list.
	AllowedFactors []string `json:"allowed_factors,omitempty"`
	// AllowSignup lets people create their own account
	// (authclient.Signup, "Create account" on the hosted pages); it needs
	// SignupOrganizationID, the organization new accounts join, and
	// AllowPassword or AllowEmailCode. SignupGroupID is an optional
	// operator-managed group of it.
	AllowSignup          bool   `json:"allow_signup"`
	SignupOrganizationID string `json:"signup_organization_id,omitempty"`
	SignupGroupID        string `json:"signup_group_id,omitempty"`
	// RequireTerms makes sign-up record the acceptance of the terms
	// (authclient.SignupRequest.AcceptTerms; the hosted page links the
	// branding's legal terms_url). Nil keeps the stored value.
	RequireTerms *bool `json:"require_terms,omitempty"`
	// Custom is false for the built-in default (everything allowed).
	Custom    bool   `json:"custom,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// SignInPolicy returns the environment's policy, or the default.
func (e Environment) SignInPolicy(ctx context.Context) (SignInPolicy, error) {
	var out SignInPolicy
	err := e.client.Do(ctx, "GET", e.path("sign-in-policy"), nil, &out)
	return out, err
}

// SetSignInPolicy replaces the whole policy. Audited as
// sign_in_policy.update.
func (e Environment) SetSignInPolicy(ctx context.Context, input SignInPolicy) (SignInPolicy, error) {
	input.Custom, input.UpdatedAt = false, ""
	var out SignInPolicy
	err := e.client.Do(ctx, "PUT", e.path("sign-in-policy"), input, &out)
	return out, err
}

// DeleteSignInPolicy restores the default. Audited as
// sign_in_policy.delete.
func (e Environment) DeleteSignInPolicy(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("sign-in-policy"), nil, nil)
}

// OrgAdminPortal is the hosted organization admin portal of an
// environment: when Enabled, organization administrators sign in at URL
// with IAMKit's own public OAuth client (ClientID, on the IAM resource,
// not editable) and manage their organization within their iam:org:*
// permissions.
type OrgAdminPortal struct {
	Enabled       bool   `json:"enabled"`
	ClientID      string `json:"client_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	URL           string `json:"url,omitempty"`
}

// OrgAdminPortal reports whether the portal is on and where it is.
func (e Environment) OrgAdminPortal(ctx context.Context) (OrgAdminPortal, error) {
	var out OrgAdminPortal
	err := e.client.Do(ctx, "GET", e.path("org-admin-portal"), nil, &out)
	return out, err
}

// EnableOrgAdminPortal turns the portal on (idempotent). Audited as
// org_admin_portal.enabled.
func (e Environment) EnableOrgAdminPortal(ctx context.Context) (OrgAdminPortal, error) {
	var out OrgAdminPortal
	err := e.client.Do(ctx, "PUT", e.path("org-admin-portal"), struct{}{}, &out)
	return out, err
}

// DisableOrgAdminPortal turns the portal off and ends its sessions at
// once; the organization admin API keeps working. Audited as
// org_admin_portal.disabled.
func (e Environment) DisableOrgAdminPortal(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("org-admin-portal"), nil, nil)
}

// DeliveryAttempt is the outcome of one delivery. Reason is a fixed,
// secret-free description; Status is the HTTP status of the webhook or
// Resend API when it answered.
type DeliveryAttempt struct {
	Source    string `json:"source"` // environment, global or none
	Purpose   string `json:"purpose"`
	Delivered bool   `json:"delivered"`
	Status    *int   `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	LatencyMS int    `json:"latency_ms"`
	At        string `json:"at"`
}

// DeliveryStatus says which configuration serves the environment
// (environment, global or none), its provider and its latest attempt and
// failure.
type DeliveryStatus struct {
	Source              string           `json:"source"`
	Provider            string           `json:"provider"`
	GlobalConfigured    bool             `json:"global_configured"`
	HostedInvitationURL string           `json:"hosted_invitation_url"`
	LastAttempt         *DeliveryAttempt `json:"last_attempt"`
	LastFailure         *DeliveryAttempt `json:"last_failure"`
}

// DeliveryStatus returns the effective delivery source and recent activity.
func (e Environment) DeliveryStatus(ctx context.Context) (DeliveryStatus, error) {
	var out DeliveryStatus
	err := e.client.Do(ctx, "GET", e.path("delivery/status"), nil, &out)
	return out, err
}

// TestDelivery sends a test message through the effective delivery. A
// failed delivery is returned as an attempt, not an error.
func (e Environment) TestDelivery(ctx context.Context, email string) (DeliveryAttempt, error) {
	var out DeliveryAttempt
	err := e.client.Do(ctx, "POST", e.path("delivery/test"), map[string]string{"email": email}, &out)
	return out, err
}

// SMS providers.
const (
	SMSTwilio  = "twilio"
	SMSWebhook = "webhook"
)

// SMSConfig is an environment's SMS provider (GET /sms). Secrets are
// never returned; HasSecret says one is stored.
type SMSConfig struct {
	EnvironmentID       string `json:"environment_id"`
	Provider            string `json:"provider"`
	AccountSID          string `json:"account_sid,omitempty"`
	FromNumber          string `json:"from_number,omitempty"`
	MessagingServiceSID string `json:"messaging_service_sid,omitempty"`
	WebhookURL          string `json:"webhook_url,omitempty"`
	HasSecret           bool   `json:"has_secret"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

// SetSMSConfig replaces the SMS provider. Twilio needs AccountSID,
// AuthToken and FromNumber or MessagingServiceSID; the webhook needs an
// HTTPS WebhookURL and WebhookToken (bearer + Standard Webhooks
// signature). A blank secret keeps the stored one when the provider does
// not change.
type SetSMSConfig struct {
	Provider            string `json:"provider"`
	AccountSID          string `json:"account_sid,omitempty"`
	AuthToken           string `json:"auth_token,omitempty"`
	FromNumber          string `json:"from_number,omitempty"`
	MessagingServiceSID string `json:"messaging_service_sid,omitempty"`
	WebhookURL          string `json:"webhook_url,omitempty"`
	WebhookToken        string `json:"webhook_token,omitempty"`
}

// SMSStatus says whether the environment can text and its recent activity.
type SMSStatus struct {
	Configured  bool             `json:"configured"`
	Provider    string           `json:"provider"`
	LastAttempt *DeliveryAttempt `json:"last_attempt"`
	LastFailure *DeliveryAttempt `json:"last_failure"`
}

// SMSConfig returns the SMS provider (apierror not found when none).
func (e Environment) SMSConfig(ctx context.Context) (SMSConfig, error) {
	var out SMSConfig
	err := e.client.Do(ctx, "GET", e.path("sms"), nil, &out)
	return out, err
}

// SetSMSConfig saves the SMS provider.
func (e Environment) SetSMSConfig(ctx context.Context, input SetSMSConfig) (SMSConfig, error) {
	var out SMSConfig
	err := e.client.Do(ctx, "PUT", e.path("sms"), input, &out)
	return out, err
}

// DeleteSMSConfig removes the SMS provider; SMS codes stop being sent.
func (e Environment) DeleteSMSConfig(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("sms"), nil, nil)
}

// SMSStatus returns whether SMS is configured and its recent activity.
func (e Environment) SMSStatus(ctx context.Context) (SMSStatus, error) {
	var out SMSStatus
	err := e.client.Do(ctx, "GET", e.path("sms/status"), nil, &out)
	return out, err
}

// TestSMS texts a message without a code to phone (E.164). A failed
// delivery is returned as an attempt, not an error.
func (e Environment) TestSMS(ctx context.Context, phone string) (DeliveryAttempt, error) {
	var out DeliveryAttempt
	err := e.client.Do(ctx, "POST", e.path("sms/test"), map[string]string{"phone": phone}, &out)
	return out, err
}

// Email purposes IAMKit renders (previews and templates).
const (
	EmailLogin         = "login"
	EmailPasswordReset = "password_reset"
	EmailVerification  = "email_verification"
	EmailInvitation    = "invitation"
	EmailTest          = "test"
)

// EmailCopy is the wording of one email. Empty fields use IAMKit's default;
// the {{placeholders}} allowed are listed in EmailTemplate.Placeholders.
type EmailCopy struct {
	Subject string `json:"subject"`
	Heading string `json:"heading"`
	Body    string `json:"body"`
	// Action is the button label; only emails with a link have one.
	Action string `json:"action"`
	Footer string `json:"footer"`
}

// DeliveryPreview selects a sample email: its purpose and language (empty
// = the environment's email language). Template previews unsaved wording,
// AppName an unsaved brand name (the hosted display_name).
type DeliveryPreview struct {
	Purpose  string     `json:"purpose"`
	Locale   string     `json:"locale,omitempty"`
	Template *EmailCopy `json:"template,omitempty"`
	AppName  *string    `json:"app_name,omitempty"`
}

// EmailPreview is a rendered sample email.
type EmailPreview struct {
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
}

// PreviewDelivery renders a sample email with the environment's branding
// and wording (or input.Template). It works with any provider; only smtp
// and resend send what it shows. Without a Template it is a read (GET).
func (e Environment) PreviewDelivery(ctx context.Context, input DeliveryPreview) (EmailPreview, error) {
	var out EmailPreview
	if input.Template == nil {
		q := url.Values{"purpose": {input.Purpose}}
		if input.Locale != "" {
			q.Set("locale", input.Locale)
		}
		err := e.client.do(ctx, "GET", e.path("delivery/preview"), q, nil, &out)
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("delivery/preview"), input, &out)
	return out, err
}

// EmailTemplateSummary says whether one email and language has custom wording.
type EmailTemplateSummary struct {
	Purpose    string `json:"purpose"`
	Locale     string `json:"locale"`
	Customized bool   `json:"customized"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// EmailTemplate is the saved wording (empty fields = default), IAMKit's
// defaults and the placeholders the wording may use.
type EmailTemplate struct {
	EmailTemplateSummary
	Template     EmailCopy `json:"template"`
	Defaults     EmailCopy `json:"defaults"`
	Placeholders []string  `json:"placeholders"`
}

// EmailTemplates lists every email purpose in every available language.
func (e Environment) EmailTemplates(ctx context.Context) ([]EmailTemplateSummary, error) {
	return list[EmailTemplateSummary](e, ctx, "delivery/templates")
}

// EmailTemplate returns the wording of one email in one language (an
// available code, e.g. "es").
func (e Environment) EmailTemplate(ctx context.Context, purpose, locale string) (EmailTemplate, error) {
	var out EmailTemplate
	err := e.operation(ctx, "GET", []string{"delivery", "templates", purpose, locale}, nil, &out)
	return out, err
}

// SetEmailTemplate saves the wording of one email in one language.
func (e Environment) SetEmailTemplate(ctx context.Context, purpose, locale string, input EmailCopy) (EmailTemplate, error) {
	var out EmailTemplate
	err := e.operation(ctx, "PUT", []string{"delivery", "templates", purpose, locale}, input, &out)
	return out, err
}

// ResetEmailTemplate returns one email in one language to IAMKit's wording.
func (e Environment) ResetEmailTemplate(ctx context.Context, purpose, locale string) error {
	return e.operation(ctx, "DELETE", []string{"delivery", "templates", purpose, locale}, nil, nil)
}

// ── Hosted login ──

// LoginSettings brands the hosted sign-in and invitation pages: the
// environment default, or one OAuth client's style (ClientID set). Empty
// fields use the defaults (no name, no logo, blue accent, light theme).
type LoginSettings struct {
	EnvironmentID string `json:"environment_id,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	DisplayName   string `json:"display_name"`
	// LogoURL must be an https URL.
	LogoURL string `json:"logo_url"`
	// AccentColor is "#rrggbb", the same color as Theme.Light.Primary.
	AccentColor string     `json:"accent_color"`
	Theme       LoginTheme `json:"theme"`
	// Locale is the default language of the environment's emails (a code
	// from Locales; "" = the server's EMAIL_LOCALE). Nil keeps the stored
	// value; client styles have none. The name, logo and primary color of
	// the default style also brand emails sent through smtp or resend.
	Locale *string `json:"locale,omitempty"`
	// Languages are the languages the hosted pages may use (empty = every
	// available one; environment default only). Nil keeps the stored list.
	Languages []string `json:"languages"`
	// Legal are the policy links of the sign-in and sign-up pages. Nil
	// keeps the stored ones; a client style's empty links inherit the
	// environment's.
	Legal     *LoginLegal `json:"legal,omitempty"`
	UpdatedAt string      `json:"updated_at,omitempty"`
}

// LoginLegal are the links to an application's policies: https URLs and a
// support email address.
type LoginLegal struct {
	PrivacyURL   string `json:"privacy_url,omitempty"`
	TermsURL     string `json:"terms_url,omitempty"`
	HelpURL      string `json:"help_url,omitempty"`
	SupportEmail string `json:"support_email,omitempty"`
}

// Locale is a language IAMKit has text for.
type Locale struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Locales lists the languages available for emails and hosted pages.
func (e Environment) Locales(ctx context.Context) ([]Locale, error) {
	return list[Locale](e, ctx, "login-settings/locales")
}

// LoginTheme is the look of the hosted pages. Zero values take defaults.
type LoginTheme struct {
	// Mode is "light", "dark" or "adaptive" (follows the browser).
	Mode string `json:"mode,omitempty"`
	// Radius is the corner radius in pixels, 0 to 24 (nil: 12).
	Radius *int `json:"radius,omitempty"`
	// Spacing is "compact", "normal" or "roomy".
	Spacing string `json:"spacing,omitempty"`
	// Align places the form: "center", "left" or "right".
	Align string       `json:"align,omitempty"`
	Light LoginPalette `json:"light"`
	Dark  LoginPalette `json:"dark"`
	// LogoDarkURL and FaviconURL must be https URLs.
	LogoDarkURL string `json:"logo_dark_url,omitempty"`
	FaviconURL  string `json:"favicon_url,omitempty"`
	// LogoPosition is "card" or "header" (requires Header.Show).
	LogoPosition string      `json:"logo_position,omitempty"`
	Header       LoginHeader `json:"header"`
	Footer       LoginFooter `json:"footer"`
	// BackgroundImageURL (https) covers the page behind the card;
	// BackgroundOverlay (0-90 %) tints it with the background color.
	BackgroundImageURL string `json:"background_image_url,omitempty"`
	BackgroundOverlay  int    `json:"background_overlay,omitempty"`
	// Font is the text typeface and HeadingFont the title's.
	Font        LoginFont `json:"font"`
	HeadingFont LoginFont `json:"heading_font"`
}

// LoginFont is a typeface: Family "system" (default; for HeadingFont,
// the text font), one IAMKit serves itself ("inter", "roboto",
// "open-sans", "lora"; no third-party request) or "custom" with URL, an
// https .woff2 file.
type LoginFont struct {
	Family string `json:"family,omitempty"`
	URL    string `json:"url,omitempty"`
}

// LoginPalette colors one scheme ("#rrggbb"; empty uses the default).
type LoginPalette struct {
	Primary    string `json:"primary,omitempty"`
	Background string `json:"background,omitempty"`
	Card       string `json:"card,omitempty"`
	Text       string `json:"text,omitempty"`
	Header     string `json:"header,omitempty"`
}

type LoginHeader struct {
	Show bool `json:"show"`
}

type LoginFooter struct {
	Text string `json:"text,omitempty"`
	// Links: at most 5, https or mailto URLs.
	Links []LoginLink `json:"links,omitempty"`
}

type LoginLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// LoginSettings returns the hosted login branding for this environment.
func (e Environment) LoginSettings(ctx context.Context) (LoginSettings, error) {
	var out LoginSettings
	err := e.client.Do(ctx, "GET", e.path("login-settings"), nil, &out)
	return out, err
}

// SetLoginSettings replaces the hosted login branding and returns the
// normalized result.
func (e Environment) SetLoginSettings(ctx context.Context, input LoginSettings) (LoginSettings, error) {
	var out LoginSettings
	err := e.client.Do(ctx, "PUT", e.path("login-settings"), input, &out)
	return out, err
}

// ClientLoginSettings returns an OAuth client's own style; a not-found
// error means the client uses the environment default.
func (e Environment) ClientLoginSettings(ctx context.Context, clientID string) (LoginSettings, error) {
	var out LoginSettings
	err := e.operation(ctx, "GET", []string{"login-settings", "clients", clientID}, nil, &out)
	return out, err
}

// ClientLoginStyles lists the OAuth clients that have their own style.
func (e Environment) ClientLoginStyles(ctx context.Context) ([]LoginSettings, error) {
	return list[LoginSettings](e, ctx, "login-settings/clients")
}

// SetClientLoginSettings gives an OAuth client its own style (a complete
// style, not an overlay on the default).
func (e Environment) SetClientLoginSettings(ctx context.Context, clientID string, input LoginSettings) (LoginSettings, error) {
	var out LoginSettings
	err := e.operation(ctx, "PUT", []string{"login-settings", "clients", clientID}, input, &out)
	return out, err
}

// DeleteClientLoginSettings returns an OAuth client to the default style.
func (e Environment) DeleteClientLoginSettings(ctx context.Context, clientID string) error {
	return e.operation(ctx, "DELETE", []string{"login-settings", "clients", clientID}, nil, nil)
}

// SignIn is the sign-in methods an OAuth client's hosted pages offer. At
// least one must be on. With AllConnections every active environment
// (social) connection is shown, otherwise only ConnectionIDs.
type SignIn struct {
	ClientID        string   `json:"client_id,omitempty"`
	Password        bool     `json:"password"`
	EmailCode       bool     `json:"email_code"`
	OrganizationSSO bool     `json:"organization_sso"`
	AllConnections  bool     `json:"all_connections"`
	ConnectionIDs   []string `json:"connection_ids"`
	// Signup shows "Create account" when the environment allows sign-up
	// (SignInPolicy.AllowSignup). Pass true to keep offering it.
	Signup bool `json:"signup"`
	// Passkey offers "Sign in with a passkey" (and passkey autofill) when
	// the environment allows passkeys. Clients configured before passkeys
	// existed keep false until changed.
	Passkey bool `json:"passkey"`
	// Read-only: false when the client offers every method by default.
	Custom    bool       `json:"custom,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// ClientSignIn returns the sign-in methods a client offers (every method
// when it has none of its own).
func (e Environment) ClientSignIn(ctx context.Context, clientID string) (SignIn, error) {
	var out SignIn
	err := e.operation(ctx, "GET", []string{"login-settings", "clients", clientID, "sign-in"}, nil, &out)
	return out, err
}

// ClientSignIns lists the OAuth clients with their own sign-in methods.
func (e Environment) ClientSignIns(ctx context.Context) ([]SignIn, error) {
	return list[SignIn](e, ctx, "login-settings/sign-in")
}

// SetClientSignIn chooses the sign-in methods of a client.
func (e Environment) SetClientSignIn(ctx context.Context, clientID string, input SignIn) (SignIn, error) {
	var out SignIn
	err := e.operation(ctx, "PUT", []string{"login-settings", "clients", clientID, "sign-in"}, input, &out)
	return out, err
}

// DeleteClientSignIn makes a client offer every sign-in method again.
func (e Environment) DeleteClientSignIn(ctx context.Context, clientID string) error {
	return e.operation(ctx, "DELETE", []string{"login-settings", "clients", clientID, "sign-in"}, nil, nil)
}
