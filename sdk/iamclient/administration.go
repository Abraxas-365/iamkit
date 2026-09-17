package iamclient

import (
	"context"
	"strings"
	"time"
)

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
	ExpiresIn     int      `json:"expires_in,omitempty"`
}
type Credential struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	ConnectionID string    `json:"connection_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type OAuthClient struct {
	ApplicationID string   `json:"application_id"`
	ResourceID    string   `json:"resource_id"`
	RedirectURIs  []string `json:"redirect_uris"`
	Public        bool     `json:"public"`
}
type OAuthCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}
type Federation struct {
	Name      string `json:"name"`
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client_id"`
	SecretEnv string `json:"secret_env"`
}
type ExternalIdentity struct {
	ConnectionID string `json:"connection_id"`
	UserID       string `json:"user_id"`
	Subject      string `json:"subject"`
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

func (e Environment) operation(ctx context.Context, method string, parts []string, input, output any) error {
	for _, part := range parts {
		if err := safeSegment(part); err != nil {
			return err
		}
	}
	return e.client.Do(ctx, method, e.path(strings.Join(parts, "/")), input, output)
}
func (e Environment) User(ctx context.Context, id string) (User, error) {
	var out User
	err := e.operation(ctx, "GET", []string{"users", id}, nil, &out)
	return out, err
}
func (e Environment) UpdateUser(ctx context.Context, id string, input UserPatch) error {
	return e.operation(ctx, "PATCH", []string{"users", id}, input, nil)
}
func (e Environment) SuspendUser(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"users", id}, nil, nil)
}
func (e Environment) Organization(ctx context.Context, id string) (Organization, error) {
	var out Organization
	err := e.operation(ctx, "GET", []string{"organizations", id}, nil, &out)
	return out, err
}
func (e Environment) UpdateOrganization(ctx context.Context, id string, input UserPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", id}, input, nil)
}
func (e Environment) Members(ctx context.Context, org string) ([]Membership, error) {
	var out []Membership
	err := e.operation(ctx, "GET", []string{"organizations", org, "members"}, nil, &out)
	return out, err
}
func (e Environment) SetMemberProfile(ctx context.Context, org, user string, input MemberProfile) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "members", user, "profile"}, input, nil)
}
func (e Environment) RemoveMember(ctx context.Context, org, user string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "members", user}, nil, nil)
}
func (e Environment) Application(ctx context.Context, id string) (Application, error) {
	var out Application
	err := e.operation(ctx, "GET", []string{"applications", id}, nil, &out)
	return out, err
}
func (e Environment) UpdateApplication(ctx context.Context, id string, input Application) error {
	return e.operation(ctx, "PATCH", []string{"applications", id}, input, nil)
}
func (e Environment) UpdateResource(ctx context.Context, id string, input Resource) error {
	return e.operation(ctx, "PUT", []string{"resources", id}, input, nil)
}
func (e Environment) Grant(ctx context.Context, id string) (Grant, error) {
	var out Grant
	err := e.operation(ctx, "GET", []string{"grants", id}, nil, &out)
	return out, err
}
func (e Environment) DeleteGrant(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"grants", id}, nil, nil)
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
func (e Environment) UnassignRole(ctx context.Context, input RoleAssignment) error {
	return e.operation(ctx, "DELETE", []string{"role-assignments", input.RoleID, input.OrganizationID, input.UserID}, nil, nil)
}
func (e Environment) UpdateOrgUnit(ctx context.Context, org, id string, input OrgUnit) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "org-units", id}, input, nil)
}
func (e Environment) DeleteOrgUnit(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "org-units", id}, nil, nil)
}
func (e Environment) OrgUnit(ctx context.Context, org, id string) (OrgUnit, error) {
	var out OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id}, nil, &out)
	return out, err
}
func (e Environment) OrgUnitAncestors(ctx context.Context, org, id string) ([]OrgUnit, error) {
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "ancestors"}, nil, &out)
	return out, err
}
func (e Environment) OrgUnitDescendants(ctx context.Context, org, id string) ([]OrgUnit, error) {
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "descendants"}, nil, &out)
	return out, err
}
func (e Environment) OrgUnitTree(ctx context.Context, org string) ([]OrgUnit, error) {
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "tree"}, nil, &out)
	return out, err
}
func (e Environment) Positions(ctx context.Context, org string) ([]Position, error) {
	var out []Position
	err := e.operation(ctx, "GET", []string{"organizations", org, "positions"}, nil, &out)
	return out, err
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
	var out []PositionAssignment
	err := e.operation(ctx, "GET", []string{"organizations", org, "position-assignments"}, nil, &out)
	return out, err
}
func (e Environment) UnassignPosition(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "position-assignments", id}, nil, nil)
}
func (e Environment) CreateServiceAccount(ctx context.Context, input ServiceAccount) (Credential, error) {
	var out Credential
	err := e.operation(ctx, "POST", []string{"service-accounts"}, input, &out)
	return out, err
}
func (e Environment) ServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	var out []ServiceAccount
	err := e.operation(ctx, "GET", []string{"service-accounts"}, nil, &out)
	return out, err
}
func (e Environment) RevokeServiceAccount(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"service-accounts", id}, nil, nil)
}
func (e Environment) CreateProvisioningCredential(ctx context.Context, name, org, connection string) (Credential, error) {
	var out Credential
	err := e.operation(ctx, "POST", []string{"provisioning-credentials"}, map[string]string{"name": name, "organization_id": org, "connection_id": connection}, &out)
	return out, err
}
func (e Environment) RevokeProvisioningCredential(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"provisioning-credentials", id}, nil, nil)
}
func (e Environment) CreateOAuthClient(ctx context.Context, input OAuthClient) (OAuthCredential, error) {
	var out OAuthCredential
	err := e.operation(ctx, "POST", []string{"oauth-clients"}, input, &out)
	return out, err
}
func (e Environment) DisableOAuthClient(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"oauth-clients", id}, nil, nil)
}
func (e Environment) CreateFederation(ctx context.Context, input Federation) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"federation-connections"}, input, &out)
	return out, err
}
func (e Environment) DisableFederation(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"federation-connections", id}, nil, nil)
}
func (e Environment) LinkExternalIdentity(ctx context.Context, input ExternalIdentity) error {
	return e.operation(ctx, "POST", []string{"external-identities"}, input, nil)
}
func (e Environment) Sessions(ctx context.Context) ([]Session, error) {
	var out []Session
	err := e.operation(ctx, "GET", []string{"sessions"}, nil, &out)
	return out, err
}
func (e Environment) RevokeSession(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"sessions", id}, nil, nil)
}
func (e Environment) AuditEvents(ctx context.Context) ([]AuditEvent, error) {
	var out []AuditEvent
	err := e.operation(ctx, "GET", []string{"audit-events"}, nil, &out)
	return out, err
}
