package iamclient

import (
	"context"
	"fmt"
	"strings"
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
	ID     string `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type CreateUser struct {
	OTPEnabled bool   `json:"otp_enabled"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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

func (e Environment) SuspendUser(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"users", id}, nil, nil)
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

// DeliveryConfig is the per-environment webhook delivery configuration.
type DeliveryConfig struct {
	EnvironmentID string `json:"environment_id"`
	WebhookURL    string `json:"webhook_url"`
	HasToken      bool   `json:"has_token"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// SetDeliveryConfig creates or replaces the per-environment delivery webhook.
type SetDeliveryConfig struct {
	WebhookURL   string `json:"webhook_url"`
	WebhookToken string `json:"webhook_token"`
}

// DeliveryConfig returns the delivery webhook configuration for this environment.
func (e Environment) DeliveryConfig(ctx context.Context) (DeliveryConfig, error) {
	var out DeliveryConfig
	err := e.client.Do(ctx, "GET", e.path("delivery"), nil, &out)
	return out, err
}

// SetDeliveryConfig creates or replaces the delivery webhook for this environment.
func (e Environment) SetDeliveryConfig(ctx context.Context, input SetDeliveryConfig) error {
	return e.client.Do(ctx, "PUT", e.path("delivery"), input, nil)
}

// DeleteDeliveryConfig removes the per-environment delivery webhook,
// falling back to the global EMAIL_WEBHOOK_URL.
func (e Environment) DeleteDeliveryConfig(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("delivery"), nil, nil)
}
