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
	var out []User
	err := e.client.Do(ctx, "GET", e.path("users"), nil, &out)
	return out, err
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
	var out []Organization
	err := e.client.Do(ctx, "GET", e.path("organizations"), nil, &out)
	return out, err
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
	var out []Membership
	err := e.operation(ctx, "GET", []string{"organizations", org, "members"}, nil, &out)
	return out, err
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
	var out []Application
	err := e.client.Do(ctx, "GET", e.path("applications"), nil, &out)
	return out, err
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
	var out []Resource
	err := e.client.Do(ctx, "GET", e.path("resources"), nil, &out)
	return out, err
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
	var out []Resource
	err := e.operation(ctx, "GET", []string{"applications", application, "resources"}, nil, &out)
	return out, err
}

// ── Grants ──

func (e Environment) PutGrant(ctx context.Context, input Grant) (Created, error) {
	var out Created
	err := e.client.Do(ctx, "PUT", e.path("grants"), input, &out)
	return out, err
}

func (e Environment) Grants(ctx context.Context) ([]Grant, error) {
	var out []Grant
	err := e.client.Do(ctx, "GET", e.path("grants"), nil, &out)
	return out, err
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
	var out []Role
	err := e.client.Do(ctx, "GET", e.path("roles"), nil, &out)
	return out, err
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
	var out []RoleAssignment
	err := e.client.Do(ctx, "GET", e.path("role-assignments"), nil, &out)
	return out, err
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
	var out []OrgUnit
	err := e.client.Do(ctx, "GET", e.path("organizations/"+organization+"/org-units"), nil, &out)
	return out, err
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
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "ancestors"}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitDescendants(ctx context.Context, org, id string) ([]OrgUnit, error) {
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "descendants"}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitDeleteImpact(ctx context.Context, org, id string) (UnitImpact, error) {
	var out UnitImpact
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "delete-impact"}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitTree(ctx context.Context, org string) ([]OrgUnit, error) {
	var out []OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "tree"}, nil, &out)
	return out, err
}

func (e Environment) OrgChart(ctx context.Context, org string) ([]ReportingMember, error) {
	var out []ReportingMember
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-chart"}, nil, &out)
	return out, err
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
