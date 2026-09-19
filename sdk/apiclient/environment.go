package apiclient

import (
	"context"
	"strings"
)

// Environment scopes API calls to a single IAMKit environment.
type Environment struct {
	client *Client
	id     string
}

func (e Environment) path(segments ...string) string {
	return "/environments/" + e.id + "/" + strings.Join(segments, "/")
}

// ── Shared types ──

// Created is returned by endpoints that create a resource.
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

type UpdateUser struct {
	OTPEnabled *bool          `json:"otp_enabled,omitempty"`
	Name       *string        `json:"name,omitempty"`
	Active     *bool          `json:"active,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
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

type Grant struct {
	ID             string   `json:"id,omitempty"`
	OrganizationID string   `json:"organization_id"`
	UserID         string   `json:"user_id"`
	ResourceID     string   `json:"resource_id"`
	Permissions    []string `json:"permissions"`
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
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// ── Users ──

func (e Environment) CreateUser(ctx context.Context, input CreateUser) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("users"), input, &out)
}

func (e Environment) Users(ctx context.Context) ([]User, error) {
	var out []User
	return out, e.client.Do(ctx, "GET", e.path("users"), nil, &out)
}

func (e Environment) User(ctx context.Context, id string) (User, error) {
	var out User
	return out, e.client.Do(ctx, "GET", e.path("users", id), nil, &out)
}

func (e Environment) UpdateUser(ctx context.Context, id string, input UpdateUser) error {
	return e.client.Do(ctx, "PATCH", e.path("users", id), input, nil)
}

func (e Environment) SuspendUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("users", id), nil, nil)
}

// ── Organizations ──

func (e Environment) CreateOrganization(ctx context.Context, name string) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("organizations"), map[string]string{"name": name}, &out)
}

func (e Environment) Organizations(ctx context.Context) ([]Organization, error) {
	var out []Organization
	return out, e.client.Do(ctx, "GET", e.path("organizations"), nil, &out)
}

func (e Environment) Organization(ctx context.Context, id string) (Organization, error) {
	var out Organization
	return out, e.client.Do(ctx, "GET", e.path("organizations", id), nil, &out)
}

func (e Environment) UpdateOrganization(ctx context.Context, id string, input map[string]any) error {
	return e.client.Do(ctx, "PATCH", e.path("organizations", id), input, nil)
}

// ── Members ──

func (e Environment) AddMember(ctx context.Context, input Membership) error {
	return e.client.Do(ctx, "POST", e.path("memberships"), input, nil)
}

func (e Environment) Members(ctx context.Context, org string) ([]Membership, error) {
	var out []Membership
	return out, e.client.Do(ctx, "GET", e.path("organizations", org, "members"), nil, &out)
}

func (e Environment) RemoveMember(ctx context.Context, org, user string) error {
	return e.client.Do(ctx, "DELETE", e.path("organizations", org, "members", user), nil, nil)
}

// ── Applications ──

func (e Environment) CreateApplication(ctx context.Context, input Application) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("applications"), input, &out)
}

func (e Environment) Applications(ctx context.Context) ([]Application, error) {
	var out []Application
	return out, e.client.Do(ctx, "GET", e.path("applications"), nil, &out)
}

func (e Environment) Application(ctx context.Context, id string) (Application, error) {
	var out Application
	return out, e.client.Do(ctx, "GET", e.path("applications", id), nil, &out)
}

func (e Environment) UpdateApplication(ctx context.Context, id string, input map[string]any) error {
	return e.client.Do(ctx, "PATCH", e.path("applications", id), input, nil)
}

// ── Resources ──

func (e Environment) CreateResource(ctx context.Context, input Resource) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("resources"), input, &out)
}

func (e Environment) Resources(ctx context.Context) ([]Resource, error) {
	var out []Resource
	return out, e.client.Do(ctx, "GET", e.path("resources"), nil, &out)
}

func (e Environment) Resource(ctx context.Context, id string) (Resource, error) {
	var out Resource
	return out, e.client.Do(ctx, "GET", e.path("resources", id), nil, &out)
}

func (e Environment) UpdateResource(ctx context.Context, id string, input map[string]any) error {
	return e.client.Do(ctx, "PUT", e.path("resources", id), input, nil)
}

func (e Environment) BindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "POST", e.path("application-resources"), map[string]string{"application_id": application, "resource_id": resource}, nil)
}

func (e Environment) UnbindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "DELETE", e.path("application-resources", application, resource), nil, nil)
}

func (e Environment) ResourcesByApplication(ctx context.Context, application string) ([]Resource, error) {
	var out []Resource
	return out, e.client.Do(ctx, "GET", e.path("applications", application, "resources"), nil, &out)
}

// ── Roles ──

func (e Environment) Roles(ctx context.Context) ([]Role, error) {
	var out []Role
	return out, e.client.Do(ctx, "GET", e.path("roles"), nil, &out)
}

func (e Environment) CreateRole(ctx context.Context, input Role) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("roles"), input, &out)
}

func (e Environment) UpdateRole(ctx context.Context, id string, input Role) error {
	return e.client.Do(ctx, "PUT", e.path("roles", id), input, nil)
}

func (e Environment) DeleteRole(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("roles", id), nil, nil)
}

func (e Environment) AssignRole(ctx context.Context, input RoleAssignment) error {
	return e.client.Do(ctx, "POST", e.path("role-assignments"), input, nil)
}

func (e Environment) RoleAssignments(ctx context.Context) ([]RoleAssignment, error) {
	var out []RoleAssignment
	return out, e.client.Do(ctx, "GET", e.path("role-assignments"), nil, &out)
}

func (e Environment) UnassignRole(ctx context.Context, role, org, user string) error {
	return e.client.Do(ctx, "DELETE", e.path("role-assignments", role, org, user), nil, nil)
}

// ── Grants ──

func (e Environment) Grants(ctx context.Context) ([]Grant, error) {
	var out []Grant
	return out, e.client.Do(ctx, "GET", e.path("grants"), nil, &out)
}

func (e Environment) PutGrant(ctx context.Context, input Grant) error {
	return e.client.Do(ctx, "PUT", e.path("grants"), input, nil)
}

func (e Environment) DeleteGrant(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("grants", id), nil, nil)
}

// ── Service Accounts ──

func (e Environment) CreateServiceAccount(ctx context.Context, input ServiceAccount) (ServiceAccountKey, error) {
	var out ServiceAccountKey
	return out, e.client.Do(ctx, "POST", e.path("service-accounts"), input, &out)
}

func (e Environment) ServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	var out []ServiceAccount
	return out, e.client.Do(ctx, "GET", e.path("service-accounts"), nil, &out)
}

func (e Environment) RevokeServiceAccount(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("service-accounts", id), nil, nil)
}
