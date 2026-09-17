package iamclient

import (
	"context"
	"fmt"
	"strings"
)

type Environment struct {
	client Client
	ID     string
}

func (c Client) Environment(id string) (Environment, error) {
	if id == "" || strings.ContainsAny(id, "/?#.%\\") {
		return Environment{}, fmt.Errorf("invalid environment ID")
	}
	return Environment{c, id}, nil
}
func (e Environment) path(collection string) string {
	return "/environments/" + e.ID + "/" + collection
}

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
func (e Environment) AddMember(ctx context.Context, input Membership) error {
	return e.client.Do(ctx, "POST", e.path("memberships"), input, nil)
}
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
func (e Environment) BindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "POST", e.path("application-resources"), map[string]string{"application_id": application, "resource_id": resource}, nil)
}
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
func (e Environment) AssignRole(ctx context.Context, input RoleAssignment) error {
	return e.client.Do(ctx, "POST", e.path("role-assignments"), input, nil)
}
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
func (e Environment) CreatePosition(ctx context.Context, organization string, input Position) (Created, error) {
	var out Created
	if err := safeSegment(organization); err != nil {
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("organizations/"+organization+"/positions"), input, &out)
	return out, err
}
