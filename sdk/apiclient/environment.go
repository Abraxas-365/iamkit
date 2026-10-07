package apiclient

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
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

// items decodes a list response: the paginated envelope
// {"items":[...],"page":{...}} or a bare array.
// page is one response of a collection: {"items":[...],"page":{...}}, or
// a plain array for the few collections that are not paginated.
type page[T any] struct {
	Items []T `json:"items"`
	Page  *struct {
		Total int `json:"total"`
	} `json:"page"`
}

func (p *page[T]) UnmarshalJSON(raw []byte) error {
	if trimmed := strings.TrimSpace(string(raw)); strings.HasPrefix(trimmed, "[") || trimmed == "null" {
		p.Page = nil
		return json.Unmarshal(raw, &p.Items)
	}
	type plain page[T]
	return json.Unmarshal(raw, (*plain)(p))
}

// maxPage is the server's largest page.
const maxPage = 100

// list GETs every page of a collection (query filters kept) and returns
// the items, never nil.
func list[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	out := []T{}
	params := url.Values{}
	for k, v := range query {
		params[k] = v
	}
	for {
		var p page[T]
		if err := c.do(ctx, "GET", path, params, nil, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Items...)
		if p.Page == nil || len(p.Items) == 0 || len(out) >= p.Page.Total {
			return out, nil
		}
		params.Set("limit", strconv.Itoa(maxPage))
		params.Set("offset", strconv.Itoa(len(out)))
	}
}

// first GETs one page of a log or outbox (newest first) and returns its
// items, never nil.
func first[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var p page[T]
	if err := c.do(ctx, "GET", path, query, nil, &p); err != nil {
		return nil, err
	}
	if p.Items == nil {
		return []T{}, nil
	}
	return p.Items, nil
}

// ── Shared types ──

// ── Users ──

func (e Environment) CreateUser(ctx context.Context, input CreateUser) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("users"), input, &out)
}

func (e Environment) Users(ctx context.Context) ([]User, error) {
	return list[User](ctx, e.client, e.path("users"), nil)
}

func (e Environment) User(ctx context.Context, id string) (User, error) {
	var out User
	return out, e.client.Do(ctx, "GET", e.path("users", id), nil, &out)
}

func (e Environment) UpdateUser(ctx context.Context, id string, input UserPatch) error {
	return e.client.Do(ctx, "PATCH", e.path("users", id), input, nil)
}

func (e Environment) SuspendUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("users", id), nil, nil)
}

// UsersInState lists the first page of users in state (suspended,
// locked, initial, inactive or active).
func (e Environment) UsersInState(ctx context.Context, state string) ([]User, error) {
	return list[User](ctx, e.client, e.path("users"), url.Values{"state": {state}})
}

// DeactivateUser suspends a user; requires iam:users:write.
func (e Environment) DeactivateUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "POST", e.path("users", id, "deactivate"), nil, nil)
}

// ReactivateUser lifts a suspension; requires iam:users:write.
func (e Environment) ReactivateUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "POST", e.path("users", id, "reactivate"), nil, nil)
}

// UnlockUser clears a user's wrong-password count and lockout; requires
// iam:users:write.
func (e Environment) UnlockUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "POST", e.path("users", id, "unlock"), nil, nil)
}

// ── Machine users ──

// CreateMachineUser creates a user of kind "machine" (no email, password
// or second factor); requires iam:users:write.
// homeOrganization ("" for none) is the organization owning the record.
func (e Environment) CreateMachineUser(ctx context.Context, name, homeOrganization string) (Created, error) {
	body := map[string]string{"kind": "machine", "name": name}
	if homeOrganization != "" {
		body["home_organization_id"] = homeOrganization
	}
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("users"), body, &out)
}

// MachineUsers lists the first page of machine users; requires iam:users:read.
func (e Environment) MachineUsers(ctx context.Context) ([]User, error) {
	return list[User](ctx, e.client, e.path("users"), url.Values{"kind": {"machine"}})
}

// CreateAccessToken issues a machine user's personal access token;
// requires iam:users:write.
func (e Environment) CreateAccessToken(ctx context.Context, user string, input CreateAccessToken) (IssuedAccessToken, error) {
	var out IssuedAccessToken
	return out, e.client.Do(ctx, "POST", e.path("users", user, "access-tokens"), input, &out)
}

// AccessTokens lists the first page of a machine user's tokens; requires
// iam:users:read.
func (e Environment) AccessTokens(ctx context.Context, user string) ([]AccessToken, error) {
	return list[AccessToken](ctx, e.client, e.path("users", user, "access-tokens"), nil)
}

// RevokeAccessToken revokes a token and the sessions exchanged from it;
// requires iam:users:write.
func (e Environment) RevokeAccessToken(ctx context.Context, user, token string) error {
	return e.client.Do(ctx, "DELETE", e.path("users", user, "access-tokens", token), nil, nil)
}

// AddUserKey adds a key to a machine user; requires iam:users:write.
func (e Environment) AddUserKey(ctx context.Context, user string, input AddUserKey) (IssuedUserKey, error) {
	var out IssuedUserKey
	return out, e.client.Do(ctx, "POST", e.path("users", user, "keys"), input, &out)
}

// UserKeys lists the first page of a machine user's keys; requires
// iam:users:read.
func (e Environment) UserKeys(ctx context.Context, user string) ([]UserKey, error) {
	return list[UserKey](ctx, e.client, e.path("users", user, "keys"), nil)
}

// RemoveUserKey deletes a key and ends the sessions opened with it;
// requires iam:users:write.
func (e Environment) RemoveUserKey(ctx context.Context, user, key string) error {
	return e.client.Do(ctx, "DELETE", e.path("users", user, "keys", key), nil, nil)
}

// ── Organizations ──

func (e Environment) CreateOrganization(ctx context.Context, name string) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("organizations"), map[string]string{"name": name}, &out)
}

func (e Environment) Organizations(ctx context.Context) ([]Organization, error) {
	return list[Organization](ctx, e.client, e.path("organizations"), nil)
}

func (e Environment) Organization(ctx context.Context, id string) (Organization, error) {
	var out Organization
	return out, e.client.Do(ctx, "GET", e.path("organizations", id), nil, &out)
}

func (e Environment) UpdateOrganization(ctx context.Context, id string, input OrganizationPatch) error {
	return e.client.Do(ctx, "PATCH", e.path("organizations", id), input, nil)
}

// ── Members ──

func (e Environment) AddMember(ctx context.Context, input Membership) error {
	return e.client.Do(ctx, "POST", e.path("memberships"), input, nil)
}

func (e Environment) Members(ctx context.Context, org string) ([]Member, error) {
	return list[Member](ctx, e.client, e.path("organizations", org, "members"), nil)
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
	return list[Application](ctx, e.client, e.path("applications"), nil)
}

func (e Environment) Application(ctx context.Context, id string) (Application, error) {
	var out Application
	return out, e.client.Do(ctx, "GET", e.path("applications", id), nil, &out)
}

func (e Environment) UpdateApplication(ctx context.Context, id string, input ApplicationPatch) error {
	return e.client.Do(ctx, "PATCH", e.path("applications", id), input, nil)
}

// ── Resources ──

func (e Environment) CreateResource(ctx context.Context, input Resource) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "POST", e.path("resources"), input, &out)
}

func (e Environment) Resources(ctx context.Context) ([]Resource, error) {
	return list[Resource](ctx, e.client, e.path("resources"), nil)
}

func (e Environment) Resource(ctx context.Context, id string) (Resource, error) {
	var out Resource
	return out, e.client.Do(ctx, "GET", e.path("resources", id), nil, &out)
}

func (e Environment) UpdateResource(ctx context.Context, id string, input ResourcePatch) error {
	return e.client.Do(ctx, "PUT", e.path("resources", id), input, nil)
}

func (e Environment) BindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "POST", e.path("application-resources"), map[string]string{"application_id": application, "resource_id": resource}, nil)
}

func (e Environment) UnbindResource(ctx context.Context, application, resource string) error {
	return e.client.Do(ctx, "DELETE", e.path("application-resources", application, resource), nil, nil)
}

// ApplicationResources lists the resources bound to an application.
func (e Environment) ApplicationResources(ctx context.Context, application string) ([]Resource, error) {
	return list[Resource](ctx, e.client, e.path("applications", application, "resources"), nil)
}

// ── Roles ──

func (e Environment) Roles(ctx context.Context) ([]Role, error) {
	return list[Role](ctx, e.client, e.path("roles"), nil)
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

func (e Environment) RoleAssignments(ctx context.Context) ([]RoleAssignmentView, error) {
	return list[RoleAssignmentView](ctx, e.client, e.path("role-assignments"), nil)
}

func (e Environment) UnassignRole(ctx context.Context, input RoleAssignment) error {
	return e.operation(ctx, "DELETE", []string{"role-assignments", input.RoleID, input.OrganizationID, input.UserID}, nil, nil)
}

// ── Grants ──

func (e Environment) Grants(ctx context.Context) ([]Grant, error) {
	return list[Grant](ctx, e.client, e.path("grants"), nil)
}

func (e Environment) PutGrant(ctx context.Context, input Grant) (Created, error) {
	var out Created
	return out, e.client.Do(ctx, "PUT", e.path("grants"), input, &out)
}

func (e Environment) DeleteGrant(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("grants", id), nil, nil)
}

// ── Resource grants (iam:roles:*; access needs iam:resources:write) ──

// SetResourceAccess sets the resource's owner organization and whether it
// requires a grant; organizations losing access have their sessions ended.
func (e Environment) SetResourceAccess(ctx context.Context, resource string, input ResourceAccess) error {
	return e.client.Do(ctx, "PUT", e.path("resources", resource, "access"), input, nil)
}

// ResourceGrants lists grants, optionally of one resource and/or to one
// organization ("" = any).
func (e Environment) ResourceGrants(ctx context.Context, resource, organization string) ([]ResourceGrant, error) {
	q := url.Values{}
	if resource != "" {
		q.Set("resource_id", resource)
	}
	if organization != "" {
		q.Set("organization_id", organization)
	}
	return list[ResourceGrant](ctx, e.client, e.path("resource-grants"), q)
}

func (e Environment) ResourceGrant(ctx context.Context, id string) (ResourceGrant, error) {
	var out ResourceGrant
	return out, e.client.Do(ctx, "GET", e.path("resource-grants", id), nil, &out)
}

// PutResourceGrant grants the resource to the organization, or replaces
// the granted roles; narrowing ends the organization's sessions for it.
func (e Environment) PutResourceGrant(ctx context.Context, input ResourceGrant) (ResourceGrant, error) {
	var out ResourceGrant
	return out, e.client.Do(ctx, "PUT", e.path("resource-grants"), input, &out)
}

func (e Environment) DeleteResourceGrant(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("resource-grants", id), nil, nil)
}

// ── Service Accounts ──

func (e Environment) CreateServiceAccount(ctx context.Context, input ServiceAccount) (ServiceAccountKey, error) {
	var out ServiceAccountKey
	return out, e.client.Do(ctx, "POST", e.path("service-accounts"), input, &out)
}

func (e Environment) ServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return list[ServiceAccount](ctx, e.client, e.path("service-accounts"), nil)
}

func (e Environment) RevokeServiceAccount(ctx context.Context, id string) error {
	return e.client.Do(ctx, "DELETE", e.path("service-accounts", id), nil, nil)
}

// ── Delivery Config ──

// Email delivery providers of an environment.
const (
	DeliveryWebhook = "webhook" // IAMKit posts JSON to your endpoint, which writes and sends the email
	DeliverySMTP    = "smtp"    // IAMKit renders the email and sends it through an SMTP server
	DeliveryResend  = "resend"  // IAMKit renders the email and sends it through the Resend API
)

// DeliveryConfig returns the delivery configuration for this environment.
func (e Environment) DeliveryConfig(ctx context.Context) (DeliveryConfig, error) {
	var out DeliveryConfig
	return out, e.client.Do(ctx, "GET", e.path("delivery"), nil, &out)
}

// SetDeliveryConfig creates or replaces the delivery for this environment.
func (e Environment) SetDeliveryConfig(ctx context.Context, input SetDeliveryConfig) error {
	return e.client.Do(ctx, "PUT", e.path("delivery"), input, nil)
}

// DeleteDeliveryConfig removes the per-environment delivery, falling back
// to the global sender.
func (e Environment) DeleteDeliveryConfig(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("delivery"), nil, nil)
}

// DeliveryStatus requires delivery:read.
func (e Environment) DeliveryStatus(ctx context.Context) (DeliveryStatus, error) {
	var out DeliveryStatus
	return out, e.client.Do(ctx, "GET", e.path("delivery", "status"), nil, &out)
}

// TestDelivery sends a test message; requires delivery:write.
func (e Environment) TestDelivery(ctx context.Context, email string) (DeliveryAttempt, error) {
	var out DeliveryAttempt
	return out, e.client.Do(ctx, "POST", e.path("delivery", "test"), map[string]string{"email": email}, &out)
}

// Email purposes IAMKit renders (previews and templates).
const (
	EmailLogin         = "login"
	EmailPasswordReset = "password_reset"
	EmailVerification  = "email_verification"
	EmailInvitation    = "invitation"
	EmailTest          = "test"
)

// PreviewDelivery renders a sample email. Without a Template it reads the
// saved wording (GET, delivery:read); a draft Template is sent with POST
// and needs delivery:write.
func (e Environment) PreviewDelivery(ctx context.Context, input DeliveryPreview) (EmailPreview, error) {
	var out EmailPreview
	if input.Template == nil {
		q := url.Values{"purpose": {input.Purpose}}
		if input.Locale != "" {
			q.Set("locale", input.Locale)
		}
		return out, e.client.do(ctx, "GET", e.path("delivery", "preview"), q, nil, &out)
	}
	return out, e.client.Do(ctx, "POST", e.path("delivery", "preview"), input, &out)
}

// EmailTemplates lists every email purpose in every available language;
// requires delivery:read.
func (e Environment) EmailTemplates(ctx context.Context) ([]EmailTemplateSummary, error) {
	var out struct {
		Items []EmailTemplateSummary `json:"items"`
	}
	if err := e.client.Do(ctx, "GET", e.path("delivery", "templates"), nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []EmailTemplateSummary{}
	}
	return out.Items, nil
}

// EmailTemplate returns the wording of one email in one language; requires
// delivery:read.
func (e Environment) EmailTemplate(ctx context.Context, purpose, locale string) (EmailTemplate, error) {
	var out EmailTemplate
	return out, e.client.Do(ctx, "GET", e.path("delivery", "templates", url.PathEscape(purpose), url.PathEscape(locale)), nil, &out)
}

// SetEmailTemplate saves the wording of one email in one language; requires
// delivery:write.
func (e Environment) SetEmailTemplate(ctx context.Context, purpose, locale string, input EmailCopy) (EmailTemplate, error) {
	var out EmailTemplate
	return out, e.client.Do(ctx, "PUT", e.path("delivery", "templates", url.PathEscape(purpose), url.PathEscape(locale)), input, &out)
}

// ResetEmailTemplate returns one email in one language to IAMKit's wording;
// requires delivery:write.
func (e Environment) ResetEmailTemplate(ctx context.Context, purpose, locale string) error {
	return e.client.Do(ctx, "DELETE", e.path("delivery", "templates", url.PathEscape(purpose), url.PathEscape(locale)), nil, nil)
}
