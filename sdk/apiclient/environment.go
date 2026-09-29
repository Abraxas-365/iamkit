package apiclient

import (
	"context"
	"net/url"
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
	// Phone sets the user's number in E.164 ("" clears it).
	Phone *string `json:"phone,omitempty"`
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

// UnlockUser clears a user's wrong-password count and lockout; requires
// iam:users:write.
func (e Environment) UnlockUser(ctx context.Context, id string) error {
	return e.client.Do(ctx, "POST", e.path("users", id, "unlock"), nil, nil)
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

// DeliveryAttempt is the outcome of one delivery.
type DeliveryAttempt struct {
	Source    string `json:"source"`
	Purpose   string `json:"purpose"`
	Delivered bool   `json:"delivered"`
	Status    *int   `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	LatencyMS int    `json:"latency_ms"`
	At        string `json:"at"`
}

// DeliveryStatus is the effective delivery source, its provider and recent
// activity.
type DeliveryStatus struct {
	Source              string           `json:"source"`
	Provider            string           `json:"provider"`
	GlobalConfigured    bool             `json:"global_configured"`
	HostedInvitationURL string           `json:"hosted_invitation_url"`
	LastAttempt         *DeliveryAttempt `json:"last_attempt"`
	LastFailure         *DeliveryAttempt `json:"last_failure"`
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
