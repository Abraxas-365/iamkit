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
	ID        string `json:"id,omitempty"`
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
	var out []ServiceAccount
	err := e.operation(ctx, "GET", []string{"service-accounts"}, nil, &out)
	return out, err
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
	var out []Credential
	err := e.operation(ctx, "GET", []string{"provisioning-credentials"}, nil, &out)
	return out, err
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
	var out []OAuthCredential
	err := e.operation(ctx, "GET", []string{"oauth-clients"}, nil, &out)
	return out, err
}

func (e Environment) DisableOAuthClient(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"oauth-clients", id}, nil, nil)
}

// ── Federation ──

func (e Environment) CreateFederation(ctx context.Context, input Federation) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"federation-connections"}, input, &out)
	return out, err
}

func (e Environment) FederationConnections(ctx context.Context) ([]Federation, error) {
	var out []Federation
	err := e.operation(ctx, "GET", []string{"federation-connections"}, nil, &out)
	return out, err
}

func (e Environment) FederationConnection(ctx context.Context, id string) (Federation, error) {
	var out Federation
	err := e.operation(ctx, "GET", []string{"federation-connections", id}, nil, &out)
	return out, err
}

func (e Environment) FederationIdentities(ctx context.Context, id string) ([]ExternalIdentity, error) {
	var out []ExternalIdentity
	err := e.operation(ctx, "GET", []string{"federation-connections", id, "identities"}, nil, &out)
	return out, err
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

// ── Impersonation ──

func (e Environment) Impersonate(ctx context.Context, input Impersonation) (authclient.TokenPair, error) {
	var out authclient.TokenPair
	err := e.operation(ctx, "POST", []string{"impersonations"}, input, &out)
	return out, err
}
