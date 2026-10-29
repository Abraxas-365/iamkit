package iamclient

import (
	"context"
	"time"
)

// ProtectedResource registers a resource as an RFC 8707 protected resource
// (an MCP server): clients ask for it with resource=URI and get tokens with
// aud = URI and the resource's permissions as scopes.
type ProtectedResource struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	ApplicationID string `json:"application_id"`
	ResourceID    string `json:"resource_id"`
	// URI is the resource's audience, canonical (the tokens' aud).
	URI  string `json:"uri"`
	Name string `json:"name"`
	// DefaultScopes are granted when a client asks for no scope.
	DefaultScopes  []string `json:"default_scopes"`
	IdleTTLSeconds int64    `json:"idle_ttl_seconds"`
	MaxTTLSeconds  int64    `json:"max_ttl_seconds"`
	Active         bool     `json:"active"`
	// AllowClientMetadata lets clients named by an https client_id URL (a
	// Client ID Metadata Document) ask for this server.
	AllowClientMetadata bool `json:"allow_client_metadata"`
	// AllowDynamicRegistration lets clients registered at /oauth/register
	// (RFC 7591) ask for this server, while the environment's
	// dynamic_client_registration feature is on.
	AllowDynamicRegistration bool `json:"allow_dynamic_registration"`
	// ClientAdmission is ClientAdmissionAllowlist or ClientAdmissionOpen:
	// how such clients are admitted the first time.
	ClientAdmission string `json:"client_admission"`
	// ConsentMode is ConsentModePerUser or ConsentModeAdminGranted: whether
	// each user consents to what a client asks, or an administrator may
	// grant a client scopes for them (see GrantClient).
	ConsentMode string `json:"consent_mode"`
	// AccessTokenTTLSeconds is the lifetime of the access tokens the server
	// gets (60 to 3600, never past the idle TTL).
	AccessTokenTTLSeconds int64     `json:"access_token_ttl_seconds"`
	CreatedAt             time.Time `json:"created_at"`
}

// Consent modes of a protected resource (ProtectedResource.ConsentMode).
const (
	ConsentModePerUser      = "per_user"
	ConsentModeAdminGranted = "admin_granted"
)

// Where an environment's users consent
// (ProtectedResourcePolicy.ConsentUI).
const (
	ConsentUIHosted = "hosted"
	ConsentUICustom = "custom"
)

// Consent policies of an OAuth client (OAuthClient.ConsentPolicy): whether
// its users consent to what it asks for at a protected resource. Clients
// named outside IAMKit and clients made from a preset are always
// ConsentRequired.
const (
	ConsentRequired = "required"
	ConsentSkip     = "skip"
)

// ProtectedResourceImpact is what deactivating or deleting a protected
// resource would end.
type ProtectedResourceImpact struct {
	// ActiveSessions are the live OAuth sessions of its resource.
	ActiveSessions int `json:"active_sessions"`
	// ExternalClients are the clients named by a metadata document it
	// knows; deleting the server forgets them and their grants.
	ExternalClients int `json:"external_clients"`
}

// ProtectedResourceCreate registers a resource linked to the application.
// Zero TTLs take the defaults (7 days idle, 30 days in all).
type ProtectedResourceCreate struct {
	ApplicationID  string   `json:"application_id"`
	ResourceID     string   `json:"resource_id"`
	Name           string   `json:"name"`
	DefaultScopes  []string `json:"default_scopes,omitempty"`
	IdleTTLSeconds int64    `json:"idle_ttl_seconds,omitempty"`
	MaxTTLSeconds  int64    `json:"max_ttl_seconds,omitempty"`
	// ConsentMode is ConsentModePerUser (default) or ConsentModeAdminGranted.
	ConsentMode string `json:"consent_mode,omitempty"`
	// AccessTokenTTLSeconds takes the default when zero.
	AccessTokenTTLSeconds int64 `json:"access_token_ttl_seconds,omitempty"`
}

// ProtectedResourceUpdate changes only its non-nil fields. Active false
// ends every authorization of the resource.
type ProtectedResourceUpdate struct {
	Name           *string   `json:"name,omitempty"`
	DefaultScopes  *[]string `json:"default_scopes,omitempty"`
	IdleTTLSeconds *int64    `json:"idle_ttl_seconds,omitempty"`
	MaxTTLSeconds  *int64    `json:"max_ttl_seconds,omitempty"`
	Active         *bool     `json:"active,omitempty"`
	// AllowClientMetadata turns clients named by a metadata document on or
	// off for this server; ClientAdmission is ClientAdmissionAllowlist or
	// ClientAdmissionOpen (open admits any such client without review).
	AllowClientMetadata *bool   `json:"allow_client_metadata,omitempty"`
	ClientAdmission     *string `json:"client_admission,omitempty"`
	// AllowDynamicRegistration turns dynamically registered clients on or
	// off for this server (off demotes their approvals).
	AllowDynamicRegistration *bool `json:"allow_dynamic_registration,omitempty"`
	// ConsentMode is ConsentModePerUser or ConsentModeAdminGranted.
	ConsentMode           *string `json:"consent_mode,omitempty"`
	AccessTokenTTLSeconds *int64  `json:"access_token_ttl_seconds,omitempty"`
}

// ProtectedResourcePolicy are the environment's TTL ceilings for its
// protected resources and where its users consent.
type ProtectedResourcePolicy struct {
	MaxIdleTTLSeconds     int64 `json:"max_idle_ttl_seconds"`
	MaxLifetimeTTLSeconds int64 `json:"max_lifetime_ttl_seconds"`
	// ConsentUI is ConsentUIHosted (IAMKit's consent page) or
	// ConsentUICustom (your own sign-in UI). Left out, the saved one stays.
	ConsentUI string `json:"consent_ui,omitempty"`
}

func (e Environment) ProtectedResources(ctx context.Context) ([]ProtectedResource, error) {
	return list[ProtectedResource](e, ctx, "protected-resources")
}

func (e Environment) ProtectedResource(ctx context.Context, id string) (ProtectedResource, error) {
	var out ProtectedResource
	err := e.operation(ctx, "GET", []string{"protected-resources", id}, nil, &out)
	return out, err
}

func (e Environment) CreateProtectedResource(ctx context.Context, input ProtectedResourceCreate) (ProtectedResource, error) {
	var out ProtectedResource
	err := e.operation(ctx, "POST", []string{"protected-resources"}, input, &out)
	return out, err
}

func (e Environment) UpdateProtectedResource(ctx context.Context, id string, input ProtectedResourceUpdate) (ProtectedResource, error) {
	var out ProtectedResource
	err := e.operation(ctx, "PATCH", []string{"protected-resources", id}, input, &out)
	return out, err
}

// DeleteProtectedResource removes the registration and ends its
// authorizations; the resource itself stays.
func (e Environment) DeleteProtectedResource(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"protected-resources", id}, nil, nil)
}

// ProtectedResourceImpact counts what deactivating or deleting the
// resource would end, so a caller can warn first.
func (e Environment) ProtectedResourceImpact(ctx context.Context, id string) (ProtectedResourceImpact, error) {
	var out ProtectedResourceImpact
	err := e.operation(ctx, "GET", []string{"protected-resources", id, "impact"}, nil, &out)
	return out, err
}

func (e Environment) ProtectedResourcePolicy(ctx context.Context) (ProtectedResourcePolicy, error) {
	var out ProtectedResourcePolicy
	err := e.operation(ctx, "GET", []string{"protected-resource-policy"}, nil, &out)
	return out, err
}

// SetProtectedResourcePolicy replaces the ceilings; protected resources
// above a lowered ceiling are trimmed to it.
func (e Environment) SetProtectedResourcePolicy(ctx context.Context, policy ProtectedResourcePolicy) (ProtectedResourcePolicy, error) {
	var out ProtectedResourcePolicy
	err := e.operation(ctx, "PUT", []string{"protected-resource-policy"}, policy, &out)
	return out, err
}
