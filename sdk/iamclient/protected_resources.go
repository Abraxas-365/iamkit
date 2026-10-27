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
	DefaultScopes  []string  `json:"default_scopes"`
	IdleTTLSeconds int64     `json:"idle_ttl_seconds"`
	MaxTTLSeconds  int64     `json:"max_ttl_seconds"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
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
}

// ProtectedResourceUpdate changes only its non-nil fields. Active false
// ends every authorization of the resource.
type ProtectedResourceUpdate struct {
	Name           *string   `json:"name,omitempty"`
	DefaultScopes  *[]string `json:"default_scopes,omitempty"`
	IdleTTLSeconds *int64    `json:"idle_ttl_seconds,omitempty"`
	MaxTTLSeconds  *int64    `json:"max_ttl_seconds,omitempty"`
	Active         *bool     `json:"active,omitempty"`
}

// ProtectedResourcePolicy are the environment's TTL ceilings for its
// protected resources.
type ProtectedResourcePolicy struct {
	MaxIdleTTLSeconds     int64 `json:"max_idle_ttl_seconds"`
	MaxLifetimeTTLSeconds int64 `json:"max_lifetime_ttl_seconds"`
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
