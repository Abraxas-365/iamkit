package iamclient

import (
	"context"
	"encoding/json"
	"time"
)

// ── Metadata & profiles ──
//
// Metadata is free-form operator data on users and organizations: at most
// 64 keys matching ^[a-zA-Z0-9_.-]{1,64}$, values of at most 4 KiB, 32 KiB
// in total. A user's Profile holds the attributes the environment's user
// schema (JSON Schema 2020-12) describes.

// UserMetadata returns one metadata value of a user (404 when unset).
func (e Environment) UserMetadata(ctx context.Context, user, key string) (json.RawMessage, error) {
	var out json.RawMessage
	err := e.operation(ctx, "GET", []string{"users", user, "metadata", key}, nil, &out)
	return out, err
}

// SetUserMetadata sets one key to value (any JSON-encodable value).
func (e Environment) SetUserMetadata(ctx context.Context, user, key string, value any) error {
	return e.operation(ctx, "PUT", []string{"users", user, "metadata", key}, value, nil)
}

// DeleteUserMetadata removes one key (404 when unset).
func (e Environment) DeleteUserMetadata(ctx context.Context, user, key string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "metadata", key}, nil, nil)
}

// OrganizationMetadata returns one metadata value of an organization.
func (e Environment) OrganizationMetadata(ctx context.Context, organization, key string) (json.RawMessage, error) {
	var out json.RawMessage
	err := e.operation(ctx, "GET", []string{"organizations", organization, "metadata", key}, nil, &out)
	return out, err
}

// SetOrganizationMetadata sets one key of an organization's metadata.
func (e Environment) SetOrganizationMetadata(ctx context.Context, organization, key string, value any) error {
	return e.operation(ctx, "PUT", []string{"organizations", organization, "metadata", key}, value, nil)
}

// DeleteOrganizationMetadata removes one key.
func (e Environment) DeleteOrganizationMetadata(ctx context.Context, organization, key string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", organization, "metadata", key}, nil, nil)
}

// UpdateUserProfile merges patch into the user's profile (a nil value
// removes the attribute) and returns the result; with a user schema the
// result must conform (400 PROFILE_SCHEMA).
func (e Environment) UpdateUserProfile(ctx context.Context, user string, patch map[string]any) (map[string]any, error) {
	var out struct {
		Profile map[string]any `json:"profile"`
	}
	err := e.operation(ctx, "PATCH", []string{"users", user, "profile"}, patch, &out)
	return out.Profile, err
}

// UserSchema is an environment's profile schema. Properties may carry
// "x-iamkit-self": "read"|"write" (visible/editable at
// /identity/v1/me/profile) and "x-iamkit-claim": "<name>" (released in ID
// tokens and UserInfo with the profile scope).
type UserSchema struct {
	Schema    json.RawMessage `json:"schema"`
	Version   int             `json:"version"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
	// NonConforming counts existing profiles the saved schema rejects
	// (answered by SaveUserSchema only); they must conform on their next
	// write.
	NonConforming int `json:"non_conforming,omitempty"`
}

// UserSchema returns the environment's user schema (404 when none).
func (e Environment) UserSchema(ctx context.Context) (UserSchema, error) {
	var out UserSchema
	err := e.operation(ctx, "GET", []string{"user-schema"}, nil, &out)
	return out, err
}

// SaveUserSchema replaces the user schema; remote $ref are refused.
func (e Environment) SaveUserSchema(ctx context.Context, schema any) (UserSchema, error) {
	var out UserSchema
	err := e.operation(ctx, "PUT", []string{"user-schema"}, map[string]any{"schema": schema}, &out)
	return out, err
}

// DeleteUserSchema removes it: profiles are no longer checked.
func (e Environment) DeleteUserSchema(ctx context.Context) error {
	return e.operation(ctx, "DELETE", []string{"user-schema"}, nil, nil)
}
