package apiclient

import (
	"context"
	"encoding/json"
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
	err := e.client.Do(ctx, "GET", e.path("users", user, "metadata", key), nil, &out)
	return out, err
}

// SetUserMetadata sets one key to value (any JSON-encodable value).
func (e Environment) SetUserMetadata(ctx context.Context, user, key string, value any) error {
	return e.client.Do(ctx, "PUT", e.path("users", user, "metadata", key), value, nil)
}

// DeleteUserMetadata removes one key (404 when unset).
func (e Environment) DeleteUserMetadata(ctx context.Context, user, key string) error {
	return e.client.Do(ctx, "DELETE", e.path("users", user, "metadata", key), nil, nil)
}

// OrganizationMetadata returns one metadata value of an organization.
func (e Environment) OrganizationMetadata(ctx context.Context, organization, key string) (json.RawMessage, error) {
	var out json.RawMessage
	err := e.client.Do(ctx, "GET", e.path("organizations", organization, "metadata", key), nil, &out)
	return out, err
}

// SetOrganizationMetadata sets one key of an organization's metadata.
func (e Environment) SetOrganizationMetadata(ctx context.Context, organization, key string, value any) error {
	return e.client.Do(ctx, "PUT", e.path("organizations", organization, "metadata", key), value, nil)
}

// DeleteOrganizationMetadata removes one key.
func (e Environment) DeleteOrganizationMetadata(ctx context.Context, organization, key string) error {
	return e.client.Do(ctx, "DELETE", e.path("organizations", organization, "metadata", key), nil, nil)
}

// UpdateUserProfile merges patch into the user's profile (a nil value
// removes the attribute) and returns the result; with a user schema the
// result must conform (400 PROFILE_SCHEMA).
func (e Environment) UpdateUserProfile(ctx context.Context, user string, patch map[string]any) (map[string]any, error) {
	var out struct {
		Profile map[string]any `json:"profile"`
	}
	err := e.client.Do(ctx, "PATCH", e.path("users", user, "profile"), patch, &out)
	return out.Profile, err
}

// UserSchema returns the environment's user schema (404 when none).
func (e Environment) UserSchema(ctx context.Context) (UserSchema, error) {
	var out UserSchema
	err := e.client.Do(ctx, "GET", e.path("user-schema"), nil, &out)
	return out, err
}

// SaveUserSchema replaces the user schema; remote $ref are refused.
func (e Environment) SaveUserSchema(ctx context.Context, schema any) (UserSchema, error) {
	var out UserSchema
	err := e.client.Do(ctx, "PUT", e.path("user-schema"), map[string]any{"schema": schema}, &out)
	return out, err
}

// DeleteUserSchema removes it: profiles are no longer checked.
func (e Environment) DeleteUserSchema(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("user-schema"), nil, nil)
}
