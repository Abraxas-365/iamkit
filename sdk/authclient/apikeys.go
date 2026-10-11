package authclient

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

// APIKeyPrefix starts every API key value: ik_key_.
const APIKeyPrefix = "ik_key_"

// IsAPIKey reports whether value looks like an API key (not that it is valid).
func IsAPIKey(value string) bool { return strings.HasPrefix(value, APIKeyPrefix) }

// APIKeyOwner says whose key it is. Type is "user", "organization" or
// "machine"; ID is the user (empty for an organization key);
// OrganizationID is the organization the key works in.
type APIKeyOwner struct {
	Type           string `json:"type"`
	ID             string `json:"id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
}

// APIKey is a validated API key: what IAMKit confirmed on a request.
type APIKey struct {
	ID             string
	Name           string
	Owner          APIKeyOwner
	OrganizationID string
	ResourceID     string
	// Permissions are the key's effective permissions right now: its own
	// list narrowed by the resource allowlist and what its owner can still
	// do. Never empty on a valid key.
	Permissions []string
	// ExpiresAt is when the key stops working; the zero time = never.
	ExpiresAt time.Time
}

// HasPermission reports whether the key carries the permission.
func (k APIKey) HasPermission(required string) bool {
	for _, p := range k.Permissions {
		if p == required {
			return true
		}
	}
	return false
}

// ValidateAPIKey asks IAMKit whether value (ik_key_…) is a live key for the
// audience this client was configured with (WithAudience) and returns it.
// Inactive, revoked, expired, unknown or other-resource keys, and values
// that are not API keys, answer an UNAUTHORIZED error; an unreachable
// IAMKit answers its own error: never admit the request then. Call it per
// request: the answer is not cacheable beyond the permissions' freshness you
// accept.
func (c *Client) ValidateAPIKey(ctx context.Context, apiKey string) (APIKey, error) {
	if !IsAPIKey(apiKey) {
		return APIKey{}, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid API key", HTTPStatus: 401}
	}
	if c.environment == "" || c.audience == "" {
		return APIKey{}, &apierror.Error{Code: "VALIDATION", Message: "environment and audience required (WithAudience)", HTTPStatus: 400}
	}
	var out struct {
		Active bool `json:"active"`
		Claims struct {
			Purpose        string   `json:"purpose"`
			EnvironmentID  string   `json:"environment_id"`
			OrganizationID string   `json:"organization_id"`
			ResourceID     string   `json:"resource_id"`
			Audience       []string `json:"aud"`
			APIKey         *struct {
				ID         string      `json:"id"`
				Name       string      `json:"name"`
				Owner      APIKeyOwner `json:"owner"`
				ResourceID string      `json:"resource_id"`
				Permission []string    `json:"permissions"`
				ExpiresAt  int64       `json:"expires_at"`
			} `json:"api_key"`
		} `json:"claims"`
	}
	body := map[string]string{"environment_id": c.environment, "audience": c.audience}
	if err := c.request(ctx, "/introspect", apiKey, body, &out); err != nil {
		return APIKey{}, err
	}
	claims, key := out.Claims, out.Claims.APIKey
	if !out.Active || key == nil || claims.Purpose != "api_key" || claims.EnvironmentID != c.environment || !contains(claims.Audience, c.audience) || key.ID == "" || len(key.Permission) == 0 {
		return APIKey{}, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid or inactive API key", HTTPStatus: 401}
	}
	result := APIKey{ID: key.ID, Name: key.Name, Owner: key.Owner, OrganizationID: key.Owner.OrganizationID, ResourceID: key.ResourceID, Permissions: key.Permission}
	if result.OrganizationID == "" {
		result.OrganizationID = claims.OrganizationID
	}
	if result.ResourceID == "" {
		result.ResourceID = claims.ResourceID
	}
	if result.Owner.OrganizationID == "" {
		result.Owner.OrganizationID = result.OrganizationID
	}
	if key.ExpiresAt > 0 {
		result.ExpiresAt = time.Unix(key.ExpiresAt, 0).UTC()
		if !result.ExpiresAt.After(time.Now()) {
			return APIKey{}, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid or inactive API key", HTTPStatus: 401}
		}
	}
	return result, nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// Principal is who a request is, after middleware authenticated it: a user
// or machine access token (Claims) or an API key (APIKey); exactly one is set.
type Principal struct {
	Claims *Claims
	APIKey *APIKey
}

// OrganizationID is the organization the principal acts in ("" for tokens
// without one).
func (p Principal) OrganizationID() string {
	switch {
	case p.APIKey != nil:
		return p.APIKey.OrganizationID
	case p.Claims != nil:
		return p.Claims.OrganizationID
	}
	return ""
}

// Permissions are the permissions the principal holds.
func (p Principal) Permissions() []string {
	switch {
	case p.APIKey != nil:
		return p.APIKey.Permissions
	case p.Claims != nil:
		return p.Claims.Permissions
	}
	return nil
}

// HasPermission reports whether the principal holds the permission.
func (p Principal) HasPermission(required string) bool {
	switch {
	case p.APIKey != nil:
		return p.APIKey.HasPermission(required)
	case p.Claims != nil:
		return p.Claims.HasPermission(required)
	}
	return false
}

// Owner is the API key's owner, nil when the principal is a token.
func (p Principal) Owner() *APIKeyOwner {
	if p.APIKey == nil {
		return nil
	}
	owner := p.APIKey.Owner
	return &owner
}

// OrganizationBound reports whether the principal acts in organization id:
// an "application" token or an API key of that organization.
func (p Principal) OrganizationBound(id string) bool {
	if id == "" {
		return false
	}
	switch {
	case p.APIKey != nil:
		return p.APIKey.OrganizationID == id
	case p.Claims != nil:
		return p.Claims.Purpose == "application" && p.Claims.OrganizationID == id
	}
	return false
}

// ── Self-service (the signed-in user's own keys) ──

// Me is the signed-in user's self-service view of their API keys in the
// organization of their access token. Make one with Client.Me.
type Me struct {
	client                *Client
	token                 string
	environment, audience string
}

// Me returns the self-service API key calls for the user holding token (an
// "application" access token for audience in environment; impersonated
// tokens may only read).
func (c *Client) Me(token, environment, audience string) Me {
	return Me{client: c, token: token, environment: environment, audience: audience}
}

// UserAPIKey is one of the user's own keys (never its value).
type UserAPIKey struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	ResourceID      string     `json:"resource_id"`
	ResourceName    string     `json:"resource_name,omitempty"`
	Name            string     `json:"name"`
	Permissions     []string   `json:"permissions"`
	ObfuscatedValue string     `json:"obfuscated_value"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Expires         bool       `json:"expires"`
	LastUsedAt      *time.Time `json:"last_used_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
	CreatedAt       time.Time  `json:"created_at"`
	// State is "active", "revoked" or "expired".
	State string `json:"state"`
}

// IssuedUserAPIKey is a new key; Value (ik_key_…) is returned only here.
type IssuedUserAPIKey struct {
	UserAPIKey
	Value string `json:"value"`
}

// NewUserAPIKey asks for a user key in the token's organization. Permissions
// is required, inside what the resource allows users and what the user
// holds. ExpiresIn is a Go duration from 1h to 8760h or "never" (omitted =
// never), within the environment's maximum.
type NewUserAPIKey struct {
	ResourceID  string   `json:"resource_id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	ExpiresIn   string   `json:"expires_in,omitempty"`
}

// UserAPIKeys is one page of the user's keys.
type UserAPIKeys struct {
	Items []UserAPIKey `json:"items"`
	Page  struct {
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	} `json:"page"`
}

// UserAPIKeyOptions says what the user can create: whether user keys are on,
// the longest lifetime in days (nil = unlimited) and the resources of the
// token's application with the permissions that can be given.
type UserAPIKeyOptions struct {
	Enabled    bool `json:"enabled"`
	MaxTTLDays *int `json:"max_ttl_days"`
	Resources  []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Audience    string   `json:"audience"`
		Permissions []string `json:"permissions"`
	} `json:"resources"`
}

// APIKeys lists the user's own keys in the token's organization, newest
// first (limit 0 = the server default).
func (m Me) APIKeys(ctx context.Context, limit, offset int) (UserAPIKeys, error) {
	var out UserAPIKeys
	q := "?" + sessionQuery(m.environment, m.audience)
	if limit > 0 {
		q += "&limit=" + strconv.Itoa(limit)
	}
	if offset > 0 {
		q += "&offset=" + strconv.Itoa(offset)
	}
	err := m.client.requestMethod(ctx, "GET", "/me/api-keys"+q, m.token, nil, &out)
	if out.Items == nil {
		out.Items = []UserAPIKey{}
	}
	return out, err
}

// APIKeyOptions reads what the user may create.
func (m Me) APIKeyOptions(ctx context.Context) (UserAPIKeyOptions, error) {
	var out UserAPIKeyOptions
	err := m.client.requestMethod(ctx, "GET", "/me/api-keys/options?"+sessionQuery(m.environment, m.audience), m.token, nil, &out)
	return out, err
}

// CreateAPIKey issues a user key; the value is returned once. It needs a
// recent sign-in (403 REAUTHENTICATION_REQUIRED otherwise), an enabled
// policy (403 API_KEYS_DISABLED) and room under the per-user limit (422
// API_KEY_LIMIT_REACHED).
func (m Me) CreateAPIKey(ctx context.Context, input NewUserAPIKey) (IssuedUserAPIKey, error) {
	var out IssuedUserAPIKey
	err := m.client.requestMethod(ctx, "POST", "/me/api-keys?"+sessionQuery(m.environment, m.audience), m.token, input, &out)
	return out, err
}

// RevokeAPIKey revokes one of the user's own keys (idempotent); another
// user's key is a 404 error.
func (m Me) RevokeAPIKey(ctx context.Context, id string) error {
	return m.client.requestMethod(ctx, "DELETE", "/me/api-keys/"+url.PathEscape(id)+"?"+sessionQuery(m.environment, m.audience), m.token, nil, nil)
}
