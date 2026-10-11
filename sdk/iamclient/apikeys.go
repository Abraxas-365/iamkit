package iamclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// API key owner types and states (APIKeyOwner.Type, APIKeyFilter).
const (
	APIKeyOwnerUser         = "user"
	APIKeyOwnerOrganization = "organization"
	APIKeyOwnerMachine      = "machine"

	APIKeyActive  = "active"
	APIKeyRevoked = "revoked"
	APIKeyExpired = "expired"
)

// APIKeyOwner says whose key it is: a person ("user", UserID set), an
// organization ("organization") or a machine user ("machine", UserID set).
type APIKeyOwner struct {
	Type   string `json:"type"`
	UserID string `json:"user_id,omitempty"`
}

// APIKeyCreator is who made the key (kind: operator, user, machine,
// service_account, setup_link or system).
type APIKeyCreator struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

// APIKey is an API key without its value. ObfuscatedValue is
// "ik_key_…" plus the last four characters.
type APIKey struct {
	ID            string      `json:"id"`
	EnvironmentID string      `json:"environment_id"`
	Owner         APIKeyOwner `json:"owner"`
	// OrganizationID is the organization the key works in.
	OrganizationID string `json:"organization_id"`
	// ApplicationID is set on machine keys only.
	ApplicationID string `json:"application_id,omitempty"`
	ResourceID    string `json:"resource_id"`
	Name          string `json:"name"`
	// Permissions are the key's own list; nil on a machine key means
	// everything its machine user holds. What a use is allowed is always
	// narrowed further (see ValidateAPIKey).
	Permissions     []string  `json:"permissions"`
	ObfuscatedValue string    `json:"obfuscated_value"`
	ExpiresAt       time.Time `json:"expires_at"`
	// Expires is false for a key that never expires.
	Expires    bool          `json:"expires"`
	LastUsedAt *time.Time    `json:"last_used_at"`
	RevokedAt  *time.Time    `json:"revoked_at"`
	CreatedBy  APIKeyCreator `json:"created_by"`
	CreatedAt  time.Time     `json:"created_at"`
	// State is "active", "revoked" or "expired".
	State string `json:"state"`
	// Names are filled when keys are listed.
	UserName         string `json:"user_name,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	ApplicationName  string `json:"application_name,omitempty"`
	ResourceName     string `json:"resource_name,omitempty"`
}

// IssuedAPIKey is a new key; Value (ik_key_…) is returned only here.
type IssuedAPIKey struct {
	APIKey
	Value string `json:"value"`
}

// NewAPIKey asks for a key. For an organization key (CreateAPIKey) Permissions
// is required and must lie inside the resource's allowlist; for a machine key
// (CreateMachineAPIKey) ApplicationID is required and Permissions optional
// (omitted = everything the machine user holds). ExpiresIn is a Go duration
// from 1h to 8760h or "never"; omitted means never.
type NewAPIKey struct {
	OrganizationID string   `json:"organization_id"`
	ApplicationID  string   `json:"application_id,omitempty"`
	ResourceID     string   `json:"resource_id"`
	Name           string   `json:"name"`
	Permissions    []string `json:"permissions,omitempty"`
	ExpiresIn      string   `json:"expires_in,omitempty"`
}

// APIKeyFilter narrows APIKeys; empty fields do not filter.
type APIKeyFilter struct {
	// OwnerType is "user", "organization" or "machine".
	OwnerType      string
	OrganizationID string
	UserID         string
	ResourceID     string
	// State is "active", "revoked" or "expired".
	State string
	// Search matches the key name.
	Search string
}

// Query encodes the filter as query parameters.
func (f APIKeyFilter) Query() url.Values {
	q := url.Values{}
	for key, value := range map[string]string{
		"owner_type":      f.OwnerType,
		"organization_id": f.OrganizationID,
		"user_id":         f.UserID,
		"resource_id":     f.ResourceID,
		"state":           f.State,
		"search":          f.Search,
	} {
		if value != "" {
			q.Set(key, value)
		}
	}
	return q
}

// Page selects one page of a list; zero fields use the server's defaults.
type Page struct {
	Limit  int
	Offset int
}

// Query adds the page to q (which may be nil) and returns it.
func (p Page) Query(q url.Values) url.Values {
	if q == nil {
		q = url.Values{}
	}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}
	return q
}

// Paging is the page information of a list answer.
type Paging struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// APIKeyList is one page of API keys.
type APIKeyList struct {
	Items []APIKey `json:"items"`
	Page  Paging   `json:"page"`
}

// APIKeyPolicy is the environment's API key policy.
type APIKeyPolicy struct {
	// UserKeys and OrganizationKeys switch each key type on.
	UserKeys         bool `json:"user_keys"`
	OrganizationKeys bool `json:"organization_keys"`
	// MaxTTLDays caps the lifetime of new user and organization keys
	// (1–365); nil = no cap (and "never" allowed).
	MaxTTLDays *int `json:"max_ttl_days"`
	// MaxPerUser (1–100) and MaxPerOrganization (1–500) bound the live keys.
	MaxPerUser         int       `json:"max_per_user"`
	MaxPerOrganization int       `json:"max_per_organization"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// APIKeyPolicyInput replaces the policy (SaveAPIKeyPolicy).
type APIKeyPolicyInput struct {
	UserKeys           bool `json:"user_keys"`
	OrganizationKeys   bool `json:"organization_keys"`
	MaxTTLDays         *int `json:"max_ttl_days"`
	MaxPerUser         int  `json:"max_per_user"`
	MaxPerOrganization int  `json:"max_per_organization"`
}

// APIKeyPermissions is a resource's allowlist: the permissions API keys of
// each owner type may carry (subsets of the resource's permissions; empty =
// no keys of that type). The IAM resource must keep both empty.
type APIKeyPermissions struct {
	User         []string `json:"user"`
	Organization []string `json:"organization"`
}

// APIKeyOptionsResource is a resource a key can be created for.
type APIKeyOptionsResource struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}

// APIKeyOptions says what the caller can create: whether the key type is
// enabled, the longest lifetime in days (nil = unlimited) and, per
// resource, the permissions it can give.
type APIKeyOptions struct {
	Enabled    bool                    `json:"enabled"`
	MaxTTLDays *int                    `json:"max_ttl_days"`
	Resources  []APIKeyOptionsResource `json:"resources"`
}

// APIKeys reads one page of the environment's keys (all owner types);
// requires iam:api-keys:read.
func (e Environment) APIKeys(ctx context.Context, filter APIKeyFilter, page Page) (APIKeyList, error) {
	var out APIKeyList
	if err := e.client.do(ctx, "GET", e.path("api-keys"), page.Query(filter.Query()), nil, &out); err != nil {
		return APIKeyList{}, err
	}
	if out.Items == nil {
		out.Items = []APIKey{}
	}
	return out, nil
}

// APIKey reads one key; requires iam:api-keys:read.
func (e Environment) APIKey(ctx context.Context, id string) (APIKey, error) {
	var out APIKey
	err := e.operation(ctx, "GET", []string{"api-keys", id}, nil, &out)
	return out, err
}

// CreateAPIKey issues an organization key (an operator creates no other
// kind here; no granter check applies). The value is returned once.
// Requires iam:api-keys:write.
func (e Environment) CreateAPIKey(ctx context.Context, input NewAPIKey) (IssuedAPIKey, error) {
	var out IssuedAPIKey
	err := e.operation(ctx, "POST", []string{"api-keys"}, input, &out)
	return out, err
}

// RevokeAPIKey revokes any key (idempotent); requires iam:api-keys:write.
func (e Environment) RevokeAPIKey(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"api-keys", id}, nil, nil)
}

// APIKeyPolicy reads the environment's policy; requires iam:api-keys:read.
func (e Environment) APIKeyPolicy(ctx context.Context) (APIKeyPolicy, error) {
	var out APIKeyPolicy
	err := e.operation(ctx, "GET", []string{"api-key-policy"}, nil, &out)
	return out, err
}

// SaveAPIKeyPolicy replaces the policy and returns it; requires
// iam:api-keys:write.
func (e Environment) SaveAPIKeyPolicy(ctx context.Context, input APIKeyPolicyInput) (APIKeyPolicy, error) {
	var out APIKeyPolicy
	err := e.operation(ctx, "PUT", []string{"api-key-policy"}, input, &out)
	return out, err
}

// SetResourceAPIKeyPermissions replaces a resource's API key allowlist;
// requires iam:resources:write. Read it back with Resource.
func (e Environment) SetResourceAPIKeyPermissions(ctx context.Context, resource string, input APIKeyPermissions) error {
	if input.User == nil {
		input.User = []string{}
	}
	if input.Organization == nil {
		input.Organization = []string{}
	}
	return e.operation(ctx, "PUT", []string{"resources", resource, "api-key-permissions"}, input, nil)
}

// UserAPIKeys lists every key of a user (any kind: a machine user's or a
// person's); requires iam:users:read.
func (e Environment) UserAPIKeys(ctx context.Context, user string) ([]APIKey, error) {
	return listOp[APIKey](e, ctx, []string{"users", user, "api-keys"})
}

// CreateMachineAPIKey issues a key for a machine user: it acts as the user in
// one organization for one application resource and is the only kind that
// reaches /api/v1 and the token exchange. Requires iam:users:write.
func (e Environment) CreateMachineAPIKey(ctx context.Context, user string, input NewAPIKey) (IssuedAPIKey, error) {
	var out IssuedAPIKey
	err := e.operation(ctx, "POST", []string{"users", user, "api-keys"}, input, &out)
	return out, err
}

// RevokeUserAPIKey revokes a key of a user and the sessions exchanged from
// it; requires iam:users:write.
func (e Environment) RevokeUserAPIKey(ctx context.Context, user, id string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "api-keys", id}, nil, nil)
}
