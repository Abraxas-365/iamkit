// Package apikey is self-service API keys: credentials the environment's
// applications validate (introspection, SDK ValidateAPIKey) to let their
// customers' scripts and integrations call them. Three owners share one
// credential (api_keys, value ik_key_…, shown once):
//
//   - user: a person's key in one organization, capped by what the person
//     may do there now;
//   - organization: the organization's own key, capped by what the
//     organization may reach; it outlives its creator;
//   - machine: a machine user's key (operator-made), the only kind IAMKit's
//     own API accepts and the only one exchangeable for a JWT.
//
// User and organization keys carry an explicit permission list inside the
// resource's allowlist for the owner kind (authorization.Resource
// APIKeyUserPermissions / APIKeyOrganizationPermissions, never on the IAM
// resource) and need the environment's Policy to allow the kind.
package apikey

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Owner kinds (api_keys.owner_kind; the API calls it owner.type).
type OwnerKind string

const (
	OwnerUser         OwnerKind = "user"
	OwnerOrganization OwnerKind = "organization"
	OwnerMachine      OwnerKind = "machine"
)

// Valid reports a known owner kind.
func (k OwnerKind) Valid() bool {
	return k == OwnerUser || k == OwnerOrganization || k == OwnerMachine
}

// Audit actions (event.Classify maps them to api_key.created, …).
const (
	ActionCreate       = "api_key.create"
	ActionRevoke       = "api_key.revoke"
	ActionPolicyUpdate = "api_key_policy.update"
)

// Limits of one key.
const (
	MaxName        = 200
	MaxPermissions = 100
)

// Owner names who a key acts for. User is zero for organization keys.
type Owner struct {
	Type OwnerKind       `json:"type"`
	User identity.UserID `json:"user_id,omitzero"`
}

// Creator is who created a key (api_keys.created_by_*): kind operator,
// user, machine, service_account, setup_link or system, and its id.
type Creator struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

// APIKey is a stored key; the value is never returned after creation.
type APIKey struct {
	ID           identity.APIKeyID       `json:"id"`
	Environment  identity.EnvironmentID  `json:"environment_id"`
	Owner        Owner                   `json:"owner"`
	Organization identity.OrganizationID `json:"organization_id"`
	// Application is set for machine keys only (their token exchange
	// opens a session of the application).
	Application *identity.ApplicationID `json:"application_id,omitempty"`
	Resource    identity.ResourceID     `json:"resource_id"`
	Name        string                  `json:"name"`
	// Permissions is the key's own list; nil on a machine key means
	// everything the machine user holds.
	Permissions []string `json:"permissions"`
	// ObfuscatedValue is ik_key_…<last 4 characters>.
	ObfuscatedValue string `json:"obfuscated_value"`
	// ExpiresAt is identity.NoExpiry ahead for keys that never expire;
	// Expires is false for them.
	ExpiresAt  time.Time  `json:"expires_at"`
	Expires    bool       `json:"expires"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedBy  Creator    `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	// State is active, revoked or expired (derived).
	State string `json:"state"`
	// Names, filled when keys are read.
	UserName         string `json:"user_name,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	ApplicationName  string `json:"application_name,omitempty"`
	ResourceName     string `json:"resource_name,omitempty"`
}

// Issued is a new key with its value, returned once.
type Issued struct {
	APIKey
	Value string `json:"value"`
}

// Key states (APIKey.State, Filter.State).
const (
	StateActive  = "active"
	StateRevoked = "revoked"
	StateExpired = "expired"
)

// Options is what a caller may create (portal and self-service create
// dialogs): whether the kind is enabled, the maximum lifetime, and per
// resource the permissions a new key may carry — the allowlist for the
// kind ∩ the owner's reach ∩ (organization keys) the creating admin's own.
type Options struct {
	Enabled    bool             `json:"enabled"`
	MaxTTLDays *int             `json:"max_ttl_days"`
	Resources  []OptionResource `json:"resources"`
}

type OptionResource struct {
	ID          identity.ResourceID `json:"id"`
	Name        string              `json:"name"`
	Audience    string              `json:"audience"`
	Permissions []string            `json:"permissions"`
}

// NewAPIKey creates a key. Owner is set by the caller's surface (the
// service never trusts a body for it): operators may create any kind, an
// organization admin organization keys, a user only their own user key.
type NewAPIKey struct {
	Owner        Owner                   `json:"-"`
	Organization identity.OrganizationID `json:"organization_id"`
	// Application: machine keys only (required there).
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Name        string                 `json:"name"`
	// Permissions: required and non-empty for user and organization keys;
	// optional for machine keys (omitted = everything the user holds).
	Permissions []string `json:"permissions"`
	// ExpiresIn is a Go duration from 1h to 8760h or "never"; omitted =
	// never (identity.ParseTTL otherwise).
	ExpiresIn *string `json:"expires_in"`
}

// TTL is the key's lifetime: identity.NoExpiry when ExpiresIn is omitted.
func (n NewAPIKey) TTL() (time.Duration, error) {
	if n.ExpiresIn == nil || *n.ExpiresIn == "" {
		return identity.NoExpiry, nil
	}
	return identity.ParseTTL(n.ExpiresIn)
}

// Validate checks the request alone; owner, allowlist, reach and policy
// checks are the service's.
func (n NewAPIKey) Validate() error {
	if !n.Owner.Type.Valid() {
		return errx.Validation("owner type must be user, organization or machine")
	}
	if (n.Owner.Type == OwnerOrganization) != n.Owner.User.IsZero() {
		return errx.Validation("an organization key has no user; user and machine keys need one")
	}
	name := strings.TrimSpace(n.Name)
	if name == "" {
		return errx.Validation("name is required")
	}
	if len(name) > MaxName {
		return errx.Validation("name must be at most 200 characters")
	}
	if n.Organization.IsZero() {
		return errx.Validation("organization_id is required")
	}
	if n.Resource.IsZero() {
		return errx.Validation("resource_id is required")
	}
	if n.Owner.Type == OwnerMachine && n.Application.IsZero() {
		return errx.Validation("application_id is required")
	}
	if n.Owner.Type != OwnerMachine && !n.Application.IsZero() {
		return errx.Validation("application_id is only for machine user keys")
	}
	if n.Owner.Type != OwnerMachine && len(n.Permissions) == 0 {
		return errx.Validation("permissions are required")
	}
	if len(n.Permissions) > MaxPermissions {
		return errx.Validation("at most 100 permissions")
	}
	for _, p := range n.Permissions {
		if strings.TrimSpace(p) == "" {
			return errx.Validation("permissions must not be empty")
		}
	}
	_, err := n.TTL()
	return err
}

// Target is a key's audit target: organizations/<org>/api-keys/<id> for user
// and organization keys (so they reach the organization's audit views),
// the bare id for machine keys.
func Target(kind OwnerKind, organization identity.OrganizationID, key identity.APIKeyID) string {
	if kind == OwnerMachine || organization.IsZero() {
		return key.String()
	}
	return "/organizations/" + organization.String() + "/api-keys/" + key.String()
}

// Filter narrows a listing. Zero fields match everything; State is
// "active" (unrevoked, unexpired), "revoked", "expired" or "".
type Filter struct {
	OwnerType    OwnerKind
	Organization identity.OrganizationID
	User         identity.UserID
	Resource     identity.ResourceID
	State        string
}

// Scope is what a caller reaches: the whole environment (operators), one
// organization (its admins: organization keys and its members' user keys,
// never machine keys) or one user in one organization (self-service: that
// user's own user keys).
type Scope struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	User         identity.UserID
	kind         scopeKind
}

type scopeKind int

const (
	scopeEnvironment scopeKind = iota
	scopeOrganization
	scopeSelf
)

func EnvironmentScope(environment identity.EnvironmentID) Scope {
	return Scope{Environment: environment}
}

func OrganizationScope(environment identity.EnvironmentID, organization identity.OrganizationID) Scope {
	return Scope{Environment: environment, Organization: organization, kind: scopeOrganization}
}

func SelfScope(environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) Scope {
	return Scope{Environment: environment, Organization: organization, User: user, kind: scopeSelf}
}

// IsOrganization reports an organization admin's scope.
func (s Scope) IsOrganization() bool { return s.kind == scopeOrganization }

// IsSelf reports a user's own scope.
func (s Scope) IsSelf() bool { return s.kind == scopeSelf }

// Narrow applies the scope to a filter: an organization scope pins the
// organization and leaves out machine keys; a self scope pins organization,
// user and owner type user. Repositories filter with the result in SQL.
func (s Scope) Narrow(f Filter) Filter {
	switch s.kind {
	case scopeOrganization:
		f.Organization = s.Organization
	case scopeSelf:
		f.Organization, f.User, f.OwnerType = s.Organization, s.User, OwnerUser
	}
	return f
}

// Mutation is an audited key change made within a scope.
type Mutation struct {
	Scope
	Actor string
	// Granter is the creating organization admin (organization scope): an
	// organization key may not carry a permission the admin does not hold
	// on the resource themselves (api_key_reach of the admin; like
	// orgadmin.Role.Assignable). Zero skips the check (operators); an
	// organization scope without a user (setup link) cannot create keys.
	Granter identity.UserID
	// Application is the caller's application (self scope): the resource
	// must be linked to it.
	Application identity.ApplicationID
	// AuthTime is the caller's auth_time (self scope): creating a key
	// needs a recent sign-in (config.MFAFreshAuth).
	AuthTime int64
	Action   string
	Target   string
}

// Policy is the environment's API key policy (api_key_policies; defaults
// when no row exists: both kinds off, no maximum lifetime,
// config.APIKeyMaxPerUserDefault / APIKeyMaxPerOrganizationDefault).
type Policy struct {
	UserKeys         bool `json:"user_keys"`
	OrganizationKeys bool `json:"organization_keys"`
	// MaxTTLDays caps a key's lifetime (1–365); nil = no maximum, so keys
	// may never expire.
	MaxTTLDays         *int      `json:"max_ttl_days"`
	MaxPerUser         int       `json:"max_per_user"`
	MaxPerOrganization int       `json:"max_per_organization"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Allows reports whether the policy lets keys of kind be created and used
// (machine keys always).
func (p Policy) Allows(kind OwnerKind) bool {
	switch kind {
	case OwnerUser:
		return p.UserKeys
	case OwnerOrganization:
		return p.OrganizationKeys
	}
	return true
}

// Validate checks the bounds api_key_policies enforces.
func (p Policy) Validate() error {
	if p.MaxTTLDays != nil && (*p.MaxTTLDays < 1 || *p.MaxTTLDays > 365) {
		return errx.Validation("max_ttl_days must be between 1 and 365, or null")
	}
	if p.MaxPerUser < 1 || p.MaxPerUser > 100 {
		return errx.Validation("max_per_user must be between 1 and 100")
	}
	if p.MaxPerOrganization < 1 || p.MaxPerOrganization > 500 {
		return errx.Validation("max_per_organization must be between 1 and 500")
	}
	return nil
}

// CheckTTL refuses a lifetime the policy does not allow (user and
// organization keys).
func (p Policy) CheckTTL(ttl time.Duration) error {
	if p.MaxTTLDays == nil {
		return nil
	}
	if ttl > time.Duration(*p.MaxTTLDays)*24*time.Hour {
		return errx.Validation("expires_in exceeds the environment's maximum API key lifetime")
	}
	return nil
}

// FreshAuth refuses a session that signed in longer ago than
// config.MFAFreshAuth (authTime is unix seconds, 0 when unknown): creating a
// key is a sensitive change, so a stolen long-lived session cannot mint one.
func FreshAuth(authTime int64, now time.Time) error {
	if authTime != 0 && now.Sub(time.Unix(authTime, 0)) <= config.MFAFreshAuth {
		return nil
	}
	e := errx.Forbidden("sign in again to create an API key")
	e.Code = "REAUTHENTICATION_REQUIRED"
	return e
}

// ErrLimitReached is the refusal of a key past the policy's live-key limits
// (422 API_KEY_LIMIT_REACHED).
func ErrLimitReached(message string) error {
	e := errx.Business(message)
	e.Code = "API_KEY_LIMIT_REACHED"
	return e
}
