package oauth

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ProtectedResource is an OAuth resource server (RFC 9728) such as a remote
// MCP server: a resource of an application whose audience is the server's
// canonical URL. Clients of the application reach it with the RFC 8707
// resource parameter; the tokens they get carry aud = URI and, as scopes,
// the resource's permissions the user consented to and still holds.
type ProtectedResource struct {
	ID          identity.ProtectedResourceID `json:"id"`
	Environment identity.EnvironmentID       `json:"environment_id"`
	Application identity.ApplicationID       `json:"application_id"`
	Resource    identity.ResourceID          `json:"resource_id"`
	// URI is the canonical resource indicator (= the resource's audience),
	// unique in the deployment.
	URI  string `json:"uri"`
	Name string `json:"name"`
	// DefaultScopes are granted when a client asks for none, and published
	// as the server's scopes_supported.
	DefaultScopes []string `json:"default_scopes"`
	// IdleTTLSeconds bounds the inactivity between two refreshes;
	// MaxTTLSeconds the whole authorization (its session).
	IdleTTLSeconds int64 `json:"idle_ttl_seconds"`
	MaxTTLSeconds  int64 `json:"max_ttl_seconds"`
	Active         bool  `json:"active"`
	// AllowClientMetadata lets clients identified by a metadata document
	// (client_id = https URL) ask for this server; off: registered clients
	// only.
	AllowClientMetadata bool `json:"allow_client_metadata"`
	// AllowDynamicRegistration lets clients registered at /oauth/register
	// (RFC 7591) ask for this server, admitted like document clients but
	// never by an allowlist entry (off by default; the environment's
	// dynamic_client_registration feature must be on too).
	AllowDynamicRegistration bool `json:"allow_dynamic_registration"`
	// ClientAdmission is ClientAdmissionAllowlist (a document client waits
	// for IT unless an allowlist entry admits it) or ClientAdmissionOpen.
	ClientAdmission string    `json:"client_admission"`
	CreatedAt       time.Time `json:"created_at"`
}

// ProtectedResourceImpact is what deactivating or deleting a protected
// resource would end: the live OAuth sessions of its resource (resource
// flow and plain OpenID Connect grants of its clients alike).
type ProtectedResourceImpact struct {
	ActiveSessions int `json:"active_sessions"`
	// ExternalClients are the clients identified by a metadata document
	// the server knows; deleting the server forgets them and their grants.
	ExternalClients int `json:"external_clients"`
}

// ProtectedResourceCreate registers a resource of an application as a
// protected resource. The URI is the resource's audience, which must
// already be its canonical URL (CanonicalResource).
type ProtectedResourceCreate struct {
	Application    identity.ApplicationID `json:"application_id"`
	Resource       identity.ResourceID    `json:"resource_id"`
	Name           string                 `json:"name"`
	DefaultScopes  []string               `json:"default_scopes"`
	IdleTTLSeconds int64                  `json:"idle_ttl_seconds"`
	MaxTTLSeconds  int64                  `json:"max_ttl_seconds"`
}

// WithDefaults fills the TTLs left out.
func (c ProtectedResourceCreate) WithDefaults() ProtectedResourceCreate {
	if c.IdleTTLSeconds == 0 {
		c.IdleTTLSeconds = int64(config.ProtectedResourceIdleTTL.Seconds())
	}
	if c.MaxTTLSeconds == 0 {
		c.MaxTTLSeconds = int64(config.ProtectedResourceMaxTTL.Seconds())
	}
	if c.DefaultScopes == nil {
		c.DefaultScopes = []string{}
	}
	return c
}

func (c ProtectedResourceCreate) Validate() error {
	if c.Application.IsZero() || c.Resource.IsZero() {
		return errx.Validation("application_id and resource_id are required")
	}
	if err := validateProtectedName(c.Name); err != nil {
		return err
	}
	if err := identity.ValidatePermissions(c.DefaultScopes, ""); err != nil {
		return errx.Validation("default_scopes must be distinct permissions of the resource")
	}
	return validateTTLs(c.IdleTTLSeconds, c.MaxTTLSeconds)
}

// ProtectedResourceUpdate changes a protected resource; nil fields keep.
type ProtectedResourceUpdate struct {
	Name           *string   `json:"name"`
	DefaultScopes  *[]string `json:"default_scopes"`
	IdleTTLSeconds *int64    `json:"idle_ttl_seconds"`
	MaxTTLSeconds  *int64    `json:"max_ttl_seconds"`
	Active         *bool     `json:"active"`
	// AllowClientMetadata and ClientAdmission set the server's policy for
	// clients identified by a metadata document; AllowDynamicRegistration
	// for dynamically registered ones.
	AllowClientMetadata      *bool   `json:"allow_client_metadata"`
	AllowDynamicRegistration *bool   `json:"allow_dynamic_registration"`
	ClientAdmission          *string `json:"client_admission"`
}

func (u ProtectedResourceUpdate) Validate() error {
	if u.ClientAdmission != nil && *u.ClientAdmission != ClientAdmissionAllowlist && *u.ClientAdmission != ClientAdmissionOpen {
		return errx.Validation("client_admission must be allowlist or open")
	}
	if u.Name != nil {
		if err := validateProtectedName(*u.Name); err != nil {
			return err
		}
	}
	if u.DefaultScopes != nil {
		if err := identity.ValidatePermissions(*u.DefaultScopes, ""); err != nil {
			return errx.Validation("default_scopes must be distinct permissions of the resource")
		}
	}
	if u.IdleTTLSeconds != nil && *u.IdleTTLSeconds <= 0 || u.MaxTTLSeconds != nil && *u.MaxTTLSeconds <= 0 {
		return errx.Validation("idle_ttl_seconds and max_ttl_seconds must be positive")
	}
	return nil
}

// Apply returns current with the update's fields.
func (u ProtectedResourceUpdate) Apply(current ProtectedResource) ProtectedResource {
	if u.Name != nil {
		current.Name = *u.Name
	}
	if u.DefaultScopes != nil {
		current.DefaultScopes = *u.DefaultScopes
	}
	if u.IdleTTLSeconds != nil {
		current.IdleTTLSeconds = *u.IdleTTLSeconds
	}
	if u.MaxTTLSeconds != nil {
		current.MaxTTLSeconds = *u.MaxTTLSeconds
	}
	if u.Active != nil {
		current.Active = *u.Active
	}
	if u.AllowClientMetadata != nil {
		current.AllowClientMetadata = *u.AllowClientMetadata
	}
	if u.AllowDynamicRegistration != nil {
		current.AllowDynamicRegistration = *u.AllowDynamicRegistration
	}
	if u.ClientAdmission != nil {
		current.ClientAdmission = *u.ClientAdmission
	}
	return current
}

// Validate checks a protected resource after an update was applied.
func (r ProtectedResource) Validate() error {
	if err := validateProtectedName(r.Name); err != nil {
		return err
	}
	if r.ClientAdmission != ClientAdmissionAllowlist && r.ClientAdmission != ClientAdmissionOpen {
		return errx.Validation("client_admission must be allowlist or open")
	}
	return validateTTLs(r.IdleTTLSeconds, r.MaxTTLSeconds)
}

// ProtectedResourcePolicy are an environment's ceilings for the TTLs of its
// protected resources. A resource above a ceiling (saved before it was
// lowered) is held to the ceiling when tokens are issued.
type ProtectedResourcePolicy struct {
	MaxIdleTTLSeconds     int64 `json:"max_idle_ttl_seconds"`
	MaxLifetimeTTLSeconds int64 `json:"max_lifetime_ttl_seconds"`
}

// DefaultProtectedResourcePolicy applies while an environment saved none.
func DefaultProtectedResourcePolicy() ProtectedResourcePolicy {
	return ProtectedResourcePolicy{MaxIdleTTLSeconds: int64(config.ProtectedResourceIdleCeiling.Seconds()), MaxLifetimeTTLSeconds: int64(config.ProtectedResourceLifetimeCeiling.Seconds())}
}

func (p ProtectedResourcePolicy) Validate() error {
	return validateTTLs(p.MaxIdleTTLSeconds, p.MaxLifetimeTTLSeconds)
}

// Admits refuses TTLs above the policy's ceilings.
func (p ProtectedResourcePolicy) Admits(idle, lifetime int64) error {
	if idle > p.MaxIdleTTLSeconds || lifetime > p.MaxLifetimeTTLSeconds {
		return errx.Validation("idle_ttl_seconds and max_ttl_seconds cannot exceed the environment's protected resource policy")
	}
	return nil
}

// ProtectedTarget is the protected resource behind a client's resource, as
// the authorization and token endpoints need it.
type ProtectedTarget struct {
	ID  identity.ProtectedResourceID
	URI string
	// Scopes is the resource's permission catalog: every scope a client may
	// ask for at this server.
	Scopes        []string
	DefaultScopes []string
	// Idle and Lifetime are the TTLs already held to the environment's
	// policy.
	Idle     time.Duration
	Lifetime time.Duration
}

// NewProtectedTarget holds a resource's TTLs to the policy (nil policy:
// the default).
func NewProtectedTarget(r ProtectedResource, scopes []string, policy *ProtectedResourcePolicy) *ProtectedTarget {
	p := DefaultProtectedResourcePolicy()
	if policy != nil {
		p = *policy
	}
	return &ProtectedTarget{ID: r.ID, URI: r.URI, Scopes: scopes, DefaultScopes: r.DefaultScopes,
		Idle:     time.Duration(min(r.IdleTTLSeconds, p.MaxIdleTTLSeconds)) * time.Second,
		Lifetime: time.Duration(min(r.MaxTTLSeconds, p.MaxLifetimeTTLSeconds)) * time.Second}
}

// RefreshExpiry is when a refresh token issued now expires: after the
// inactivity window, never past the session's deadline.
func (t *ProtectedTarget) RefreshExpiry(now, deadline time.Time) time.Time {
	if at := now.Add(t.Idle); at.Before(deadline) {
		return at
	}
	return deadline
}

// Deadline is a grant's end at a refresh: the stored deadline, held to the
// session's start plus the resource's current lifetime (already held to the
// environment's current ceiling), so lowering either also shortens grants
// already issued. A zero start keeps the stored deadline.
func (t *ProtectedTarget) Deadline(started, stored time.Time) time.Time {
	if started.IsZero() {
		return stored
	}
	if at := started.Add(t.Lifetime); at.Before(stored) {
		return at
	}
	return stored
}

// Audited actions of protected resources.
const (
	ActionProtectedResourceCreate = "protected_resource.create"
	ActionProtectedResourceUpdate = "protected_resource.update"
	ActionProtectedResourceDelete = "protected_resource.delete"
	ActionProtectedResourcePolicy = "protected_resource_policy.update"
)

// ProtectedResourceSource is what registering a resource needs to know
// about it.
type ProtectedResourceSource struct {
	Audience    string
	Permissions []string
	// System is the IAM resource, which is never a protected resource.
	System bool
}

// CheckSource refuses a resource that cannot be protected and returns the
// URI: the resource's audience, which must be canonical.
func (s ProtectedResourceSource) CheckSource() (string, error) {
	if s.System {
		return "", errx.Validation("the IAM resource cannot be a protected resource")
	}
	uri, err := CanonicalResource(s.Audience)
	if err != nil {
		return "", errx.Validation("the resource's audience must be the server's URL: " + err.Error())
	}
	if uri != s.Audience {
		return "", errx.Validation("the resource's audience must be its canonical URL " + uri)
	}
	return uri, nil
}

// CheckScopes refuses default scopes outside the resource's catalog.
func (s ProtectedResourceSource) CheckScopes(scopes []string) error {
	for _, scope := range scopes {
		if !slices.Contains(s.Permissions, scope) {
			return errx.Validation("default scope " + scope + " is not a permission of the resource")
		}
	}
	return nil
}

func validateProtectedName(name string) error {
	if n := len(strings.TrimSpace(name)); n == 0 || len(name) > 200 {
		return errx.Validation("name is required (at most 200 characters)")
	}
	return nil
}

func validateTTLs(idle, lifetime int64) error {
	if idle <= 0 || lifetime <= 0 || idle > lifetime {
		return errx.Validation("TTLs must be positive and the idle TTL at most the lifetime")
	}
	return nil
}
