// Package identity defines environment-scoped end-user identity and access.
// Workspace operators are not end users and never inherit business permissions.
package identity

import (
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

type User struct {
	ID            UserID        `json:"id"`
	EnvironmentID EnvironmentID `json:"environment_id"`
	Email         string        `json:"email"`
	Name          string        `json:"name"`
}

type Membership struct {
	EnvironmentID  EnvironmentID  `json:"environment_id"`
	OrganizationID OrganizationID `json:"organization_id"`
	UserID         UserID         `json:"user_id"`
}

// AccessClaims contain only application authority. Management middleware does not
// accept JWTs, regardless of their content, issuer, or signature.
type Access struct {
	EnvironmentID  EnvironmentID  `json:"environment_id"`
	OrganizationID OrganizationID `json:"organization_id,omitempty"`
	ApplicationID  ApplicationID  `json:"application_id"`
	ResourceID     ResourceID     `json:"resource_id"`
	Permissions    []string       `json:"permissions"`
}

func Email(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errx.Validation("invalid email")
	}
	return value, nil
}

// Permissions are resource-local, exact names. Wildcards cannot become
// application authority. The "management" namespace remains reserved for
// operator-only console/API authority and can never appear in a resource's
// permission catalog. "iam" is a legitimate resource prefix — IAMKit exposes
// its own management operations as iam:* scopes on the system IAM resource.
// When prefix is non-empty, every permission must start with "{prefix}:".
func ValidatePermissions(values []string, prefix string) error {
	if len(values) > 100 {
		return errx.Validation("too many permissions")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "* \t\r\n") || v == "management" || strings.HasPrefix(v, "management:") || seen[v] {
			return errx.Validation("invalid or duplicate application permission")
		}
		if prefix != "" && !strings.HasPrefix(v, prefix+":") {
			return errx.Validation("permission must start with \"" + prefix + ":\"")
		}
		seen[v] = true
	}
	return nil
}

// ValidatePrefix checks a resource scope prefix: lowercase letters, digits,
// hyphens and underscores, starting with a letter, 1–32 chars. "iam" is
// reserved for the system-managed IAM resource created per environment;
// operators cannot create additional resources with that prefix.
func ValidatePrefix(p string) error {
	if p == "" || len(p) > 32 {
		return errx.Validation("prefix must be 1–32 characters")
	}
	for i, c := range p {
		if i == 0 && !(c >= 'a' && c <= 'z') {
			return errx.Validation("prefix must start with a lowercase letter")
		}
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return errx.Validation("prefix may only contain lowercase letters, digits, hyphens, and underscores")
		}
	}
	if p == "management" {
		return errx.Validation("prefix \"" + p + "\" is reserved")
	}
	return nil
}

func Subset(requested, catalog []string) bool {
	allowed := map[string]bool{}
	for _, v := range catalog {
		allowed[v] = true
	}
	for _, v := range requested {
		if !allowed[v] {
			return false
		}
	}
	return true
}

// DefaultTTL is the credential expiry used when no custom TTL is specified.
const DefaultTTL = 24 * time.Hour

// MinTTL and MaxTTL are the bounds for configurable credential expiry.
const (
	MinTTL   = 1 * time.Hour
	MaxTTL   = 365 * 24 * time.Hour       // 1 year
	NoExpiry = 100 * 365 * 24 * time.Hour // ~100 years, effectively never
)

// ParseTTL parses an optional TTL string (Go duration like "24h", "720h",
// "8760h") and returns a time.Duration. If raw is nil or empty, DefaultTTL is
// returned. The special value "never" maps to NoExpiry (100 years).
// Otherwise the duration is clamped to [MinTTL, MaxTTL].
func ParseTTL(raw *string) (time.Duration, error) {
	if raw == nil || *raw == "" {
		return DefaultTTL, nil
	}
	if *raw == "never" {
		return NoExpiry, nil
	}
	d, err := time.ParseDuration(*raw)
	if err != nil {
		return 0, errx.Validation("invalid expires_in: must be a Go duration (e.g. \"24h\", \"720h\") or \"never\"")
	}
	if d < MinTTL {
		return 0, errx.Validation("expires_in must be at least 1h")
	}
	if d > MaxTTL {
		return 0, errx.Validation("expires_in must be at most 8760h (1 year), or \"never\"")
	}
	return d, nil
}

func ValidateRedirects(values []string) error {
	for _, v := range values {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errx.Validation("redirect URIs must be absolute HTTPS URLs without credentials or fragments")
		}
	}
	return nil
}
