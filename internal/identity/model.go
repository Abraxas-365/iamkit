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

// Phone normalizes a phone number to E.164 ("+" then 7 to 15 digits, no
// leading zero); spaces, dashes, dots and parentheses are dropped.
func Phone(value string) (string, error) {
	invalid := errx.Validation("phone must be in international format, e.g. +14155550100")
	var b strings.Builder
	for i, r := range strings.TrimSpace(value) {
		switch {
		case r == '+' && i == 0, r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
		default:
			return "", invalid
		}
	}
	out := b.String()
	if len(out) < 8 || len(out) > 16 || out[0] != '+' || out[1] == '0' {
		return "", invalid
	}
	return out, nil
}

// UsernameMaxLength bounds usernames.
const UsernameMaxLength = 64

// Username normalizes an optional username: lowercase, 3 to 64 letters,
// digits, ".", "_" or "-", starting with a letter or digit. It never
// contains "@", so a login input is an email exactly when it has one.
// "" means none.
func Username(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	valid := len(value) >= 3 && len(value) <= UsernameMaxLength && isAlnum(value[0])
	for i := 0; valid && i < len(value); i++ {
		c := value[i]
		valid = isAlnum(c) || c == '.' || c == '_' || c == '-'
	}
	if !valid {
		return "", errx.Validation("username must be 3 to 64 letters, digits, dots, dashes or underscores, starting with a letter or digit")
	}
	return value, nil
}

func isAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

// Login splits what a user typed to sign in into a normalized email or
// username (exactly one is set).
func Login(value string) (email, username string, err error) {
	if strings.Contains(value, "@") {
		email, err = Email(value)
		return email, "", err
	}
	username, err = Username(value)
	if err == nil && username == "" {
		err = errx.Validation("email or username is required")
	}
	return "", username, err
}

// AvatarMaxLength bounds an avatar URL.
const AvatarMaxLength = 2048

// AvatarURL normalizes a user's avatar: "" (none) or an https URL with a
// host and no credentials, at most AvatarMaxLength bytes. Hosted pages and
// the console load it as an image, so no other scheme is accepted.
func AvatarURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(value) > AvatarMaxLength {
		return "", errx.Validation("avatar_url must be an https URL of at most 2048 characters")
	}
	return value, nil
}

// FactorKinds are the second-factor kinds, in the order they are offered.
var FactorKinds = []string{"totp", "webauthn", "sms", "email"}

// ValidateFactors checks a list of allowed second-factor kinds (sign-in
// policies, organizations): known, distinct, at least one.
func ValidateFactors(field string, kinds []string) error {
	if len(kinds) == 0 {
		return errx.Validation(field + " needs at least one factor")
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		known := false
		for _, f := range FactorKinds {
			known = known || f == k
		}
		if !known || seen[k] {
			return errx.Validation(field + " must list distinct factors among totp, webauthn, sms, email")
		}
		seen[k] = true
	}
	return nil
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

// ValidateRedirects checks browser redirect targets (OAuth redirect and
// post-logout URIs, application redirects): absolute https URLs, or http
// on a loopback host (localhost, 127.0.0.1, [::1]) for development and
// native apps (RFC 8252 §7.3), without credentials or fragments. They are
// matched exactly, so a wildcard host is refused rather than stored as a
// URI no browser could ever return to.
func ValidateRedirects(values []string) error {
	for _, v := range values {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && !LoopbackHTTP(u)) || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errx.Validation("redirect URIs must be absolute HTTPS URLs (http only for localhost, 127.0.0.1 or [::1]) without credentials or fragments")
		}
		if strings.Contains(u.Host, "*") {
			return errx.Validation("redirect URIs are matched exactly; wildcards are not supported, register each URI")
		}
	}
	return nil
}

// ValidateHTTPS checks URLs IAMKit or a browser must reach over TLS
// whatever the deployment (back-channel logout, SAML ACS): absolute https
// URLs without credentials or fragments.
func ValidateHTTPS(values []string) error {
	for _, v := range values {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errx.Validation("URLs must be absolute HTTPS URLs without credentials or fragments")
		}
		if strings.Contains(u.Host, "*") {
			return errx.Validation("URLs are matched exactly; wildcards are not supported")
		}
	}
	return nil
}

// LoopbackHTTP reports an http URL on localhost, 127.0.0.1 or ::1.
func LoopbackHTTP(u *url.URL) bool {
	if u == nil || u.Scheme != "http" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
