// Package identity defines environment-scoped end-user identity and access.
// Workspace operators are not end users and never inherit business permissions.
package identity

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"net/mail"
	"net/url"
	"strings"
)

type User struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
}

type Membership struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           string `json:"role"`
}

// AccessClaims contain only application authority. Management middleware does not
// accept JWTs, regardless of their content, issuer, or signature.
type Access struct {
	EnvironmentID  string   `json:"environment_id"`
	OrganizationID string   `json:"organization_id,omitempty"`
	ApplicationID  string   `json:"application_id"`
	ResourceID     string   `json:"resource_id"`
	Permissions    []string `json:"permissions"`
}

func Email(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errx.Validation("invalid email")
	}
	return value, nil
}

// Permissions are resource-local, exact names. Wildcards and management
// namespaces cannot become application authority.
func ValidatePermissions(values []string) error {
	if len(values) > 100 {
		return errx.Validation("too many permissions")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "* \t\r\n") || v == "iam" || strings.HasPrefix(v, "iam:") || v == "management" || strings.HasPrefix(v, "management:") || seen[v] {
			return errx.Validation("invalid or duplicate application permission")
		}
		seen[v] = true
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

func ValidateRedirects(values []string) error {
	for _, v := range values {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errx.Validation("redirect URIs must be absolute HTTPS URLs without credentials or fragments")
		}
	}
	return nil
}
