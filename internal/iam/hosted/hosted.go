// Package hosted serves IAMKit's own sign-in pages for OAuth clients that
// opt in (hosted_login). The pages authenticate the user first (password,
// email code or single sign-on), then choose the organization, then issue
// the session and finish the pending OAuth authorization.
package hosted

import (
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Settings brand the hosted pages of an environment. Empty values fall back
// to IAMKit defaults.
type Settings struct {
	Environment identity.EnvironmentID `json:"environment_id" db:"environment_id"`
	DisplayName string                 `json:"display_name" db:"display_name"`
	LogoURL     string                 `json:"logo_url" db:"logo_url"`
	AccentColor string                 `json:"accent_color" db:"accent_color"`
	UpdatedAt   *time.Time             `json:"updated_at,omitempty" db:"updated_at"`
}

var accent = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// Validate normalizes and checks the branding. The logo must be an https URL
// (the pages' content security policy only loads https images).
func (s *Settings) Validate() error {
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.LogoURL = strings.TrimSpace(s.LogoURL)
	s.AccentColor = strings.ToLower(strings.TrimSpace(s.AccentColor))
	if utf8.RuneCountInString(s.DisplayName) > 100 {
		return errx.Validation("display_name must be at most 100 characters")
	}
	if s.LogoURL != "" {
		u, err := url.Parse(s.LogoURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(s.LogoURL) > 2048 {
			return errx.Validation("logo_url must be an https URL")
		}
	}
	if s.AccentColor != "" && !accent.MatchString(s.AccentColor) {
		return errx.Validation("accent_color must be a #rrggbb color")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Request identifies the pending authorization a hosted page acts on: the
// authorization ticket and the browser binding cookie issued with it.
type Request struct {
	Ticket  string
	Binding string
}

// Page is what the first sign-in page shows.
type Page struct {
	Settings    Settings
	Connections []federation.ConnectionSummary
}

// Route is where an identified email signs in: single sign-on (the browser
// goes to Redirect, with Binding as the federation cookie) or password,
// with SSO offered as an alternative when Connection is set.
type Route struct {
	Method     string
	Redirect   string
	Binding    string
	Connection *identity.ConnectionID
}

// Result of a verification step: the organizations to choose from, or the
// login that finishes the authorization when there was a single one.
type Result struct {
	Organizations []authentication.Organization
	Login         *oauth.Login
}

// ErrNoAccess is returned when the verified user may not use the client's
// application in any organization.
func ErrNoAccess() error {
	return errx.Forbidden("your account does not have access to this application")
}
