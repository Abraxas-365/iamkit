package management

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Principal struct {
	WorkspaceID identity.WorkspaceID `json:"workspace_id"`
	OperatorID  identity.OperatorID  `json:"operator_id"`
	Role        string               `json:"role"`
	// Method is how the request authenticated: MethodPassword or MethodSSO
	// (console sessions), MethodKey (management keys).
	Method string `json:"method,omitempty"`
	// Session and AuthTime identify a console session and when it signed
	// in; zero for management keys.
	Session  identity.SessionID `json:"-"`
	AuthTime *time.Time         `json:"authenticated_at,omitempty"`
}

// Operator sign-in methods (operator_sessions.method, Principal.Method).
const (
	MethodPassword = "password"
	MethodSSO      = "sso"
	MethodKey      = "key"
)

// Fresh reports whether the principal may change sign-in credentials
// without proving a password: a management key (how /setup sets the first
// password), or a console session that signed in within window.
func (p Principal) Fresh(now time.Time, window time.Duration) bool {
	if p.Method == MethodKey {
		return true
	}
	return p.AuthTime != nil && now.Sub(*p.AuthTime) <= window
}

func (p Principal) CanWrite() bool { return p.Role == "owner" || p.Role == "admin" }

type Named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Key struct {
	ID       identity.KeyID      `json:"id"`
	Operator identity.OperatorID `json:"operator_id"`
	Expires  time.Time           `json:"expires_at"`
	Revoked  *time.Time          `json:"revoked_at"`
}
type Credential struct {
	ID      identity.KeyID `json:"id"`
	Secret  string         `json:"secret"`
	Expires time.Time      `json:"expires_at"`
}
type Delegated struct {
	Operator identity.OperatorID `json:"operator_id"`
	Key      identity.KeyID      `json:"key_id"`
	Secret   string              `json:"secret"`
	Expires  time.Time           `json:"expires_at"`
}
type Operator struct {
	ID     identity.OperatorID `json:"id"`
	Email  string              `json:"email"`
	Role   string              `json:"role"`
	Active bool                `json:"active"`
	// PasswordAllowed is emergency password access in break-glass mode.
	PasswordAllowed bool `json:"password_allowed"`
	// Providers are the configured operator SSO providers the operator has
	// linked an identity through (IDs at link time), for display.
	Providers []string   `json:"sso_providers"`
	LastSSO   *time.Time `json:"last_sso_login_at"`
}

// PasswordAccount is what a password sign-in checks: the operator's
// principal, password hash (empty: none set), emergency access grant, and
// whether the password must be replaced at the next sign-in.
type PasswordAccount struct {
	Principal  Principal
	Hash       string
	Allowed    bool
	MustChange bool
}

// ConsoleLocales are the languages the console is translated into
// (frontend/src/locales); keep both lists in step.
var ConsoleLocales = []string{"en", "es"}

// Preferences are the caller's own console settings.
type Preferences struct {
	// Locale is the console language; nil follows the browser.
	Locale *string `json:"locale"`
}

// Validate accepts a console language or nil.
func (p Preferences) Validate() error {
	if p.Locale != nil && !slices.Contains(ConsoleLocales, *p.Locale) {
		return errx.Validation("locale must be one of " + strings.Join(ConsoleLocales, ", "))
	}
	return nil
}

// PasswordStatus is the caller's own password state, for the console.
type PasswordStatus struct {
	// Set: the operator has a password.
	Set bool `json:"set"`
	// Usable: the deployment lets this operator sign in with a password.
	Usable bool `json:"usable"`
	// Fresh: a password can be set without the current one (none is set
	// yet and the session signed in recently, or a management key).
	Fresh bool         `json:"fresh"`
	Mode  PasswordMode `json:"mode"`
}
