package iamclient

import (
	"context"
	"time"
)

// ── Workspace-level types ──

// Principal is who a management request authenticated as.
type Principal struct {
	WorkspaceID string `json:"workspace_id"`
	OperatorID  string `json:"operator_id"`
	Role        string `json:"role"`
	// Method is "password" or "sso" (console sessions) or "key".
	Method string `json:"method,omitempty"`
	// AuthenticatedAt is when the console session signed in (nil for keys).
	AuthenticatedAt *time.Time `json:"authenticated_at,omitempty"`
}

// Operator is a member of the workspace's management console.
type Operator struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Active bool   `json:"active"`
	// PasswordAllowed is emergency password access in break-glass mode.
	PasswordAllowed bool `json:"password_allowed"`
	// SSOProviders are the operator SSO providers the operator linked.
	SSOProviders   []string   `json:"sso_providers"`
	LastSSOLoginAt *time.Time `json:"last_sso_login_at"`
}

// OperatorIdentity is an external SSO identity linked to an operator.
type OperatorIdentity struct {
	Provider    string     `json:"provider"`
	Issuer      string     `json:"issuer"`
	Email       string     `json:"email"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// ManagementKey is a management API key (the secret is shown only once,
// in ManagementCredential).
type ManagementKey struct {
	ID         string     `json:"id"`
	OperatorID string     `json:"operator_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// ManagementCredential is a newly created management key and its secret
// (ik_mgmt_).
type ManagementCredential struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Delegated is the answer to inviting an operator: its first management
// key. Reactivated is true when a disabled operator was invited again.
type Delegated struct {
	OperatorID  string    `json:"operator_id"`
	KeyID       string    `json:"key_id"`
	Secret      string    `json:"secret"`
	ExpiresAt   time.Time `json:"expires_at"`
	Reactivated bool      `json:"reactivated"`
}

// PasswordStatus describes the caller's console password.
type PasswordStatus struct {
	// Set: the operator has a password.
	Set bool `json:"set"`
	// Usable: the deployment lets this operator sign in with a password.
	Usable bool `json:"usable"`
	// Fresh: a password can be set without the current one.
	Fresh bool   `json:"fresh"`
	Mode  string `json:"mode"`
}

// Preferences are the caller's console preferences.
type Preferences struct {
	// Locale is the console language; nil follows the browser.
	Locale *string `json:"locale"`
}

// LoginOptions are the ways operators sign in to the console.
type LoginOptions struct {
	// Password: password sign-in is offered (see PasswordMode).
	Password bool `json:"password"`
	// PasswordMode is "enabled", "break_glass" or "disabled".
	PasswordMode string        `json:"password_mode"`
	Providers    []SSOProvider `json:"providers"`
}

// SSOProvider is an operator single sign-on provider.
type SSOProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// LoginOptions returns how operators can sign in (no credential needed).
func (c *Client) LoginOptions(ctx context.Context) (LoginOptions, error) {
	var out LoginOptions
	return out, c.Do(ctx, "GET", "/login-options", nil, &out)
}

// Project groups environments.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EnvironmentInfo describes a project environment.
type EnvironmentInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ── Workspace-level operations ──

// Me returns who the credential authenticates as.
func (c *Client) Me(ctx context.Context) (Principal, error) {
	var out Principal
	return out, c.Do(ctx, "GET", "/me", nil, &out)
}

// PasswordStatus reports whether the caller has a console password and
// whether it can be set without the current one.
func (c *Client) PasswordStatus(ctx context.Context) (PasswordStatus, error) {
	var out PasswordStatus
	return out, c.Do(ctx, "GET", "/password", nil, &out)
}

// SetPassword sets the operator's console password. With a management key
// no current password is needed; see ChangePassword otherwise.
func (c *Client) SetPassword(ctx context.Context, password string) error {
	return c.Do(ctx, "POST", "/password", map[string]string{"password": password}, nil)
}

// ChangePassword changes the operator's console password, proving the
// current one. Other console sessions of the operator end.
func (c *Client) ChangePassword(ctx context.Context, current, password string) error {
	return c.Do(ctx, "POST", "/password", map[string]string{"current_password": current, "password": password}, nil)
}

// Preferences returns the caller's console preferences.
func (c *Client) Preferences(ctx context.Context) (Preferences, error) {
	var out Preferences
	return out, c.Do(ctx, "GET", "/preferences", nil, &out)
}

// SetPreferences saves the caller's console preferences.
func (c *Client) SetPreferences(ctx context.Context, input Preferences) (Preferences, error) {
	var out Preferences
	return out, c.Do(ctx, "PUT", "/preferences", input, &out)
}

// Logout terminates the current management session.
func (c *Client) Logout(ctx context.Context) error {
	return c.Do(ctx, "DELETE", "/sessions/current", nil, nil)
}

// ── Keys ──

// CreateKey creates a new management API key. expiresIn is an optional Go
// duration string (e.g. "720h") or "never".
func (c *Client) CreateKey(ctx context.Context, expiresIn string) (ManagementCredential, error) {
	var out ManagementCredential
	var input any
	if expiresIn != "" {
		input = map[string]string{"expires_in": expiresIn}
	}
	return out, c.Do(ctx, "POST", "/keys", input, &out)
}

// Keys lists the caller's management API keys.
func (c *Client) Keys(ctx context.Context) ([]ManagementKey, error) {
	out := []ManagementKey{}
	return out, c.Do(ctx, "GET", "/keys", nil, &out)
}

// RevokeKey revokes a management API key.
func (c *Client) RevokeKey(ctx context.Context, id string) error {
	if err := safeSegment(id); err != nil {
		return err
	}
	return c.Do(ctx, "DELETE", "/keys/"+id, nil, nil)
}

// ── Operators ──

// Delegate invites an operator with the given role (or reactivates a
// disabled one) and returns its first management key. expiresIn controls
// the key TTL (Go duration string or "never").
func (c *Client) Delegate(ctx context.Context, email, role, expiresIn string) (Delegated, error) {
	var out Delegated
	input := map[string]string{"email": email, "role": role}
	if expiresIn != "" {
		input["expires_in"] = expiresIn
	}
	return out, c.Do(ctx, "POST", "/operators", input, &out)
}

// Operators lists all operators in the workspace.
func (c *Client) Operators(ctx context.Context) ([]Operator, error) {
	out := []Operator{}
	return out, c.Do(ctx, "GET", "/operators", nil, &out)
}

// DisableOperator disables an operator.
func (c *Client) DisableOperator(ctx context.Context, id string) error {
	if err := safeSegment(id); err != nil {
		return err
	}
	return c.Do(ctx, "DELETE", "/operators/"+id, nil, nil)
}

// SetOperatorRole changes an operator's role (owners only; the last owner
// keeps the role).
func (c *Client) SetOperatorRole(ctx context.Context, id, role string) error {
	if err := safeSegment(id); err != nil {
		return err
	}
	return c.Do(ctx, "PUT", "/operators/"+id+"/role", map[string]string{"role": role}, nil)
}

// SetOperatorPasswordAccess grants or withdraws an operator's emergency
// password access (break-glass mode, owners only).
func (c *Client) SetOperatorPasswordAccess(ctx context.Context, id string, allowed bool) error {
	if err := safeSegment(id); err != nil {
		return err
	}
	return c.Do(ctx, "PUT", "/operators/"+id+"/password-access", map[string]bool{"allowed": allowed}, nil)
}

// OperatorIdentities lists the SSO identities linked to an operator.
func (c *Client) OperatorIdentities(ctx context.Context, id string) ([]OperatorIdentity, error) {
	if err := safeSegment(id); err != nil {
		return nil, err
	}
	var out struct {
		Items []OperatorIdentity `json:"items"`
	}
	if err := c.Do(ctx, "GET", "/operators/"+id+"/identities", nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []OperatorIdentity{}, nil
	}
	return out.Items, nil
}

// UnlinkOperatorIdentities removes every SSO identity linked to an
// operator, so the next SSO sign-in links afresh.
func (c *Client) UnlinkOperatorIdentities(ctx context.Context, id string) error {
	if err := safeSegment(id); err != nil {
		return err
	}
	return c.Do(ctx, "DELETE", "/operators/"+id+"/identities", nil, nil)
}

// ── Projects & Environments ──

// CreateProject creates a new project.
func (c *Client) CreateProject(ctx context.Context, name string) (Created, error) {
	var out Created
	return out, c.Do(ctx, "POST", "/projects", map[string]string{"name": name}, &out)
}

// Projects lists all projects.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	out := []Project{}
	return out, c.Do(ctx, "GET", "/projects", nil, &out)
}

// CreateEnvironment creates an environment within a project.
func (c *Client) CreateEnvironment(ctx context.Context, project, name string) (Created, error) {
	var out Created
	if err := safeSegment(project); err != nil {
		return out, err
	}
	return out, c.Do(ctx, "POST", "/projects/"+project+"/environments", map[string]string{"name": name}, &out)
}

// Environments lists environments for a project.
func (c *Client) Environments(ctx context.Context, project string) ([]EnvironmentInfo, error) {
	if err := safeSegment(project); err != nil {
		return nil, err
	}
	out := []EnvironmentInfo{}
	return out, c.Do(ctx, "GET", "/projects/"+project+"/environments", nil, &out)
}
