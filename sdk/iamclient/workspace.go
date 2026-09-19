package iamclient

import (
	"context"
	"time"
)

// ── Workspace-level types ──

// Operator represents a management console operator.
type Operator struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// OperatorKey is an API key for management access.
type OperatorKey struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret,omitempty"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
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

// Me returns the authenticated operator's profile.
func (c *Client) Me(ctx context.Context) (Operator, error) {
	var out Operator
	return out, c.Do(ctx, "GET", "/me", nil, &out)
}

// SetPassword sets or changes the operator's console password.
func (c *Client) SetPassword(ctx context.Context, password string) error {
	return c.Do(ctx, "POST", "/password", map[string]string{"password": password}, nil)
}

// Logout terminates the current management session.
func (c *Client) Logout(ctx context.Context) error {
	return c.Do(ctx, "DELETE", "/sessions/current", nil, nil)
}

// ── Keys ──

// CreateKey creates a new management API key. expiresIn is an optional Go
// duration string (e.g. "720h") or "never".
func (c *Client) CreateKey(ctx context.Context, expiresIn string) (OperatorKey, error) {
	var out OperatorKey
	var input any
	if expiresIn != "" {
		input = map[string]string{"expires_in": expiresIn}
	}
	return out, c.Do(ctx, "POST", "/keys", input, &out)
}

// Keys lists all management API keys.
func (c *Client) Keys(ctx context.Context) ([]OperatorKey, error) {
	var out []OperatorKey
	return out, c.Do(ctx, "GET", "/keys", nil, &out)
}

// RevokeKey revokes a management API key.
func (c *Client) RevokeKey(ctx context.Context, id string) error {
	return c.Do(ctx, "DELETE", "/keys/"+id, nil, nil)
}

// ── Operators ──

// Delegate invites a new operator with the given role. expiresIn controls the
// credential TTL (Go duration string or "never").
func (c *Client) Delegate(ctx context.Context, email, role, expiresIn string) (OperatorKey, error) {
	var out OperatorKey
	input := map[string]string{"email": email, "role": role}
	if expiresIn != "" {
		input["expires_in"] = expiresIn
	}
	return out, c.Do(ctx, "POST", "/operators", input, &out)
}

// Operators lists all operators in the workspace.
func (c *Client) Operators(ctx context.Context) ([]Operator, error) {
	var out []Operator
	return out, c.Do(ctx, "GET", "/operators", nil, &out)
}

// DisableOperator disables an operator.
func (c *Client) DisableOperator(ctx context.Context, id string) error {
	return c.Do(ctx, "DELETE", "/operators/"+id, nil, nil)
}

// ── Projects & Environments ──

// CreateProject creates a new project.
func (c *Client) CreateProject(ctx context.Context, name string) (Created, error) {
	var out Created
	return out, c.Do(ctx, "POST", "/projects", map[string]string{"name": name}, &out)
}

// Projects lists all projects.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var out []Project
	return out, c.Do(ctx, "GET", "/projects", nil, &out)
}

// CreateEnvironment creates an environment within a project.
func (c *Client) CreateEnvironment(ctx context.Context, project, name string) (Created, error) {
	var out Created
	return out, c.Do(ctx, "POST", "/projects/"+project+"/environments", map[string]string{"name": name}, &out)
}

// Environments lists environments for a project.
func (c *Client) Environments(ctx context.Context, project string) ([]EnvironmentInfo, error) {
	var out []EnvironmentInfo
	return out, c.Do(ctx, "GET", "/projects/"+project+"/environments", nil, &out)
}
