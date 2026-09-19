package management

import "time"

// Principal identifies an authenticated management operator within a workspace.
type Principal struct {
	WorkspaceID string `json:"workspace_id"`
	OperatorID  string `json:"operator_id"`
	Role        string `json:"role"`
}

func (p Principal) CanWrite() bool { return p.Role == "owner" || p.Role == "admin" }

type Named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Key struct {
	ID       string     `json:"id"`
	Operator string     `json:"operator_id"`
	Expires  time.Time  `json:"expires_at"`
	Revoked  *time.Time `json:"revoked_at"`
}
type Credential struct {
	ID      string    `json:"id"`
	Secret  string    `json:"secret"`
	Expires time.Time `json:"expires_at"`
}
type Delegated struct {
	Operator string    `json:"operator_id"`
	Key      string    `json:"key_id"`
	Secret   string    `json:"secret"`
	Expires  time.Time `json:"expires_at"`
}
type Operator struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Active bool   `json:"active"`
}
