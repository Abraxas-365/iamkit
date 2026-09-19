package management

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Principal struct {
	WorkspaceID identity.WorkspaceID `json:"workspace_id"`
	OperatorID  identity.OperatorID  `json:"operator_id"`
	Role        string               `json:"role"`
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
}
