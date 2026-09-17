package management

import (
	"context"
	"time"
)

type Principal struct {
	WorkspaceID string `json:"workspace_id"`
	OperatorID  string `json:"operator_id"`
	Role        string `json:"role"`
}

func (p Principal) CanWrite() bool { return p.Role == "owner" || p.Role == "admin" }

// Repository operations preserve bootstrap/recovery atomicity without exposing SQL transactions.
type ManagementAuthenticator interface {
	Authenticate(context.Context, string) (Principal, error)
	EnvironmentAllowed(context.Context, Principal, string) bool
}

type Repository interface {
	Bootstrap(context.Context, string, string, []byte, time.Time) error
	RecoverOwner(context.Context, string, string, []byte, time.Time) error
	Authenticate(context.Context, []byte) (Principal, error)
	EnvironmentAllowed(context.Context, string, string) (bool, error)
}
type Secrets interface {
	Generate(string) (string, []byte, error)
	Hash(string) []byte
}
