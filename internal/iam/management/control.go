package management

import (
	"context"
	"time"
)

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
type ControlCommands interface {
	CreateKey(context.Context, Principal) (Credential, error)
	RevokeKey(context.Context, Principal, string) error
	Delegate(context.Context, Principal, string, string) (Delegated, error)
	DisableOperator(context.Context, Principal, string) error
	CreateProject(context.Context, Principal, string) (string, error)
	CreateEnvironment(context.Context, Principal, string, string) (string, error)
}
type ControlQueries interface {
	Keys(context.Context, Principal) ([]Key, error)
	Projects(context.Context, Principal) ([]Named, error)
	Environments(context.Context, Principal, string) ([]Named, error)
}

type ControlRepository interface {
	CreateKey(context.Context, Principal, string, []byte, time.Time) error
	Keys(context.Context, Principal) ([]Key, error)
	RevokeKey(context.Context, Principal, string) error
	Delegate(context.Context, Principal, string, string, string, []byte, time.Time) (string, error)
	DisableOperator(context.Context, Principal, string) error
	CreateProject(context.Context, string, string, string) error
	Projects(context.Context, string) ([]Named, error)
	CreateEnvironment(context.Context, string, string, string, string) error
	Environments(context.Context, string, string) ([]Named, error)
}
