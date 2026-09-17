package serviceaccount

import (
	"context"
	"time"
)

type Input struct {
	Name        string   `json:"name"`
	Application string   `json:"application_id"`
	Resource    string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
}
type Credential struct {
	ID      string    `json:"id"`
	Secret  string    `json:"secret"`
	Expires time.Time `json:"expires_at"`
}
type Account struct {
	ID          string     `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Application string     `json:"application_id" db:"application_id"`
	Resource    string     `json:"resource_id" db:"resource_id"`
	Permissions []string   `json:"permissions" db:"permissions"`
	Expires     time.Time  `json:"expires_at" db:"expires_at"`
	Revoked     *time.Time `json:"revoked_at" db:"revoked_at"`
}
type Commands interface {
	Create(context.Context, string, Input) (Credential, error)
	Revoke(context.Context, string, string) error
}
type Queries interface {
	List(context.Context, string) ([]Account, error)
}

type Repository interface {
	Catalog(context.Context, string, string) ([]string, error)
	Create(context.Context, string, Input, Credential, []byte) error
	Revoke(context.Context, string, string) error
	List(context.Context, string) ([]Account, error)
}
type Secrets interface {
	Generate(string) (string, []byte, error)
}
