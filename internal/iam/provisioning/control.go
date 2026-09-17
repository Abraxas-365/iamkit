package provisioning

import (
	"context"
	"time"
)

type CredentialInput struct {
	Name         string `json:"name"`
	Organization string `json:"organization_id"`
	Connection   string `json:"connection_id"`
}
type Credential struct {
	ID         string    `json:"id"`
	Secret     string    `json:"secret"`
	Expires    time.Time `json:"expires_at"`
	Connection string    `json:"connection_id"`
}
type Link struct {
	Connection string `json:"connection_id"`
	User       string `json:"user_id"`
	External   string `json:"external_id"`
}
type Mutation struct{ Environment, Actor, Action, Target string }
type ControlCommands interface {
	Issue(context.Context, string, CredentialInput) (Credential, error)
	Revoke(context.Context, Mutation, string) error
	Link(context.Context, Mutation, Link) error
}

type ControlRepository interface {
	IssueCredential(context.Context, string, CredentialInput, Credential, []byte, bool) error
	RevokeCredential(context.Context, Mutation, string) error
	Link(context.Context, Mutation, Link) error
}
type Generator interface {
	Generate(string) (string, []byte, error)
}
