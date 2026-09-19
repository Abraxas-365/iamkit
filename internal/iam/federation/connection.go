package federation

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

type Connection struct{ ID, Environment, Name, Issuer, Client, SecretEnv string }
type State struct {
	Connection      string
	Boundary        authentication.Context
	Binding         []byte
	Nonce, Verifier string
}
type Start struct{ URL, Binding string }
type Mutation struct{ Environment, Actor, Action, Target string }
type ConnectionView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Active   bool   `json:"active"`
	Linked   int    `json:"linked"`
}
type ConnectionDetail struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client_id"`
	SecretEnv string `json:"secret_env"`
	Active    bool   `json:"active"`
	Linked    int    `json:"linked"`
}
type ExternalIdentityView struct {
	ConnectionID string `json:"connection_id" db:"connection_id"`
	Subject      string `json:"subject" db:"subject"`
	UserID       string `json:"user_id" db:"user_id"`
	UserName     string `json:"user_name" db:"user_name"`
	UserEmail    string `json:"user_email" db:"user_email"`
}
