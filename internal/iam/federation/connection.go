package federation

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Connection struct {
	ID          identity.ConnectionID
	Environment identity.EnvironmentID
	Name        string
	Issuer      string
	Client      string
	SecretEnv   string
}
type State struct {
	Connection      identity.ConnectionID
	Boundary        authentication.Context
	Binding         []byte
	Nonce, Verifier string
}
type Start struct{ URL, Binding string }
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
type ConnectionView struct {
	ID       identity.ConnectionID `json:"id"`
	Name     string                `json:"name"`
	Issuer   string                `json:"issuer"`
	ClientID string                `json:"client_id"`
	Active   bool                  `json:"active"`
	Linked   int                   `json:"linked"`
}
type ConnectionDetail struct {
	ID        identity.ConnectionID `json:"id"`
	Name      string                `json:"name"`
	Issuer    string                `json:"issuer"`
	ClientID  string                `json:"client_id"`
	SecretEnv string                `json:"secret_env"`
	Active    bool                  `json:"active"`
	Linked    int                   `json:"linked"`
}
type ExternalIdentityView struct {
	ConnectionID identity.ConnectionID `json:"connection_id" db:"connection_id"`
	Subject      string                `json:"subject" db:"subject"`
	UserID       identity.UserID       `json:"user_id" db:"user_id"`
	UserName     string                `json:"user_name" db:"user_name"`
	UserEmail    string                `json:"user_email" db:"user_email"`
}
