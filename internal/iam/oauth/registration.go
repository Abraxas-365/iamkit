package oauth

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type ClientView struct {
	ID              string   `json:"id"`
	Application     string   `json:"application_id"`
	ApplicationName string   `json:"application_name"`
	Resource        string   `json:"resource_id"`
	ResourceName    string   `json:"resource_name"`
	Redirects       []string `json:"redirect_uris"`
	Public          bool     `json:"public"`
	Active          bool     `json:"active"`
}

type Registration struct {
	Application string   `json:"application_id"`
	Resource    string   `json:"resource_id"`
	Redirects   []string `json:"redirect_uris"`
	Public      bool     `json:"public"`
}

// Validate checks the structural invariants Registration owns. Redirect URI
// format is validated separately via identity.ValidateRedirects.
func (r Registration) Validate() error {
	if !identity.ValidID(r.Application) {
		return errx.Validation("application_id must be a valid UUID")
	}
	if !identity.ValidID(r.Resource) {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if len(r.Redirects) == 0 {
		return errx.Validation("at least one redirect URI is required")
	}
	return nil
}

type Mutation struct{ Environment, Actor, Action, Target string }
type Ticket struct {
	Client    string    `db:"client_id"`
	Binding   []byte    `db:"binding_hash"`
	Form      string    `db:"request_form"`
	Requested time.Time `db:"requested_at"`
}
