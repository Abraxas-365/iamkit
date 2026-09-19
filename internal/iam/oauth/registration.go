package oauth

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type ClientView struct {
	ID              identity.ClientID      `json:"id"`
	Application     identity.ApplicationID `json:"application_id"`
	ApplicationName string                 `json:"application_name"`
	Resource        identity.ResourceID    `json:"resource_id"`
	ResourceName    string                 `json:"resource_name"`
	Redirects       []string               `json:"redirect_uris"`
	Public          bool                   `json:"public"`
	Active          bool                   `json:"active"`
}

type Registration struct {
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Redirects   []string               `json:"redirect_uris"`
	Public      bool                   `json:"public"`
}

func (r Registration) Validate() error {
	if r.Application.IsZero() {
		return errx.Validation("application_id must be a valid UUID")
	}
	if r.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if len(r.Redirects) == 0 {
		return errx.Validation("at least one redirect URI is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
type Ticket struct {
	Client    identity.ClientID `db:"client_id"`
	Binding   []byte            `db:"binding_hash"`
	Form      string            `db:"request_form"`
	Requested time.Time         `db:"requested_at"`
}
