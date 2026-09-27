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
	HostedLogin     bool                   `json:"hosted_login"`
	Active          bool                   `json:"active"`
}

type Registration struct {
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Redirects   []string               `json:"redirect_uris"`
	Public      bool                   `json:"public"`
	HostedLogin bool                   `json:"hosted_login"`
}

// ClientUpdate changes the settings of an existing client.
type ClientUpdate struct {
	HostedLogin *bool `json:"hosted_login"`
}

func (u ClientUpdate) Validate() error {
	if u.HostedLogin == nil {
		return errx.Validation("hosted_login is required")
	}
	return nil
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

// Pending is an unfinished authorization: its active client and the
// original authorize request form.
type Pending struct {
	Client *Client
	Form   string
}

// Login is the session a hosted login completes an authorization with.
type Login struct {
	User         identity.UserID
	Organization identity.OrganizationID
	Session      identity.SessionID
	Permissions  []string
}

// SessionInfo is what tokens take from the end-user session: its lifetime,
// when it was authenticated and how (amr claim).
type SessionInfo struct {
	Expires       time.Time
	Authenticated time.Time
	AMR           []string
}
