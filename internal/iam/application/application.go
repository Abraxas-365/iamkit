package application

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// Application is the environment-scoped client application model.
// It is independent of HTTP and PostgreSQL representations.
type Application struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
	Active    bool     `json:"active"`
}

// Create is the data required to register an application.
type Create struct {
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
}

// Validate checks the structural invariants Create owns. Redirect URI format
// is validated separately via identity.ValidateRedirects.
func (c Create) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("application name is required")
	}
	return nil
}

// Update contains only fields explicitly supplied by an administrator.
type Update struct {
	Name      *string   `json:"name"`
	Redirects *[]string `json:"redirect_uris"`
	Active    *bool     `json:"active"`
}

// Validate checks only the fields explicitly supplied.
func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("application name is required")
	}
	return nil
}

// Mutation is immutable audit context supplied by the management boundary.
type Mutation struct{ Environment, Actor, Action, Target string }
