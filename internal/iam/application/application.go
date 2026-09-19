package application

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Application struct {
	ID        identity.ApplicationID `json:"id"`
	Name      string                 `json:"name"`
	Redirects []string               `json:"redirect_uris"`
	Active    bool                   `json:"active"`
}

type Create struct {
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
}

func (c Create) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("application name is required")
	}
	return nil
}

type Update struct {
	Name      *string   `json:"name"`
	Redirects *[]string `json:"redirect_uris"`
	Active    *bool     `json:"active"`
}

func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("application name is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
