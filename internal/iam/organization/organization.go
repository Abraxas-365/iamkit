package organization

import (
	"encoding/json"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Organization struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Active   bool            `json:"active"`
	Metadata json.RawMessage `json:"metadata"`
}
type Summary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Update struct {
	Name     *string         `json:"name"`
	Active   *bool           `json:"active"`
	Metadata json.RawMessage `json:"metadata"`
}

// Validate checks only the fields explicitly supplied.
func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("organization name is required")
	}
	return nil
}

type Mutation struct{ Environment, Actor, Action, Target string }

type MemberView struct {
	User      string `json:"user_id"`
	UserName  string `json:"user_name"`
	UserEmail string `json:"user_email"`
	Active    bool   `json:"active"`
}

type Membership struct {
	Organization string `json:"organization_id"`
	User         string `json:"user_id"`
}

// Validate checks the structural invariants Membership owns.
func (m Membership) Validate() error {
	if !identity.ValidID(m.Organization) {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if !identity.ValidID(m.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	return nil
}
