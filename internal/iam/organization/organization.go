package organization

import (
	"encoding/json"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Organization struct {
	ID       identity.OrganizationID `json:"id"`
	Name     string                  `json:"name"`
	Active   bool                    `json:"active"`
	Metadata json.RawMessage         `json:"metadata"`
}
type Summary struct {
	ID   identity.OrganizationID `json:"id"`
	Name string                  `json:"name"`
}
type Update struct {
	Name     *string         `json:"name"`
	Active   *bool           `json:"active"`
	Metadata json.RawMessage `json:"metadata"`
}

func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("organization name is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

type MemberView struct {
	User      identity.UserID `json:"user_id" db:"user_id"`
	UserName  string          `json:"user_name" db:"user_name"`
	UserEmail string          `json:"user_email" db:"user_email"`
	Active    bool            `json:"active" db:"active"`
}

type Membership struct {
	Organization identity.OrganizationID `json:"organization_id"`
	User         identity.UserID         `json:"user_id"`
}

func (m Membership) Validate() error {
	if m.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if m.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	return nil
}
