package provisioning

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Group is a directory-owned organization group as the SCIM connection sees
// it. Operators decide which roles it carries; the directory owns its name
// and members.
type Group struct {
	ID       identity.GroupID `db:"id"`
	Name     string           `db:"name"`
	External string           `db:"external_id"`
	Created  time.Time        `db:"created_at"`
	Modified time.Time        `db:"updated_at"`
	Version  int64            `db:"version"`
	// Members is nil when the caller excluded the attribute.
	Members []GroupMember `db:"-"`
}

type GroupMember struct {
	Group   identity.GroupID `db:"group_id"`
	User    identity.UserID  `db:"user_id"`
	Display string           `db:"display"`
}

type GroupInput struct {
	Name     string
	External string
	Members  []identity.UserID
}

func (g GroupInput) Validate() error {
	return validGroupName(g.Name)
}

// GroupUpdate carries SCIM group changes. Members, when set, replaces the
// whole member set and then Add/Remove apply on top; nil fields are untouched.
type GroupUpdate struct {
	Name     *string
	External *string
	Members  *[]identity.UserID
	Add      []identity.UserID
	Remove   []identity.UserID
}

func (g GroupUpdate) Validate() error {
	if g.Name != nil {
		return validGroupName(*g.Name)
	}
	return nil
}

// Empty reports whether the update changes nothing.
func (g GroupUpdate) Empty() bool {
	return g.Name == nil && g.External == nil && g.Members == nil && len(g.Add) == 0 && len(g.Remove) == 0
}

func validGroupName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errx.Validation("displayName is required").WithDetail("scimType", "invalidValue")
	}
	if len(name) > 200 {
		return errx.Validation("displayName must be at most 200 characters").WithDetail("scimType", "invalidValue")
	}
	return nil
}

// GroupFilter is a SCIM /Groups query. Field is one of "", "displayName",
// "externalId" or "id". ExcludeMembers skips loading members.
type GroupFilter struct {
	Field, Value   string
	ExcludeMembers bool
}
