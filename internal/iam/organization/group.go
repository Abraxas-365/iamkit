package organization

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// MaxGroupMemberChange caps the users added or removed by one request.
const MaxGroupMemberChange = 1000

// Group is a named, flat set of organization members. Roles bound to a group
// apply to all of its members. A group with a Connection is owned by that SCIM
// directory: its name and members are read-only for operators.
type Group struct {
	ID          identity.GroupID       `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Connection  *identity.ConnectionID `json:"connection_id" db:"connection_id"`
	External    *string                `json:"external_id,omitempty" db:"external_id"`
	Members     int                    `json:"member_count" db:"member_count"`
	Created     time.Time              `json:"created_at" db:"created_at"`
	Updated     time.Time              `json:"updated_at" db:"updated_at"`
}

// Managed reports whether a directory owns the group.
func (g Group) Managed() bool { return g.Connection != nil }

type GroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (g GroupInput) Validate() error {
	if strings.TrimSpace(g.Name) == "" {
		return errx.Validation("group name is required")
	}
	if len(g.Name) > 200 {
		return errx.Validation("group name must be at most 200 characters")
	}
	if len(g.Description) > 1000 {
		return errx.Validation("group description must be at most 1000 characters")
	}
	return nil
}

// GroupUpdate changes a group; nil fields are left untouched.
type GroupUpdate struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (g GroupUpdate) Validate() error {
	if g.Name != nil && strings.TrimSpace(*g.Name) == "" {
		return errx.Validation("group name is required")
	}
	if g.Name != nil && len(*g.Name) > 200 {
		return errx.Validation("group name must be at most 200 characters")
	}
	if g.Description != nil && len(*g.Description) > 1000 {
		return errx.Validation("group description must be at most 1000 characters")
	}
	return nil
}

// GroupMembers adds and removes users in one request. Adding a current member
// or removing a non-member is a no-op.
type GroupMembers struct {
	Add    []identity.UserID `json:"add"`
	Remove []identity.UserID `json:"remove"`
}

func (g GroupMembers) Validate() error {
	if len(g.Add) == 0 && len(g.Remove) == 0 {
		return errx.Validation("add or remove is required")
	}
	if len(g.Add)+len(g.Remove) > MaxGroupMemberChange {
		return errx.Validation("at most 1000 members can be changed per request")
	}
	for _, id := range append(append([]identity.UserID{}, g.Add...), g.Remove...) {
		if id.IsZero() {
			return errx.Validation("user_id must be a valid UUID")
		}
	}
	return nil
}

type GroupMemberView struct {
	User      identity.UserID `json:"user_id" db:"user_id"`
	UserName  string          `json:"user_name" db:"user_name"`
	UserEmail string          `json:"user_email" db:"user_email"`
	Active    bool            `json:"active" db:"active"`
	Added     time.Time       `json:"added_at" db:"created_at"`
}

// GroupFilter narrows ListGroups; zero values do not filter.
type GroupFilter struct {
	User       identity.UserID       // groups the user belongs to
	Connection identity.ConnectionID // groups owned by this directory
}
