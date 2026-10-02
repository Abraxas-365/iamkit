// Package orgadmin lets an organization's own administrators manage it
// through /api/v1/environments/:environment/organizations/:organization/admin.
// They hold organization-bound permissions (authorization.OrgPermissions) in
// a token issued in that organization; the service checks every command
// against them and against the anti-escalation rules, then delegates to the
// user, organization, authorization, invitation and federation modules.
package orgadmin

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Principal is an organization administrator acting in their organization.
// Action and Target describe the request for the audit trail.
type Principal struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	User         identity.UserID
	Permissions  []string
	Action       string
	Target       string
}

// Has reports whether the principal holds the permission.
func (p Principal) Has(permission string) bool { return slices.Contains(p.Permissions, permission) }

// Require refuses a principal without the permission.
func (p Principal) Require(permission string) error {
	if !p.Has(permission) {
		return errx.Forbidden("missing permission: " + permission)
	}
	return nil
}

// Actor is the audit actor (the administrator's user ID).
func (p Principal) Actor() string { return p.User.String() }

// Settings are the organization fields its administrators may change;
// activation and metadata stay with operators.
type Settings struct {
	Name            *string  `json:"name"`
	MFARequired     *bool    `json:"mfa_required"`
	MFAForFederated *bool    `json:"mfa_for_federated"`
	AllowPassword   *bool    `json:"allow_password"`
	AllowEmailCode  *bool    `json:"allow_email_code"`
	AllowSocial     *bool    `json:"allow_social"`
	AllowPasskey    *bool    `json:"allow_passkey"`
	AllowedFactors  []string `json:"allowed_factors"`
}

// Update is the organization update the settings make.
func (s Settings) Update() organization.Update {
	return organization.Update{Name: s.Name, MFARequired: s.MFARequired, MFAForFederated: s.MFAForFederated,
		AllowPassword: s.AllowPassword, AllowEmailCode: s.AllowEmailCode, AllowSocial: s.AllowSocial,
		AllowPasskey: s.AllowPasskey, AllowedFactors: s.AllowedFactors}
}

func (s Settings) Validate() error { return s.Update().Validate() }

// NewUser creates a user homed in the organization (and a member of it).
type NewUser struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Password  string `json:"password"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
}

// Create is the user create for the organization.
func (n NewUser) Create(organization identity.OrganizationID) user.Create {
	return user.Create{Email: n.Email, Name: n.Name, Password: n.Password, Username: n.Username, AvatarURL: n.AvatarURL, HomeOrganization: organization}
}

func (n NewUser) Validate() error { return n.Create(identity.OrganizationID{}).Validate() }

// UserChange edits a home user's record; metadata, the home organization
// and second-factor settings stay with operators.
type UserChange struct {
	Name      *string `json:"name"`
	Phone     *string `json:"phone"`
	AvatarURL *string `json:"avatar_url"`
	Username  *string `json:"username"`
}

// Update is the user update the change makes.
func (c UserChange) Update() user.Update {
	return user.Update{Name: c.Name, Phone: c.Phone, AvatarURL: c.AvatarURL, Username: c.Username}
}

func (c UserChange) Validate() error {
	if c.Name == nil && c.Phone == nil && c.AvatarURL == nil && c.Username == nil {
		return errx.Validation("no changes requested")
	}
	return c.Update().Normalize().Validate()
}

// Role is a role an organization administrator may see and assign.
type Role struct {
	ID          identity.RoleID     `json:"id" db:"id"`
	Name        string              `json:"name" db:"name"`
	Resource    identity.ResourceID `json:"resource_id" db:"resource_id"`
	Permissions []string            `json:"permissions" db:"-"`
	// SystemRole names a built-in role ("" for custom roles).
	SystemRole string `json:"system_role,omitempty" db:"system_role"`
	// ResourceName is the role's resource.
	ResourceName string `json:"resource_name" db:"resource_name"`
	// IAM is true for roles of the environment's IAM resource.
	IAM bool `json:"-" db:"iam"`
	// Granted is true for roles of another resource the organization owns
	// or holds a resource grant covering the role for.
	Granted bool `json:"-" db:"granted"`
}

// Assignable reports why the principal may not assign or remove the role:
// IAM-resource roles whose permissions the principal holds (the owner role
// only by an owner), and roles of resources the organization owns or was
// granted.
func (r Role) Assignable(p Principal, owner bool) error {
	if r.Granted {
		return nil
	}
	if !r.IAM {
		return errx.Forbidden("the role's resource is not granted to your organization")
	}
	for _, permission := range r.Permissions {
		if !p.Has(permission) {
			return errx.Forbidden("the role grants " + permission + ", which you do not hold")
		}
	}
	if r.SystemRole == OwnerRole && !owner {
		return errx.Forbidden("only organization owners manage the owner role")
	}
	return nil
}

// OwnerRole is the system role that makes an organization owner (mirrors
// authorization.SystemRoleOrgOwner).
const OwnerRole = "org_owner"

// Owner is an active member holding the owner role, directly and/or
// through a group.
type Owner struct {
	User   identity.UserID `db:"user_id"`
	Direct bool            `db:"direct"`
	Group  bool            `db:"via_group"`
}

// Owners is the organization's owner list.
type Owners []Owner

// Includes reports whether the user is an owner.
func (o Owners) Includes(user identity.UserID) bool {
	for _, owner := range o {
		if owner.User == user {
			return true
		}
	}
	return false
}

// KeepsOwner reports whether an owner remains once the user loses the
// direct owner role (direct) or leaves entirely (!direct).
func (o Owners) KeepsOwner(user identity.UserID, direct bool) bool {
	for _, owner := range o {
		if owner.User != user || (direct && owner.Group) {
			return true
		}
	}
	return false
}

// Assignment gives a member a role in the organization.
type Assignment struct {
	User identity.UserID `json:"user_id"`
	Role identity.RoleID `json:"role_id"`
}

func (a Assignment) Validate() error {
	if a.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	if a.Role.IsZero() {
		return errx.Validation("role_id must be a valid UUID")
	}
	return nil
}

// Event is an audit event concerning the organization.
type Event struct {
	ID         string    `json:"id" db:"id"`
	Actor      string    `json:"actor_id" db:"actor_id"`
	ActorKind  string    `json:"actor_kind" db:"actor_kind"`
	ActorLabel string    `json:"actor_label" db:"actor_label"`
	Action     string    `json:"action" db:"action"`
	Target     string    `json:"target_id" db:"target_id"`
	Created    time.Time `json:"created_at" db:"created_at"`
}

// EventFilter narrows the organization's audit events.
type EventFilter struct {
	// Action keeps events whose action starts with it.
	Action string
}

func (f EventFilter) Validate() error {
	if len(f.Action) > 100 || strings.ContainsAny(f.Action, "%_\\") {
		return errx.Validation("action must be at most 100 characters without % _ or \\")
	}
	return nil
}
