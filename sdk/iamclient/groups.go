package iamclient

import (
	"context"
	"net/url"
	"time"
)

// Group is a set of organization members; roles assigned to it apply to
// every member. Directory groups (ConnectionID set) are managed by SCIM.
type Group struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	ConnectionID *string   `json:"connection_id"`
	ExternalID   *string   `json:"external_id,omitempty"`
	MemberCount  int       `json:"member_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GroupInput creates a group.
type GroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// GroupPatch changes a group; nil fields are left unchanged.
type GroupPatch struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// GroupFilter narrows Groups: the groups of UserID, of a directory
// ConnectionID, or by Source ("manual" or "directory").
type GroupFilter struct {
	UserID       string
	ConnectionID string
	Source       string
}

// Query encodes the filter as query parameters.
func (f GroupFilter) Query() url.Values {
	q := url.Values{}
	if f.UserID != "" {
		q.Set("user_id", f.UserID)
	}
	if f.ConnectionID != "" {
		q.Set("connection_id", f.ConnectionID)
	}
	if f.Source != "" {
		q.Set("source", f.Source)
	}
	return q
}

// GroupMember is a member of a group.
type GroupMember struct {
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	UserEmail string    `json:"user_email"`
	Active    bool      `json:"active"`
	AddedAt   time.Time `json:"added_at"`
}

// GroupRoleAssignment gives every member of a group a role in the group's
// organization.
type GroupRoleAssignment struct {
	OrganizationID string `json:"organization_id"`
	GroupID        string `json:"group_id"`
	RoleID         string `json:"role_id"`
}

// GroupRoleAssignmentView is a group role assignment with names.
type GroupRoleAssignmentView struct {
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	GroupID          string `json:"group_id"`
	GroupName        string `json:"group_name"`
	RoleID           string `json:"role_id"`
	RoleName         string `json:"role_name"`
	ResourceID       string `json:"resource_id"`
	ResourceName     string `json:"resource_name"`
}

// GroupRoleFilter narrows GroupRoleAssignments; zero fields match all.
type GroupRoleFilter struct {
	OrganizationID string
	GroupID        string
	RoleID         string
	ResourceID     string
}

// EffectiveRole is a role a user holds, directly or through a group.
type EffectiveRole struct {
	OrganizationID string `json:"organization_id"`
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	ResourceID     string `json:"resource_id"`
	ResourceName   string `json:"resource_name"`
	// Source is "direct" or "group" (GroupID and GroupName set).
	Source string `json:"source"`
	// Granted is false when the resource requires a grant the
	// organization lacks: the role gives no access.
	Granted   bool    `json:"granted"`
	GroupID   *string `json:"group_id,omitempty"`
	GroupName *string `json:"group_name,omitempty"`
}

// ── Groups ──

func (e Environment) CreateGroup(ctx context.Context, org string, input GroupInput) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"organizations", org, "groups"}, input, &out)
	return out, err
}

func (e Environment) Groups(ctx context.Context, org string, filter GroupFilter) ([]Group, error) {
	return listOp[Group](e, ctx, []string{"organizations", org, "groups"}, filter.Query())
}

func (e Environment) Group(ctx context.Context, org, id string) (Group, error) {
	var out Group
	err := e.operation(ctx, "GET", []string{"organizations", org, "groups", id}, nil, &out)
	return out, err
}

func (e Environment) UpdateGroup(ctx context.Context, org, id string, input GroupPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", org, "groups", id}, input, nil)
}

// DeleteGroup deletes a manual group (directory groups belong to SCIM).
func (e Environment) DeleteGroup(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "groups", id}, nil, nil)
}

func (e Environment) GroupMembers(ctx context.Context, org, id string) ([]GroupMember, error) {
	return listOp[GroupMember](e, ctx, []string{"organizations", org, "groups", id, "members"})
}

// ChangeGroupMembers adds and removes organization members (user IDs).
func (e Environment) ChangeGroupMembers(ctx context.Context, org, id string, add, remove []string) error {
	input := map[string][]string{"add": add, "remove": remove}
	return e.operation(ctx, "POST", []string{"organizations", org, "groups", id, "members"}, input, nil)
}

// MemberGroups lists the groups of an organization member.
func (e Environment) MemberGroups(ctx context.Context, org, user string) ([]Group, error) {
	return listOp[Group](e, ctx, []string{"organizations", org, "members", user, "groups"})
}

// ── Group role assignments ──

func (e Environment) AssignGroupRole(ctx context.Context, input GroupRoleAssignment) error {
	return e.operation(ctx, "POST", []string{"group-role-assignments"}, input, nil)
}

func (e Environment) GroupRoleAssignments(ctx context.Context, filter GroupRoleFilter) ([]GroupRoleAssignmentView, error) {
	q := url.Values{}
	for key, value := range map[string]string{"organization_id": filter.OrganizationID, "group_id": filter.GroupID, "role_id": filter.RoleID, "resource_id": filter.ResourceID} {
		if value != "" {
			q.Set(key, value)
		}
	}
	return listOp[GroupRoleAssignmentView](e, ctx, []string{"group-role-assignments"}, q)
}

func (e Environment) UnassignGroupRole(ctx context.Context, input GroupRoleAssignment) error {
	return e.operation(ctx, "DELETE", []string{"group-role-assignments", input.RoleID, input.OrganizationID, input.GroupID}, nil, nil)
}

// EffectiveRoles lists the roles user holds, directly and through groups,
// in org ("" = every organization of the user).
func (e Environment) EffectiveRoles(ctx context.Context, user, org string) ([]EffectiveRole, error) {
	q := url.Values{"user_id": {user}}
	if org != "" {
		q.Set("organization_id", org)
	}
	return first[EffectiveRole](ctx, e.client, e.path("effective-roles"), q)
}
