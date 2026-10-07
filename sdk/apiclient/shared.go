package apiclient

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Routes shared with the management API; see iamclient for the same
// methods authenticated with a management key.

func safeSegment(id string) error {
	if id == "" || strings.ContainsAny(id, "/?#.%\\") {
		return fmt.Errorf("invalid resource ID")
	}
	return nil
}

// operation calls an environment route whose path segments are validated
// (IDs supplied by callers never traverse paths).
func (e Environment) operation(ctx context.Context, method string, parts []string, input, output any) error {
	for _, part := range parts {
		if err := safeSegment(part); err != nil {
			return err
		}
	}
	return e.client.Do(ctx, method, e.path(parts...), input, output)
}

// listOp lists every item of a collection under validated segments.
func listOp[T any](e Environment, ctx context.Context, parts []string, query ...url.Values) ([]T, error) {
	for _, part := range parts {
		if err := safeSegment(part); err != nil {
			return nil, err
		}
	}
	var q url.Values
	if len(query) > 0 {
		q = query[0]
	}
	return list[T](ctx, e.client, e.path(parts...), q)
}

// ChangeGroupMembers adds and removes organization members (user IDs).
func (e Environment) ChangeGroupMembers(ctx context.Context, org, id string, add, remove []string) error {
	input := map[string][]string{"add": add, "remove": remove}
	return e.operation(ctx, "POST", []string{"organizations", org, "groups", id, "members"}, input, nil)
}

func (e Environment) CreateGroup(ctx context.Context, org string, input GroupInput) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"organizations", org, "groups"}, input, &out)
	return out, err
}

// DeleteGroup deletes a manual group (directory groups belong to SCIM).
func (e Environment) DeleteGroup(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "groups", id}, nil, nil)
}

func (e Environment) Group(ctx context.Context, org, id string) (Group, error) {
	var out Group
	err := e.operation(ctx, "GET", []string{"organizations", org, "groups", id}, nil, &out)
	return out, err
}

func (e Environment) GroupMembers(ctx context.Context, org, id string) ([]GroupMember, error) {
	return listOp[GroupMember](e, ctx, []string{"organizations", org, "groups", id, "members"})
}

func (e Environment) Groups(ctx context.Context, org string, filter GroupFilter) ([]Group, error) {
	return listOp[Group](e, ctx, []string{"organizations", org, "groups"}, filter.Query())
}

// MemberGroups lists the groups of an organization member.
func (e Environment) MemberGroups(ctx context.Context, org, user string) ([]Group, error) {
	return listOp[Group](e, ctx, []string{"organizations", org, "members", user, "groups"})
}

func (e Environment) UpdateGroup(ctx context.Context, org, id string, input GroupPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", org, "groups", id}, input, nil)
}

func (e Environment) AssignGroupRole(ctx context.Context, input GroupRoleAssignment) error {
	return e.operation(ctx, "POST", []string{"group-role-assignments"}, input, nil)
}

func (e Environment) UnassignGroupRole(ctx context.Context, input GroupRoleAssignment) error {
	return e.operation(ctx, "DELETE", []string{"group-role-assignments", input.RoleID, input.OrganizationID, input.GroupID}, nil, nil)
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

// EffectiveRoles lists the roles user holds, directly and through groups,
// in org ("" = every organization of the user).
func (e Environment) EffectiveRoles(ctx context.Context, user, org string) ([]EffectiveRole, error) {
	q := url.Values{"user_id": {user}}
	if org != "" {
		q.Set("organization_id", org)
	}
	return first[EffectiveRole](ctx, e.client, e.path("effective-roles"), q)
}

// AddDomain registers a domain; publish its Record in DNS, then call
// VerifyDomain.
func (e Environment) AddDomain(ctx context.Context, org, domain string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains"}, map[string]string{"domain": domain}, &out)
	return out, err
}

func (e Environment) DeleteDomain(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "domains", id}, nil, nil)
}

func (e Environment) Domain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "GET", []string{"organizations", org, "domains", id}, nil, &out)
	return out, err
}

func (e Environment) Domains(ctx context.Context, org string) ([]Domain, error) {
	return listOp[Domain](e, ctx, []string{"organizations", org, "domains"})
}

// ForceVerifyDomain marks the domain verified without DNS (audited).
func (e Environment) ForceVerifyDomain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains", id, "force-verify"}, nil, &out)
	return out, err
}

// VerifyDomain checks the DNS TXT record now.
func (e Environment) VerifyDomain(ctx context.Context, org, id string) (Domain, error) {
	var out Domain
	err := e.operation(ctx, "POST", []string{"organizations", org, "domains", id, "verify"}, nil, &out)
	return out, err
}

func (e Environment) Invitation(ctx context.Context, org, id string) (Invitation, error) {
	var out Invitation
	err := e.operation(ctx, "GET", []string{"organizations", org, "invitations", id}, nil, &out)
	return out, err
}

// Invitations lists an organization's invitations; status "" returns all
// (filtered client-side on the first page).
func (e Environment) Invitations(ctx context.Context, org, status string) ([]Invitation, error) {
	all, err := listOp[Invitation](e, ctx, []string{"organizations", org, "invitations"})
	if err != nil || status == "" {
		return all, err
	}
	out := []Invitation{}
	for _, inv := range all {
		if inv.Status == status {
			out = append(out, inv)
		}
	}
	return out, nil
}

func (e Environment) Invite(ctx context.Context, org string, input InvitationInput) (IssuedInvitation, error) {
	var out IssuedInvitation
	err := e.operation(ctx, "POST", []string{"organizations", org, "invitations"}, input, &out)
	return out, err
}

// ResendInvitation issues a new token (the previous one stops working) and
// restarts the expiry.
func (e Environment) ResendInvitation(ctx context.Context, org, id string) (IssuedInvitation, error) {
	var out IssuedInvitation
	err := e.operation(ctx, "POST", []string{"organizations", org, "invitations", id, "resend"}, nil, &out)
	return out, err
}

func (e Environment) RevokeInvitation(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "invitations", id}, nil, nil)
}

func (e Environment) CreateOrgUnit(ctx context.Context, organization string, input OrgUnit) (Created, error) {
	var out Created
	if err := safeSegment(organization); err != nil {
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("organizations/"+organization+"/org-units"), input, &out)
	return out, err
}

func (e Environment) DeleteOrgUnit(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "org-units", id}, nil, nil)
}

func (e Environment) OrgUnit(ctx context.Context, org, id string) (OrgUnit, error) {
	var out OrgUnit
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitAncestors(ctx context.Context, org, id string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "org-units", id, "ancestors"})
}

func (e Environment) OrgUnitDeleteImpact(ctx context.Context, org, id string) (UnitImpact, error) {
	var out UnitImpact
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "delete-impact"}, nil, &out)
	return out, err
}

func (e Environment) OrgUnitDescendants(ctx context.Context, org, id string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "org-units", id, "descendants"})
}

func (e Environment) OrgUnits(ctx context.Context, organization string) ([]OrgUnit, error) {
	if err := safeSegment(organization); err != nil {
		return nil, err
	}
	return list[OrgUnit](ctx, e.client, e.path("organizations/"+organization+"/org-units"), nil)
}

func (e Environment) UpdateOrgUnit(ctx context.Context, org, id string, input OrgUnit) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "org-units", id}, input, nil)
}

func (e Environment) AssignPosition(ctx context.Context, org string, input PositionAssignment) (Created, error) {
	var out Created
	err := e.operation(ctx, "POST", []string{"organizations", org, "position-assignments"}, input, &out)
	return out, err
}

func (e Environment) CreatePosition(ctx context.Context, organization string, input Position) (Created, error) {
	var out Created
	if err := safeSegment(organization); err != nil {
		return out, err
	}
	err := e.client.Do(ctx, "POST", e.path("organizations/"+organization+"/positions"), input, &out)
	return out, err
}

func (e Environment) DeletePosition(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "positions", id}, nil, nil)
}

func (e Environment) PositionAssignments(ctx context.Context, org string) ([]PositionAssignment, error) {
	return listOp[PositionAssignment](e, ctx, []string{"organizations", org, "position-assignments"})
}

func (e Environment) Positions(ctx context.Context, org string) ([]Position, error) {
	return listOp[Position](e, ctx, []string{"organizations", org, "positions"})
}

func (e Environment) UnassignPosition(ctx context.Context, org, id string) error {
	return e.operation(ctx, "DELETE", []string{"organizations", org, "position-assignments", id}, nil, nil)
}

func (e Environment) UpdatePosition(ctx context.Context, org, id string, input Position) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "positions", id}, input, nil)
}

func (e Environment) OrgChart(ctx context.Context, org string) ([]ReportingMember, error) {
	return listOp[ReportingMember](e, ctx, []string{"organizations", org, "org-chart"})
}

func (e Environment) OrgUnitTree(ctx context.Context, org string) ([]OrgUnit, error) {
	return listOp[OrgUnit](e, ctx, []string{"organizations", org, "tree"})
}

// DeleteSMSConfig removes the SMS provider; SMS codes stop being sent.
func (e Environment) DeleteSMSConfig(ctx context.Context) error {
	return e.client.Do(ctx, "DELETE", e.path("sms"), nil, nil)
}

// SMSConfig returns the SMS provider (apierror not found when none).
func (e Environment) SMSConfig(ctx context.Context) (SMSConfig, error) {
	var out SMSConfig
	err := e.client.Do(ctx, "GET", e.path("sms"), nil, &out)
	return out, err
}

// SMSStatus returns whether SMS is configured and its recent activity.
func (e Environment) SMSStatus(ctx context.Context) (SMSStatus, error) {
	var out SMSStatus
	err := e.client.Do(ctx, "GET", e.path("sms/status"), nil, &out)
	return out, err
}

// SetSMSConfig saves the SMS provider.
func (e Environment) SetSMSConfig(ctx context.Context, input SetSMSConfig) (SMSConfig, error) {
	var out SMSConfig
	err := e.client.Do(ctx, "PUT", e.path("sms"), input, &out)
	return out, err
}

// TestSMS texts a message without a code to phone (E.164). A failed
// delivery is returned as an attempt, not an error.
func (e Environment) TestSMS(ctx context.Context, phone string) (DeliveryAttempt, error) {
	var out DeliveryAttempt
	err := e.client.Do(ctx, "POST", e.path("sms/test"), map[string]string{"phone": phone}, &out)
	return out, err
}

// ResetUserFactors removes every second factor and recovery code of a user
// (lost device). Audited as mfa.reset.
func (e Environment) ResetUserFactors(ctx context.Context, user string) error {
	return e.operation(ctx, "DELETE", []string{"users", user, "factors"}, nil, nil)
}

// UserFactors lists a user's second factors (never secrets) and remaining
// recovery codes.
func (e Environment) UserFactors(ctx context.Context, user string) (UserFactors, error) {
	var out UserFactors
	err := e.operation(ctx, "GET", []string{"users", user, "factors"}, nil, &out)
	return out, err
}

// DeleteUserPermanently erases the user and everything referencing them
// (sessions, memberships, grants, factors, identities…). Irreversible:
// prefer SuspendUser or DeactivateUser unless the data must be erased.
func (e Environment) DeleteUserPermanently(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"users", id, "permanent"}, nil, nil)
}

// RequirePasswordChange makes the user's next password sign-in choose a
// new password (audited user.password_change_required).
func (e Environment) RequirePasswordChange(ctx context.Context, id string) error {
	return e.operation(ctx, "POST", []string{"users", id, "require-password-change"}, nil, nil)
}

// RevokeUserSessions signs a user out everywhere: every live session ends
// (audited user.sessions_revoked). It answers how many ended.
func (e Environment) RevokeUserSessions(ctx context.Context, id string) (int, error) {
	var out struct {
		Revoked int `json:"revoked"`
	}
	err := e.operation(ctx, "POST", []string{"users", id, "revoke-sessions"}, nil, &out)
	return out.Revoked, err
}

// Usage returns the usage of the last days (1 to 366, today included; 0
// asks for the server's default of 30).
func (e Environment) Usage(ctx context.Context, days int) (Usage, error) {
	var query url.Values
	if days != 0 {
		query = url.Values{"days": {strconv.Itoa(days)}}
	}
	var out Usage
	err := e.client.do(ctx, "GET", e.path("usage"), query, nil, &out)
	return out, err
}

// TestWebhook sends a webhook.test event now (never queued).
func (e Environment) TestWebhook(ctx context.Context, id string) (WebhookTest, error) {
	var out WebhookTest
	err := e.operation(ctx, "POST", []string{"webhooks", id, "test"}, map[string]any{}, &out)
	return out, err
}

// SetServiceAccountAuthentication changes how the account authenticates at
// /oauth/token (client_credentials).
func (e Environment) SetServiceAccountAuthentication(ctx context.Context, id string, input ClientAuthentication) (ServiceAccount, error) {
	var out ServiceAccount
	err := e.operation(ctx, "PUT", []string{"service-accounts", id, "authentication"}, input, &out)
	return out, err
}

func (e Environment) SetMemberProfile(ctx context.Context, org, user string, input MemberProfile) error {
	return e.operation(ctx, "PUT", []string{"organizations", org, "members", user, "profile"}, input, nil)
}

// UpdateMember changes a membership, e.g. the SSO break-glass bypass.
func (e Environment) UpdateMember(ctx context.Context, org, user string, input MemberPatch) error {
	return e.operation(ctx, "PATCH", []string{"organizations", org, "members", user}, input, nil)
}

func (e Environment) Grant(ctx context.Context, id string) (Grant, error) {
	var out Grant
	err := e.operation(ctx, "GET", []string{"grants", id}, nil, &out)
	return out, err
}

func (e Environment) Role(ctx context.Context, id string) (Role, error) {
	var out Role
	err := e.operation(ctx, "GET", []string{"roles", id}, nil, &out)
	return out, err
}

// ServiceAccount reads one service account (never its secret).
func (e Environment) ServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	var out ServiceAccount
	err := e.operation(ctx, "GET", []string{"service-accounts", id}, nil, &out)
	return out, err
}
