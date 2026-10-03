// Package orgadminsvc implements orgadmin.Commands and orgadmin.Queries on
// top of the user, organization, authorization, invitation and federation
// modules.
package orgadminsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Deps are the modules the service delegates to.
type Deps struct {
	Repository          orgadmin.Repository
	Users               user.Commands
	UserQueries         user.Queries
	Organizations       organization.Commands
	OrganizationViews   organization.Queries
	Domains             organization.DomainCommands
	DomainViews         organization.DomainQueries
	Grants              authorization.GrantCommands
	GrantViews          authorization.GrantQueries
	ResourceViews       authorization.ResourceQueries
	ResourceGrants      authorization.ResourceGrantCommands
	ResourceGrantViews  authorization.ResourceGrantQueries
	Invitations         invitation.Commands
	InvitationViews     invitation.Queries
	Connections         federation.Commands
	ConnectionViews     federation.Queries
	Branding            hosted.Commands
	BrandingViews       hosted.Queries
	PasswordPolicies    authentication.PasswordPolicyCommands
	PasswordPolicyViews authentication.PasswordPolicyQueries
}

type Service struct{ d Deps }

var _ orgadmin.Commands = (*Service)(nil)
var _ orgadmin.Queries = (*Service)(nil)

func New(deps Deps) *Service { return &Service{d: deps} }

func boundary(p orgadmin.Principal) organization.Boundary {
	return organization.Boundary{Environment: p.Environment, Organization: p.Organization}
}
func orgMutation(p orgadmin.Principal) organization.Mutation {
	return organization.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}
func userMutation(p orgadmin.Principal) user.Mutation {
	return user.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

// Organization

func (s *Service) Organization(ctx context.Context, p orgadmin.Principal) (organization.Organization, error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return organization.Organization{}, err
	}
	org, err := s.d.OrganizationViews.Find(ctx, p.Environment, p.Organization)
	org.Metadata = nil // operators' data
	return org, err
}

func (s *Service) UpdateSettings(ctx context.Context, p orgadmin.Principal, input orgadmin.Settings) error {
	if err := p.Require(authorization.PermOrgSettingsWrite); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.d.Organizations.Update(ctx, orgMutation(p), p.Organization, input.Update())
}

// Members

func (s *Service) Members(ctx context.Context, p orgadmin.Principal, filter organization.MemberFilter, page query.Pagination) (query.Paginated[organization.MemberView], error) {
	if err := p.Require(authorization.PermOrgMembersRead); err != nil {
		return query.Paginated[organization.MemberView]{}, err
	}
	return s.d.OrganizationViews.Members(ctx, p.Environment, p.Organization, filter, page)
}

func (s *Service) UpdateMember(ctx context.Context, p orgadmin.Principal, member identity.UserID, input organization.MemberUpdate) error {
	if err := p.Require(authorization.PermOrgMembersWrite); err != nil {
		return err
	}
	if err := s.member(ctx, p, member); err != nil {
		return err
	}
	if _, _, err := s.owners(ctx, p, member); err != nil {
		return err
	}
	return s.d.Organizations.UpdateMember(ctx, orgMutation(p), p.Organization, member, input)
}

// RemoveMember ends a membership; the last owner cannot leave.
func (s *Service) RemoveMember(ctx context.Context, p orgadmin.Principal, member identity.UserID) error {
	if err := p.Require(authorization.PermOrgMembersWrite); err != nil {
		return err
	}
	if err := s.member(ctx, p, member); err != nil {
		return err
	}
	if err := s.keepOwner(ctx, p, member, false); err != nil {
		return err
	}
	return s.d.Organizations.RemoveMember(ctx, p.Environment, p.Organization, member)
}

// member refuses users outside the organization with NotFound, so other
// organizations' users stay invisible.
func (s *Service) member(ctx context.Context, p orgadmin.Principal, u identity.UserID) error {
	if u.IsZero() {
		return errx.NotFound("user not found")
	}
	ok, err := s.d.Repository.Member(ctx, p.Environment, p.Organization, u)
	if err != nil {
		return err
	}
	if !ok {
		return errx.NotFound("user not found")
	}
	return nil
}

// owners guards owners: only an owner acts on another owner. It returns
// the owner list and whether u is in it.
func (s *Service) owners(ctx context.Context, p orgadmin.Principal, u identity.UserID) (orgadmin.Owners, bool, error) {
	found, err := s.d.Repository.Owners(ctx, p.Environment, p.Organization)
	if err != nil {
		return nil, false, err
	}
	owners := orgadmin.Owners(found)
	if !owners.Includes(u) {
		return owners, false, nil
	}
	if !owners.Includes(p.User) {
		return owners, true, errx.Forbidden("only organization owners manage owners")
	}
	return owners, true, nil
}

// keepOwner also refuses a change that would leave the organization
// without an owner: removing the user (direct = false) or its direct owner
// role.
func (s *Service) keepOwner(ctx context.Context, p orgadmin.Principal, u identity.UserID, direct bool) error {
	owners, owner, err := s.owners(ctx, p, u)
	if err != nil || !owner {
		return err
	}
	if !owners.KeepsOwner(u, direct) {
		return errx.Business("the organization must keep at least one owner")
	}
	return nil
}

// Users

func (s *Service) Users(ctx context.Context, p orgadmin.Principal, filter user.Filter, page query.Pagination) (query.Paginated[user.User], error) {
	if err := p.Require(authorization.PermOrgMembersRead); err != nil {
		return query.Paginated[user.User]{}, err
	}
	filter.HomeOrganization = p.Organization
	out, err := s.d.UserQueries.List(ctx, p.Environment, filter, page)
	for i := range out.Items {
		out.Items[i].Metadata = nil // operators' data
	}
	return out, err
}

func (s *Service) User(ctx context.Context, p orgadmin.Principal, u identity.UserID) (user.User, error) {
	if err := p.Require(authorization.PermOrgMembersRead); err != nil {
		return user.User{}, err
	}
	if err := s.member(ctx, p, u); err != nil {
		return user.User{}, err
	}
	found, err := s.d.UserQueries.Find(ctx, p.Environment, u)
	found.Metadata = nil // operators' data
	return found, err
}

// CreateUser creates a user homed in (and a member of) the organization.
func (s *Service) CreateUser(ctx context.Context, p orgadmin.Principal, input orgadmin.NewUser) (identity.UserID, error) {
	if err := p.Require(authorization.PermOrgUsersWrite); err != nil {
		return identity.UserID{}, err
	}
	if err := input.Validate(); err != nil {
		return identity.UserID{}, err
	}
	return s.d.Users.Create(ctx, p.Environment, input.Create(p.Organization))
}

func (s *Service) UpdateUser(ctx context.Context, p orgadmin.Principal, u identity.UserID, input orgadmin.UserChange) error {
	if err := s.home(ctx, p, u); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.d.Users.Update(ctx, userMutation(p), u, input.Update())
}

// SetUserActive deactivates or reactivates a home user; the last owner
// stays active.
func (s *Service) SetUserActive(ctx context.Context, p orgadmin.Principal, u identity.UserID, active bool) error {
	if err := s.home(ctx, p, u); err != nil {
		return err
	}
	if active {
		return s.d.Users.Reactivate(ctx, userMutation(p), u)
	}
	if err := s.keepOwner(ctx, p, u, false); err != nil {
		return err
	}
	return s.d.Users.Deactivate(ctx, userMutation(p), u)
}

func (s *Service) UnlockUser(ctx context.Context, p orgadmin.Principal, u identity.UserID) error {
	if err := s.home(ctx, p, u); err != nil {
		return err
	}
	return s.d.Users.Unlock(ctx, userMutation(p), u)
}

// home allows user-record writes only for users homed in the organization:
// a user belonging to several organizations is not any one's to edit.
func (s *Service) home(ctx context.Context, p orgadmin.Principal, u identity.UserID) error {
	if err := p.Require(authorization.PermOrgUsersWrite); err != nil {
		return err
	}
	if err := s.member(ctx, p, u); err != nil {
		return err
	}
	found, err := s.d.UserQueries.Find(ctx, p.Environment, u)
	if err != nil {
		return err
	}
	if found.HomeOrganization == nil || *found.HomeOrganization != p.Organization {
		return errx.Forbidden("the user's record belongs to another organization or to the environment")
	}
	_, _, err = s.owners(ctx, p, u)
	return err
}

// Roles

func (s *Service) Roles(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[orgadmin.Role], error) {
	if err := p.Require(authorization.PermOrgRolesRead); err != nil {
		return query.Paginated[orgadmin.Role]{}, err
	}
	return s.d.Repository.AssignableRoles(ctx, p.Environment, p.Organization, page)
}

func (s *Service) RoleAssignments(ctx context.Context, p orgadmin.Principal, u identity.UserID, page query.Pagination) (query.Paginated[authorization.RoleAssignmentView], error) {
	if err := p.Require(authorization.PermOrgRolesRead); err != nil {
		return query.Paginated[authorization.RoleAssignmentView]{}, err
	}
	// A zero user would be no filter at all; a non-member is not found.
	if err := s.member(ctx, p, u); err != nil {
		return query.Paginated[authorization.RoleAssignmentView]{}, err
	}
	return s.d.GrantViews.RoleAssignments(ctx, p.Environment, authorization.RoleAssignmentFilter{OrganizationID: p.Organization, UserID: u}, page)
}

func (s *Service) AssignRole(ctx context.Context, p orgadmin.Principal, input orgadmin.Assignment) error {
	if err := s.assignable(ctx, p, input); err != nil {
		return err
	}
	return s.d.Grants.AssignRole(ctx, s.grantMutation(p), authorization.RoleAssignment{Organization: p.Organization, User: input.User, Role: input.Role}, false)
}

// UnassignRole removes a role. Only owners change an owner's roles, and
// the last owner keeps the owner role.
func (s *Service) UnassignRole(ctx context.Context, p orgadmin.Principal, input orgadmin.Assignment) error {
	if err := s.assignable(ctx, p, input); err != nil {
		return err
	}
	roles, err := s.d.Repository.Roles(ctx, p.Environment, p.Organization, []identity.RoleID{input.Role})
	if err != nil {
		return err
	}
	if roles[0].SystemRole == orgadmin.OwnerRole {
		err = s.keepOwner(ctx, p, input.User, true)
	} else {
		_, _, err = s.owners(ctx, p, input.User)
	}
	if err != nil {
		return err
	}
	return s.d.Grants.AssignRole(ctx, s.grantMutation(p), authorization.RoleAssignment{Organization: p.Organization, User: input.User, Role: input.Role}, true)
}

func (s *Service) grantMutation(p orgadmin.Principal) authorization.Mutation {
	return authorization.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

// assignable checks the permission, the member and the role (see
// orgadmin.Role.Assignable).
func (s *Service) assignable(ctx context.Context, p orgadmin.Principal, input orgadmin.Assignment) error {
	if err := p.Require(authorization.PermOrgRolesAssign); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	if err := s.member(ctx, p, input.User); err != nil {
		return err
	}
	return s.rolesAssignable(ctx, p, []identity.RoleID{input.Role}, nil)
}

// rolesAssignable checks roles, and the roles groups carry, against the
// principal (an invitation into a group grants the group's roles).
func (s *Service) rolesAssignable(ctx context.Context, p orgadmin.Principal, ids []identity.RoleID, groups []identity.GroupID) error {
	if len(ids) == 0 && len(groups) == 0 {
		return nil
	}
	var roles []orgadmin.Role
	if len(ids) > 0 {
		found, err := s.d.Repository.Roles(ctx, p.Environment, p.Organization, ids)
		if err != nil {
			return err
		}
		if len(found) != len(ids) {
			return errx.NotFound("role not found")
		}
		roles = found
	}
	if len(groups) > 0 {
		carried, err := s.d.Repository.GroupRoles(ctx, p.Environment, p.Organization, groups)
		if err != nil {
			return err
		}
		roles = append(roles, carried...)
	}
	var owners orgadmin.Owners
	for _, role := range roles {
		if role.SystemRole == orgadmin.OwnerRole && owners == nil {
			found, err := s.d.Repository.Owners(ctx, p.Environment, p.Organization)
			if err != nil {
				return err
			}
			owners = append(orgadmin.Owners{}, found...)
		}
		if err := role.Assignable(p, owners.Includes(p.User)); err != nil {
			return err
		}
	}
	return nil
}

// Resources

func (s *Service) Resources(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	if err := p.Require(authorization.PermOrgResourcesRead); err != nil {
		return query.Paginated[authorization.Resource]{}, err
	}
	return s.d.Repository.OwnedResources(ctx, p.Environment, p.Organization, page)
}

func (s *Service) ResourceGrants(ctx context.Context, p orgadmin.Principal, filter authorization.ResourceGrantFilter, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error) {
	if err := p.Require(authorization.PermOrgResourcesRead); err != nil {
		return query.Paginated[authorization.ResourceGrant]{}, err
	}
	filter.Owner = p.Organization
	return s.d.ResourceGrantViews.ListResourceGrants(ctx, p.Environment, filter, page)
}

func (s *Service) GrantedResources(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error) {
	if err := p.Require(authorization.PermOrgResourcesRead); err != nil {
		return query.Paginated[authorization.ResourceGrant]{}, err
	}
	return s.d.ResourceGrantViews.ListResourceGrants(ctx, p.Environment, authorization.ResourceGrantFilter{Organization: p.Organization}, page)
}

// owned finds a resource the organization owns; others are 404.
func (s *Service) owned(ctx context.Context, p orgadmin.Principal, id identity.ResourceID) error {
	if err := p.Require(authorization.PermOrgResourcesWrite); err != nil {
		return err
	}
	resource, err := s.d.ResourceViews.Find(ctx, p.Environment, id)
	if err != nil {
		return err
	}
	if resource.OwnerOrganization == nil || *resource.OwnerOrganization != p.Organization {
		return errx.NotFound("resource not found")
	}
	return nil
}

func (s *Service) PutResourceGrant(ctx context.Context, p orgadmin.Principal, input authorization.ResourceGrantInput) (authorization.ResourceGrant, error) {
	if err := input.Validate(); err != nil {
		return authorization.ResourceGrant{}, err
	}
	if err := s.owned(ctx, p, input.Resource); err != nil {
		return authorization.ResourceGrant{}, err
	}
	return s.d.ResourceGrants.PutResourceGrant(ctx, s.grantMutation(p), input)
}

func (s *Service) DeleteResourceGrant(ctx context.Context, p orgadmin.Principal, id identity.ResourceGrantID) error {
	if err := p.Require(authorization.PermOrgResourcesWrite); err != nil {
		return err
	}
	grant, err := s.d.ResourceGrantViews.FindResourceGrant(ctx, p.Environment, id)
	if err != nil {
		return err
	}
	if err := s.owned(ctx, p, grant.Resource); err != nil {
		return errx.NotFound("resource grant not found")
	}
	return s.d.ResourceGrants.DeleteResourceGrant(ctx, s.grantMutation(p), id)
}

// Invitations

func (s *Service) Invitations(ctx context.Context, p orgadmin.Principal, filter invitation.Filter, page query.Pagination) (query.Paginated[invitation.Invitation], error) {
	if err := p.Require(authorization.PermOrgMembersRead); err != nil {
		return query.Paginated[invitation.Invitation]{}, err
	}
	return s.d.InvitationViews.List(ctx, s.invitationBoundary(p), filter, page)
}

// Invite invites into the organization with roles and groups the principal
// may assign.
func (s *Service) Invite(ctx context.Context, p orgadmin.Principal, input invitation.Input) (invitation.Issued, error) {
	if err := p.Require(authorization.PermOrgInvitationsWrite); err != nil {
		return invitation.Issued{}, err
	}
	if (len(input.Roles) > 0 || len(input.Groups) > 0) && !p.Has(authorization.PermOrgRolesAssign) {
		return invitation.Issued{}, errx.Forbidden("missing permission: " + authorization.PermOrgRolesAssign)
	}
	if err := s.rolesAssignable(ctx, p, input.Roles, input.Groups); err != nil {
		return invitation.Issued{}, err
	}
	return s.d.Invitations.Invite(ctx, s.invitationBoundary(p), s.invitationMutation(p), input)
}

func (s *Service) ResendInvitation(ctx context.Context, p orgadmin.Principal, id identity.InvitationID) (invitation.Issued, error) {
	if err := s.invitation(ctx, p, id); err != nil {
		return invitation.Issued{}, err
	}
	return s.d.Invitations.Resend(ctx, s.invitationBoundary(p), s.invitationMutation(p), id)
}

func (s *Service) RevokeInvitation(ctx context.Context, p orgadmin.Principal, id identity.InvitationID) error {
	if err := p.Require(authorization.PermOrgInvitationsWrite); err != nil {
		return err
	}
	return s.d.Invitations.Revoke(ctx, s.invitationBoundary(p), s.invitationMutation(p), id)
}

// invitation re-checks a resent invitation's roles: resending one an
// operator made must not let a lesser administrator re-grant them.
func (s *Service) invitation(ctx context.Context, p orgadmin.Principal, id identity.InvitationID) error {
	if err := p.Require(authorization.PermOrgInvitationsWrite); err != nil {
		return err
	}
	inv, err := s.d.InvitationViews.Find(ctx, s.invitationBoundary(p), id)
	if err != nil {
		return err
	}
	return s.rolesAssignable(ctx, p, inv.Roles, inv.Groups)
}

func (s *Service) invitationBoundary(p orgadmin.Principal) invitation.Boundary {
	return invitation.Boundary{Environment: p.Environment, Organization: p.Organization}
}
func (s *Service) invitationMutation(p orgadmin.Principal) invitation.Mutation {
	return invitation.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

// Domains

func (s *Service) Domains(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[organization.Domain], error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return query.Paginated[organization.Domain]{}, err
	}
	return s.d.DomainViews.ListDomains(ctx, boundary(p), page)
}

func (s *Service) AddDomain(ctx context.Context, p orgadmin.Principal, input organization.DomainInput) (organization.Domain, error) {
	if err := p.Require(authorization.PermOrgDomainsWrite); err != nil {
		return organization.Domain{}, err
	}
	return s.d.Domains.AddDomain(ctx, boundary(p), orgMutation(p), input)
}

// VerifyDomain checks DNS; organization administrators cannot force it.
func (s *Service) VerifyDomain(ctx context.Context, p orgadmin.Principal, domain identity.DomainID) (organization.Domain, error) {
	if err := p.Require(authorization.PermOrgDomainsWrite); err != nil {
		return organization.Domain{}, err
	}
	return s.d.Domains.VerifyDomain(ctx, boundary(p), orgMutation(p), domain)
}

func (s *Service) DeleteDomain(ctx context.Context, p orgadmin.Principal, domain identity.DomainID) error {
	if err := p.Require(authorization.PermOrgDomainsWrite); err != nil {
		return err
	}
	return s.d.Domains.DeleteDomain(ctx, boundary(p), orgMutation(p), domain)
}

// Connections

func (s *Service) Connections(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[federation.ConnectionView], error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return query.Paginated[federation.ConnectionView]{}, err
	}
	return s.d.ConnectionViews.List(ctx, p.Environment, federation.ConnectionFilter{Organization: p.Organization}, page)
}

func (s *Service) Connection(ctx context.Context, p orgadmin.Principal, id identity.ConnectionID) (federation.ConnectionDetail, error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return federation.ConnectionDetail{}, err
	}
	return s.connection(ctx, p, id)
}

// connection finds the organization's connection; others are NotFound.
func (s *Service) connection(ctx context.Context, p orgadmin.Principal, id identity.ConnectionID) (federation.ConnectionDetail, error) {
	if id.IsZero() {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	c, err := s.d.ConnectionViews.Connection(ctx, p.Environment, id)
	if err != nil {
		return c, err
	}
	if c.Organization == nil || *c.Organization != p.Organization {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	c.SecretEnv = ""
	return c, nil
}

// CreateConnection creates an SSO connection of the organization. Secrets
// are sealed values only: secret_env would read the server's environment.
func (s *Service) CreateConnection(ctx context.Context, p orgadmin.Principal, input federation.ConnectionInput) (identity.ConnectionID, error) {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return identity.ConnectionID{}, err
	}
	if !input.Organization.IsZero() && input.Organization != p.Organization {
		return identity.ConnectionID{}, errx.Validation("organization_id must be your organization")
	}
	input.Organization = p.Organization
	if input.SecretEnv != "" {
		return identity.ConnectionID{}, errx.Validation("secret_env is not available to organization administrators; send client_secret")
	}
	if !input.SignupOrganization.IsZero() && input.SignupOrganization != p.Organization {
		return identity.ConnectionID{}, errx.Validation("signup_organization_id must be your organization")
	}
	return s.d.Connections.Create(ctx, s.federationMutation(p), input)
}

func (s *Service) UpdateConnection(ctx context.Context, p orgadmin.Principal, id identity.ConnectionID, input federation.ConnectionUpdate) error {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return err
	}
	if _, err := s.connection(ctx, p, id); err != nil {
		return err
	}
	if input.SignupOrganization != nil && !input.SignupOrganization.IsZero() && *input.SignupOrganization != p.Organization {
		return errx.Validation("signup_organization_id must be your organization")
	}
	return s.d.Connections.Update(ctx, s.federationMutation(p), id, input)
}

func (s *Service) DisableConnection(ctx context.Context, p orgadmin.Principal, id identity.ConnectionID) error {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return err
	}
	if _, err := s.connection(ctx, p, id); err != nil {
		return err
	}
	return s.d.Connections.Disable(ctx, s.federationMutation(p), id)
}

func (s *Service) EnableConnection(ctx context.Context, p orgadmin.Principal, id identity.ConnectionID) error {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return err
	}
	c, err := s.connection(ctx, p, id)
	if err != nil {
		return err
	}
	if c.SecretSource == "env" {
		return errx.Forbidden("this connection reads a deployment secret (secret_env); an operator must enable it")
	}
	return s.d.Connections.Enable(ctx, s.federationMutation(p), id)
}

func (s *Service) federationMutation(p orgadmin.Principal) federation.Mutation {
	return federation.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

// Audit

func (s *Service) Events(ctx context.Context, p orgadmin.Principal, filter orgadmin.EventFilter, page query.Pagination) (query.Paginated[orgadmin.Event], error) {
	if err := p.Require(authorization.PermOrgAuditRead); err != nil {
		return query.Paginated[orgadmin.Event]{}, err
	}
	if err := filter.Validate(); err != nil {
		return query.Paginated[orgadmin.Event]{}, err
	}
	return s.d.Repository.Events(ctx, p.Environment, p.Organization, filter, page)
}
