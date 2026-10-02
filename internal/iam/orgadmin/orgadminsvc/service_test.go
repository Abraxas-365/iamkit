package orgadminsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

var (
	env      = identity.MustParseEnvironmentID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")
	org      = identity.MustParseOrganizationID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a02")
	otherOrg = identity.MustParseOrganizationID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a03")
	owner    = identity.MustParseUserID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a04")
	manager  = identity.MustParseUserID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a05")
	member   = identity.MustParseUserID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a06")
	outsider = identity.MustParseUserID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a07")
	guest    = identity.MustParseUserID("0e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a08")

	ownerRole   = identity.MustParseRoleID("1e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")
	viewerRole  = identity.MustParseRoleID("1e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a02")
	powerRole   = identity.MustParseRoleID("1e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a03")
	appRole     = identity.MustParseRoleID("1e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a04")
	grantedRole = identity.MustParseRoleID("1e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a05")
	ownedRes    = identity.MustParseResourceID("3e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")
	foreignRes  = identity.MustParseResourceID("3e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a02")
	ownedGrant  = identity.MustParseResourceGrantID("4e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")
	otherGrant  = identity.MustParseResourceGrantID("4e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a02")
	ownersGroup = identity.MustParseGroupID("2e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")

	userManager = []string{authorization.PermOrgRead, authorization.PermOrgMembersRead, authorization.PermOrgMembersWrite,
		authorization.PermOrgUsersWrite, authorization.PermOrgRolesRead, authorization.PermOrgRolesAssign, authorization.PermOrgInvitationsWrite}
)

type repo struct{ owners []orgadmin.Owner }

var roles = map[identity.RoleID]orgadmin.Role{
	ownerRole:  {ID: ownerRole, IAM: true, SystemRole: orgadmin.OwnerRole, Permissions: authorization.OrgPermissions},
	viewerRole: {ID: viewerRole, IAM: true, SystemRole: "org_viewer", Permissions: []string{authorization.PermOrgRead, authorization.PermOrgMembersRead}},
	powerRole:  {ID: powerRole, IAM: true, Permissions: []string{authorization.PermOrgRead, "iam:users:write"}},
	appRole:    {ID: appRole, IAM: false, Permissions: []string{"crm:read"}},
	// A resource granted to the organization: assignable whatever the
	// administrator's own permissions.
	grantedRole: {ID: grantedRole, Granted: true, Permissions: []string{"crm:admin"}},
}

func (r *repo) Roles(_ context.Context, _ identity.EnvironmentID, _ identity.OrganizationID, ids []identity.RoleID) ([]orgadmin.Role, error) {
	out := []orgadmin.Role{}
	for _, id := range ids {
		if role, ok := roles[id]; ok {
			out = append(out, role)
		}
	}
	return out, nil
}
func (r *repo) GroupRoles(_ context.Context, _ identity.EnvironmentID, _ identity.OrganizationID, groups []identity.GroupID) ([]orgadmin.Role, error) {
	if len(groups) == 1 && groups[0] == ownersGroup {
		return []orgadmin.Role{roles[ownerRole]}, nil
	}
	return nil, nil
}
func (r *repo) OwnedResources(context.Context, identity.EnvironmentID, identity.OrganizationID, query.Pagination) (query.Paginated[authorization.Resource], error) {
	return query.Paginated[authorization.Resource]{}, nil
}
func (r *repo) AssignableRoles(context.Context, identity.EnvironmentID, identity.OrganizationID, query.Pagination) (query.Paginated[orgadmin.Role], error) {
	return query.Paginated[orgadmin.Role]{}, nil
}
func (r *repo) Owners(context.Context, identity.EnvironmentID, identity.OrganizationID) ([]orgadmin.Owner, error) {
	return r.owners, nil
}
func (r *repo) Member(_ context.Context, _ identity.EnvironmentID, _ identity.OrganizationID, u identity.UserID) (bool, error) {
	return u != outsider, nil
}
func (r *repo) Events(context.Context, identity.EnvironmentID, identity.OrganizationID, orgadmin.EventFilter, query.Pagination) (query.Paginated[orgadmin.Event], error) {
	return query.Paginated[orgadmin.Event]{}, nil
}

// grants records role assignment calls.
type grants struct {
	authorization.GrantCommands
	calls []authorization.RoleAssignment
}

func (g *grants) AssignRole(_ context.Context, _ authorization.Mutation, input authorization.RoleAssignment, _ bool) error {
	g.calls = append(g.calls, input)
	return nil
}

type users struct {
	user.Commands
	user.Queries
	created []user.Create
	updated int
}

func (u *users) Create(_ context.Context, _ identity.EnvironmentID, input user.Create) (identity.UserID, error) {
	u.created = append(u.created, input)
	return identity.NewUserID(), nil
}
func (u *users) Update(context.Context, user.Mutation, identity.UserID, user.Update) error {
	u.updated++
	return nil
}
func (u *users) Deactivate(context.Context, user.Mutation, identity.UserID) error {
	u.updated++
	return nil
}
func (u *users) Find(_ context.Context, _ identity.EnvironmentID, id identity.UserID) (user.User, error) {
	home := org
	if id == guest {
		home = otherOrg
	}
	return user.User{ID: id, HomeOrganization: &home, Metadata: []byte(`{"tier":"gold"}`)}, nil
}

type invitations struct {
	invitation.Commands
	invitation.Queries
	invited int
	stored  invitation.Invitation
}

func (i *invitations) Invite(context.Context, invitation.Boundary, invitation.Mutation, invitation.Input) (invitation.Issued, error) {
	i.invited++
	return invitation.Issued{}, nil
}
func (i *invitations) Find(context.Context, invitation.Boundary, identity.InvitationID) (invitation.Invitation, error) {
	return i.stored, nil
}
func (i *invitations) Resend(context.Context, invitation.Boundary, invitation.Mutation, identity.InvitationID) (invitation.Issued, error) {
	i.invited++
	return invitation.Issued{}, nil
}

type connections struct {
	federation.Commands
	federation.Queries
	created []federation.ConnectionInput
	detail  federation.ConnectionDetail
}

func (c *connections) Create(_ context.Context, _ federation.Mutation, input federation.ConnectionInput) (identity.ConnectionID, error) {
	c.created = append(c.created, input)
	return identity.NewConnectionID(), nil
}
func (c *connections) Connection(context.Context, identity.EnvironmentID, identity.ConnectionID) (federation.ConnectionDetail, error) {
	return c.detail, nil
}
func (c *connections) Disable(context.Context, federation.Mutation, identity.ConnectionID) error {
	return nil
}

// resources fakes resource ownership (ownedRes belongs to org) and records
// resource grant calls.
type resources struct {
	authorization.ResourceQueries
	authorization.ResourceGrantCommands
	authorization.ResourceGrantQueries
	put     []authorization.ResourceGrantInput
	deleted []identity.ResourceGrantID
}

func (r *resources) Find(_ context.Context, _ identity.EnvironmentID, id identity.ResourceID) (authorization.Resource, error) {
	owner := otherOrg
	if id == ownedRes {
		owner = org
	}
	return authorization.Resource{ID: id, OwnerOrganization: &owner}, nil
}
func (r *resources) PutResourceGrant(_ context.Context, _ authorization.Mutation, input authorization.ResourceGrantInput) (authorization.ResourceGrant, error) {
	r.put = append(r.put, input)
	return authorization.ResourceGrant{}, nil
}
func (r *resources) DeleteResourceGrant(_ context.Context, _ authorization.Mutation, id identity.ResourceGrantID) error {
	r.deleted = append(r.deleted, id)
	return nil
}
func (r *resources) FindResourceGrant(_ context.Context, _ identity.EnvironmentID, id identity.ResourceGrantID) (authorization.ResourceGrant, error) {
	resource := foreignRes
	if id == ownedGrant {
		resource = ownedRes
	}
	return authorization.ResourceGrant{ID: id, Resource: resource}, nil
}

type fixture struct {
	*Service
	repo        *repo
	grants      *grants
	users       *users
	invitations *invitations
	connections *connections
	resources   *resources
}

func newFixture(owners ...orgadmin.Owner) fixture {
	f := fixture{repo: &repo{owners: owners}, grants: &grants{}, users: &users{}, invitations: &invitations{}, connections: &connections{}, resources: &resources{}}
	f.Service = New(Deps{Repository: f.repo, Grants: f.grants, Users: f.users, UserQueries: f.users,
		Invitations: f.invitations, InvitationViews: f.invitations, Connections: f.connections, ConnectionViews: f.connections,
		ResourceViews: f.resources, ResourceGrants: f.resources, ResourceGrantViews: f.resources})
	return f
}

func principal(u identity.UserID, permissions ...string) orgadmin.Principal {
	return orgadmin.Principal{Environment: env, Organization: org, User: u, Permissions: permissions}
}

func kind(t *testing.T, err error, want int) {
	t.Helper()
	var e *errx.Error
	if err == nil || !errx.As(err, &e) || e.HTTPStatus != want {
		t.Fatalf("got %v, want %d", err, want)
	}
}

var ctx = context.Background()

func TestAssignRoleNeedsPermissionsHeld(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true})
	p := principal(manager, userManager...)

	if err := f.AssignRole(ctx, p, orgadmin.Assignment{User: member, Role: viewerRole}); err != nil {
		t.Fatalf("viewer role within the manager's permissions refused: %v", err)
	}
	kind(t, f.AssignRole(ctx, p, orgadmin.Assignment{User: member, Role: powerRole}), 403)
	kind(t, f.AssignRole(ctx, p, orgadmin.Assignment{User: member, Role: ownerRole}), 403)
	kind(t, f.AssignRole(ctx, p, orgadmin.Assignment{User: member, Role: appRole}), 403)
	kind(t, f.AssignRole(ctx, p, orgadmin.Assignment{User: outsider, Role: viewerRole}), 404)
	kind(t, f.AssignRole(ctx, principal(manager, authorization.PermOrgRead), orgadmin.Assignment{User: member, Role: viewerRole}), 403)
	if err := f.AssignRole(ctx, p, orgadmin.Assignment{User: member, Role: grantedRole}); err != nil {
		t.Fatalf("role of a granted resource refused: %v", err)
	}
	if len(f.grants.calls) != 2 || f.grants.calls[0].Organization != org {
		t.Fatalf("assignments reaching authorization: %+v", f.grants.calls)
	}
}

func TestOwnerRoleOnlyByOwners(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true})
	// A non-owner holding every permission still cannot grant ownership.
	kind(t, f.AssignRole(ctx, principal(manager, authorization.OrgPermissions...), orgadmin.Assignment{User: member, Role: ownerRole}), 403)
	if err := f.AssignRole(ctx, principal(owner, authorization.OrgPermissions...), orgadmin.Assignment{User: member, Role: ownerRole}); err != nil {
		t.Fatalf("owner granting ownership: %v", err)
	}
}

func TestLastOwnerStays(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true})
	p := principal(owner, authorization.OrgPermissions...)
	kind(t, f.UnassignRole(ctx, p, orgadmin.Assignment{User: owner, Role: ownerRole}), 422)
	kind(t, f.RemoveMember(ctx, p, owner), 422)
	kind(t, f.SetUserActive(ctx, p, owner, false), 422)
	if len(f.grants.calls) != 0 || f.users.updated != 0 {
		t.Fatal("last owner change reached the modules")
	}

	// With a second owner, or ownership also held through a group, it goes.
	f = newFixture(orgadmin.Owner{User: owner, Direct: true}, orgadmin.Owner{User: member, Direct: true})
	if err := f.UnassignRole(ctx, p, orgadmin.Assignment{User: owner, Role: ownerRole}); err != nil {
		t.Fatal(err)
	}
	f = newFixture(orgadmin.Owner{User: owner, Direct: true, Group: true})
	if err := f.UnassignRole(ctx, p, orgadmin.Assignment{User: owner, Role: ownerRole}); err != nil {
		t.Fatalf("owner through a group losing the direct role: %v", err)
	}
	kind(t, f.RemoveMember(ctx, p, owner), 422)
}

func TestNonOwnersCannotTouchOwners(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true}, orgadmin.Owner{User: member, Direct: true})
	p := principal(manager, userManager...)
	kind(t, f.RemoveMember(ctx, p, owner), 403)
	kind(t, f.SetUserActive(ctx, p, owner, false), 403)
	kind(t, f.UpdateUser(ctx, p, owner, orgadmin.UserChange{Name: new("x")}), 403)
	kind(t, f.UnassignRole(ctx, p, orgadmin.Assignment{User: owner, Role: viewerRole}), 403)
}

func TestUserWritesOnlyForHomeUsers(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true})
	p := principal(manager, userManager...)
	name := "New name"
	if err := f.UpdateUser(ctx, p, member, orgadmin.UserChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	kind(t, f.UpdateUser(ctx, p, guest, orgadmin.UserChange{Name: &name}), 403)
	kind(t, f.UpdateUser(ctx, p, outsider, orgadmin.UserChange{Name: &name}), 404)
	kind(t, f.UpdateUser(ctx, principal(manager, authorization.PermOrgMembersWrite), member, orgadmin.UserChange{Name: &name}), 403)

	got, err := f.User(ctx, p, member)
	if err != nil || got.Metadata != nil {
		t.Fatalf("user read leaked operator metadata: %v %s", err, got.Metadata)
	}

	if _, err := f.CreateUser(ctx, p, orgadmin.NewUser{Email: "new@example.com", Name: "New"}); err != nil {
		t.Fatal(err)
	}
	if len(f.users.created) != 1 || f.users.created[0].HomeOrganization != org {
		t.Fatalf("created user not homed in the organization: %+v", f.users.created)
	}
}

func TestInvitationRolesChecked(t *testing.T) {
	f := newFixture(orgadmin.Owner{User: owner, Direct: true})
	p := principal(manager, userManager...)
	if _, err := f.Invite(ctx, p, invitation.Input{Email: "a@example.com", Roles: []identity.RoleID{viewerRole}}); err != nil {
		t.Fatal(err)
	}
	_, err := f.Invite(ctx, p, invitation.Input{Email: "a@example.com", Roles: []identity.RoleID{powerRole}})
	kind(t, err, 403)
	_, err = f.Invite(ctx, p, invitation.Input{Email: "a@example.com", Groups: []identity.GroupID{ownersGroup}})
	kind(t, err, 403)
	// Inviting with roles needs iam:org:roles:assign.
	_, err = f.Invite(ctx, principal(manager, authorization.PermOrgInvitationsWrite), invitation.Input{Email: "a@example.com", Roles: []identity.RoleID{viewerRole}})
	kind(t, err, 403)
	if _, err = f.Invite(ctx, principal(manager, authorization.PermOrgInvitationsWrite), invitation.Input{Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	// Resending an operator's invitation re-checks its roles.
	f.invitations.stored = invitation.Invitation{Roles: []identity.RoleID{ownerRole}}
	_, err = f.ResendInvitation(ctx, p, identity.NewInvitationID())
	kind(t, err, 403)
	if f.invitations.invited != 2 {
		t.Fatalf("invitations sent: %d", f.invitations.invited)
	}
}

func TestConnectionsStayInTheOrganization(t *testing.T) {
	f := newFixture()
	p := principal(manager, authorization.PermOrgSSOWrite, authorization.PermOrgRead)
	_, err := f.CreateConnection(ctx, p, federation.ConnectionInput{Name: "x", SecretEnv: "DATABASE_URL"})
	kind(t, err, 400)
	_, err = f.CreateConnection(ctx, p, federation.ConnectionInput{Name: "x", Organization: otherOrg})
	kind(t, err, 400)
	_, err = f.CreateConnection(ctx, p, federation.ConnectionInput{Name: "x", SignupOrganization: otherOrg})
	kind(t, err, 400)
	if _, err = f.CreateConnection(ctx, p, federation.ConnectionInput{Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if f.connections.created[0].Organization != org {
		t.Fatalf("connection not bound to the organization: %+v", f.connections.created[0])
	}

	// Another organization's (or the environment's) connection is invisible.
	f.connections.detail = federation.ConnectionDetail{}
	f.connections.detail.Organization = &otherOrg
	_, err = f.Connection(ctx, p, identity.NewConnectionID())
	kind(t, err, 404)
	kind(t, f.DisableConnection(ctx, p, identity.NewConnectionID()), 404)
	f.connections.detail.Organization = nil
	_, err = f.Connection(ctx, p, identity.NewConnectionID())
	kind(t, err, 404)

	f.connections.detail.Organization = &org
	f.connections.detail.SecretEnv = "OKTA_SECRET"
	got, err := f.Connection(ctx, p, identity.NewConnectionID())
	if err != nil || got.SecretEnv != "" {
		t.Fatalf("own connection: %v, secret_env %q", err, got.SecretEnv)
	}
}

func TestEventsNeedAuditPermission(t *testing.T) {
	f := newFixture()
	_, err := f.Events(ctx, principal(manager, userManager...), orgadmin.EventFilter{}, query.Pagination{Limit: 10})
	kind(t, err, 403)
	_, err = f.Events(ctx, principal(manager, authorization.PermOrgAuditRead), orgadmin.EventFilter{Action: "user%"}, query.Pagination{Limit: 10})
	kind(t, err, 400)
}

func TestResourceGrantsOnlyForOwnedResources(t *testing.T) {
	f := newFixture()
	writer := principal(manager, authorization.PermOrgResourcesRead, authorization.PermOrgResourcesWrite)

	if _, err := f.PutResourceGrant(ctx, writer, authorization.ResourceGrantInput{Resource: ownedRes, Organization: otherOrg}); err != nil {
		t.Fatalf("grant of an owned resource refused: %v", err)
	}
	_, err := f.PutResourceGrant(ctx, writer, authorization.ResourceGrantInput{Resource: foreignRes, Organization: org})
	kind(t, err, 404)
	_, err = f.PutResourceGrant(ctx, principal(manager, authorization.PermOrgResourcesRead), authorization.ResourceGrantInput{Resource: ownedRes, Organization: otherOrg})
	kind(t, err, 403)
	_, err = f.PutResourceGrant(ctx, writer, authorization.ResourceGrantInput{Resource: ownedRes})
	kind(t, err, 400)

	if err := f.DeleteResourceGrant(ctx, writer, ownedGrant); err != nil {
		t.Fatalf("revoking a grant of an owned resource refused: %v", err)
	}
	kind(t, f.DeleteResourceGrant(ctx, writer, otherGrant), 404)
	kind(t, f.DeleteResourceGrant(ctx, principal(manager, authorization.PermOrgResourcesRead), ownedGrant), 403)
	if len(f.resources.put) != 1 || len(f.resources.deleted) != 1 || f.resources.deleted[0] != ownedGrant {
		t.Fatalf("calls reaching authorization: put %+v deleted %+v", f.resources.put, f.resources.deleted)
	}
	_, err = f.GrantedResources(ctx, principal(manager, authorization.PermOrgRead), query.Pagination{})
	kind(t, err, 403)
}
