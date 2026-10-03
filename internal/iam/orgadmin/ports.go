package orgadmin

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands are the organization administrator's changes. Each checks the
// principal's permission and the anti-escalation rules first.
type Commands interface {
	UpdateSettings(ctx context.Context, p Principal, input Settings) error
	CreateUser(ctx context.Context, p Principal, input NewUser) (identity.UserID, error)
	UpdateUser(ctx context.Context, p Principal, user identity.UserID, input UserChange) error
	SetUserActive(ctx context.Context, p Principal, user identity.UserID, active bool) error
	UnlockUser(ctx context.Context, p Principal, user identity.UserID) error
	UpdateMember(ctx context.Context, p Principal, user identity.UserID, input organization.MemberUpdate) error
	RemoveMember(ctx context.Context, p Principal, user identity.UserID) error
	AssignRole(ctx context.Context, p Principal, input Assignment) error
	UnassignRole(ctx context.Context, p Principal, input Assignment) error
	Invite(ctx context.Context, p Principal, input invitation.Input) (invitation.Issued, error)
	ResendInvitation(ctx context.Context, p Principal, invitation identity.InvitationID) (invitation.Issued, error)
	RevokeInvitation(ctx context.Context, p Principal, invitation identity.InvitationID) error
	AddDomain(ctx context.Context, p Principal, input organization.DomainInput) (organization.Domain, error)
	VerifyDomain(ctx context.Context, p Principal, domain identity.DomainID) (organization.Domain, error)
	DeleteDomain(ctx context.Context, p Principal, domain identity.DomainID) error
	CreateConnection(ctx context.Context, p Principal, input federation.ConnectionInput) (identity.ConnectionID, error)
	UpdateConnection(ctx context.Context, p Principal, connection identity.ConnectionID, input federation.ConnectionUpdate) error
	DisableConnection(ctx context.Context, p Principal, connection identity.ConnectionID) error
	EnableConnection(ctx context.Context, p Principal, connection identity.ConnectionID) error
	// PutResourceGrant grants one of the organization's own resources to
	// another organization.
	PutResourceGrant(ctx context.Context, p Principal, input authorization.ResourceGrantInput) (authorization.ResourceGrant, error)
	DeleteResourceGrant(ctx context.Context, p Principal, grant identity.ResourceGrantID) error
	// SaveBranding replaces the organization's hosted-page and invitation
	// branding overrides; DeleteBranding drops them.
	SaveBranding(ctx context.Context, p Principal, input hosted.OrganizationSettings) (hosted.OrganizationSettings, error)
	DeleteBranding(ctx context.Context, p Principal) error
	// SetPasswordPolicy replaces what the organization adds to the
	// environment's password policy; DeletePasswordPolicy drops it.
	SetPasswordPolicy(ctx context.Context, p Principal, input authentication.PasswordRequirements) (authentication.PasswordRequirements, error)
	DeletePasswordPolicy(ctx context.Context, p Principal) error
}

// Queries are the organization administrator's reads.
type Queries interface {
	Organization(ctx context.Context, p Principal) (organization.Organization, error)
	Members(ctx context.Context, p Principal, filter organization.MemberFilter, page query.Pagination) (query.Paginated[organization.MemberView], error)
	// Users lists the users homed in the organization.
	Users(ctx context.Context, p Principal, filter user.Filter, page query.Pagination) (query.Paginated[user.User], error)
	// User reads a member of the organization (without operator metadata).
	User(ctx context.Context, p Principal, user identity.UserID) (user.User, error)
	// Roles lists the roles the organization's administrators can assign:
	// the IAM resource's and those of owned or granted resources.
	Roles(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[Role], error)
	// Resources lists the resources the organization owns.
	Resources(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[authorization.Resource], error)
	// ResourceGrants lists the grants of the organization's own resources
	// (filter.Resource narrows it).
	ResourceGrants(ctx context.Context, p Principal, filter authorization.ResourceGrantFilter, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error)
	// GrantedResources lists the resource grants the organization received.
	GrantedResources(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error)
	RoleAssignments(ctx context.Context, p Principal, user identity.UserID, page query.Pagination) (query.Paginated[authorization.RoleAssignmentView], error)
	Invitations(ctx context.Context, p Principal, filter invitation.Filter, page query.Pagination) (query.Paginated[invitation.Invitation], error)
	Domains(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[organization.Domain], error)
	Connections(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[federation.ConnectionView], error)
	Connection(ctx context.Context, p Principal, connection identity.ConnectionID) (federation.ConnectionDetail, error)
	Events(ctx context.Context, p Principal, filter EventFilter, page query.Pagination) (query.Paginated[Event], error)
	// Branding is the organization's branding overrides (every field null
	// when none).
	Branding(ctx context.Context, p Principal) (hosted.OrganizationSettings, error)
	// PasswordPolicy is what the organization adds to the environment's
	// password policy (custom false when nothing).
	PasswordPolicy(ctx context.Context, p Principal) (authentication.PasswordRequirements, error)
}

// Repository reads what the anti-escalation rules need and the
// organization's audit events.
type Repository interface {
	// Roles returns the roles with their permissions, Granted as seen by
	// organization; unknown IDs are left out.
	Roles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, roles []identity.RoleID) ([]Role, error)
	// GroupRoles returns the roles the organization's groups carry.
	GroupRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, groups []identity.GroupID) ([]Role, error)
	// AssignableRoles lists the IAM resource's roles and the roles
	// organization owns or was granted.
	AssignableRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[Role], error)
	// OwnedResources lists the resources organization owns.
	OwnedResources(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[authorization.Resource], error)
	// Owners lists the active members holding the owner role and how.
	Owners(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) ([]Owner, error)
	// Member reports whether the user has a membership (active or not).
	Member(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) (bool, error)
	Events(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, filter EventFilter, page query.Pagination) (query.Paginated[Event], error)
}

// PortalCommands turn an environment's hosted organization admin portal on
// and off (operators).
type PortalCommands interface {
	// EnablePortal registers the portal's application and OAuth client the
	// first time and reactivates them afterwards.
	EnablePortal(ctx context.Context, m PortalMutation) (Portal, error)
	// DisablePortal deactivates them and ends the portal's sessions.
	DisablePortal(ctx context.Context, m PortalMutation) error
}

// PortalQueries read the portal's state.
type PortalQueries interface {
	Portal(ctx context.Context, environment identity.EnvironmentID) (Portal, error)
}

// PortalRepository persists the portal's application and OAuth client.
type PortalRepository interface {
	// Portal is the environment's portal (Enabled false when never enabled).
	Portal(ctx context.Context, environment identity.EnvironmentID) (Portal, error)
	// EnablePortal creates the application (linked to the IAM resource) and
	// the system client with the given IDs when none exists, otherwise
	// reactivates both and refreshes the client's redirect URIs; audited.
	EnablePortal(ctx context.Context, m PortalMutation, application identity.ApplicationID, client identity.ClientID, redirects PortalRedirects) (Portal, error)
	// DisablePortal deactivates the application and client and revokes
	// the client's sessions; audited. Not found when never enabled.
	DisablePortal(ctx context.Context, m PortalMutation) error
}
