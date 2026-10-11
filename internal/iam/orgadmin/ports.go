package orgadmin

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
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
	// IssueDirectory creates a SCIM credential (and its provisioning
	// connection) for the organization; the secret is returned once.
	IssueDirectory(ctx context.Context, p Principal, input NewDirectory) (IssuedDirectory, error)
	// RevokeDirectory revokes a credential of the organization (404 for any
	// other).
	RevokeDirectory(ctx context.Context, p Principal, credential identity.CredentialID) error
	// CreateSetupLink and RevokeSetupLink manage the organization's setup
	// links; only owners (Principal.Owner).
	CreateSetupLink(ctx context.Context, p Principal, input SetupLinkInput) (IssuedSetupLink, error)
	RevokeSetupLink(ctx context.Context, p Principal, link identity.SetupLinkID) error
	// CreateAPIKey issues an organization API key (iam:org:api-keys:write;
	// users only: setup links cannot create keys). Permissions must also be
	// ones the administrator holds on the resource.
	CreateAPIKey(ctx context.Context, p Principal, input apikey.NewAPIKey) (apikey.Issued, error)
	// RevokeAPIKey revokes an organization key or a member's user key
	// (404 for any other, machine keys included).
	RevokeAPIKey(ctx context.Context, p Principal, key identity.APIKeyID) error
	// CreateLogStream creates a log stream of the organization (sources
	// audit_logs only); the https signing secret is returned once.
	// Needs iam:org:log-streams:write, as every method below.
	CreateLogStream(ctx context.Context, p Principal, input logstream.Create) (logstream.Created, error)
	UpdateLogStream(ctx context.Context, p Principal, stream identity.LogStreamID, input logstream.Update) (logstream.Stream, error)
	// EnableLogStream resumes a paused or failing stream.
	EnableLogStream(ctx context.Context, p Principal, stream identity.LogStreamID) (logstream.Stream, error)
	DeleteLogStream(ctx context.Context, p Principal, stream identity.LogStreamID) error
	RotateLogStreamSecret(ctx context.Context, p Principal, stream identity.LogStreamID) (logstream.Created, error)
	// TestLogStream sends one synthetic record to the destination now.
	TestLogStream(ctx context.Context, p Principal, stream identity.LogStreamID) (logstream.TestResult, error)
	RetryLogStreamDelivery(ctx context.Context, p Principal, stream identity.LogStreamID, delivery int64) error
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
	// Groups lists the organization's operator-managed (non-SCIM) groups:
	// the targets of an SSO connection's group mappings.
	Groups(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[organization.Group], error)
	Connections(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[federation.ConnectionView], error)
	Connection(ctx context.Context, p Principal, connection identity.ConnectionID) (federation.ConnectionDetail, error)
	Events(ctx context.Context, p Principal, filter EventFilter, page query.Pagination) (query.Paginated[Event], error)
	// Branding is the organization's branding overrides (every field null
	// when none).
	Branding(ctx context.Context, p Principal) (hosted.OrganizationSettings, error)
	// PasswordPolicy is what the organization adds to the environment's
	// password policy (custom false when nothing).
	PasswordPolicy(ctx context.Context, p Principal) (authentication.PasswordRequirements, error)
	// Directories lists the organization's SCIM credentials.
	Directories(ctx context.Context, p Principal, page query.Pagination) (Directories, error)
	// SetupLinks lists the organization's setup links (owners only).
	SetupLinks(ctx context.Context, p Principal, page query.Pagination) (query.Paginated[SetupLink], error)
	// AuditLogs lists the app audit log events of the organization
	// (iam:org:audit:read); filter.Organization is always the principal's.
	AuditLogs(ctx context.Context, p Principal, filter auditlog.Filter, limit int) (auditlog.Page, error)
	// ExportAuditLogs streams the matching events oldest first to write.
	ExportAuditLogs(ctx context.Context, p Principal, filter auditlog.Filter, write func(auditlog.Event) error) error
	// APIKeys, APIKey and APIKeyOptions read the organization's keys:
	// its own and its members' user keys, never machine keys
	// (iam:org:api-keys:read; options need write).
	APIKeys(ctx context.Context, p Principal, filter apikey.Filter, page query.Pagination) (query.Paginated[apikey.APIKey], error)
	APIKey(ctx context.Context, p Principal, key identity.APIKeyID) (apikey.APIKey, error)
	APIKeyOptions(ctx context.Context, p Principal) (apikey.Options, error)
	// LogStreams, LogStream and LogStreamDeliveries read the
	// organization's own streams (not the environment's): they need
	// iam:org:audit:read or iam:org:log-streams:write.
	LogStreams(ctx context.Context, p Principal) ([]logstream.Stream, error)
	LogStream(ctx context.Context, p Principal, stream identity.LogStreamID) (logstream.Stream, error)
	LogStreamDeliveries(ctx context.Context, p Principal, stream identity.LogStreamID, filter logstream.DeliveryFilter, page query.Pagination) (query.Paginated[logstream.Delivery], error)
}

// AuditLogs is what the organization administration reads of the app audit
// log (auditlog.EventQueries, narrowed).
type AuditLogs interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter auditlog.Filter, limit int) (auditlog.Page, error)
	Export(ctx context.Context, environment identity.EnvironmentID, filter auditlog.Filter, write func(auditlog.Event) error) error
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

// SetupLinkCommands issue and revoke an organization's setup links and
// exchange them. Callers check who may issue (operators by permission,
// owners through Commands.CreateSetupLink).
type SetupLinkCommands interface {
	// Create stores a link for the mutation's organization and returns its
	// URL, shown once. The organization must exist (404).
	Create(ctx context.Context, m SetupMutation, input SetupLinkInput) (IssuedSetupLink, error)
	// Revoke ends the link and, with it, every bearer exchanged from it.
	Revoke(ctx context.Context, m SetupMutation, link identity.SetupLinkID) error
	// Exchange trades a link secret for a short-lived bearer. Unknown,
	// expired and revoked links are one 401.
	Exchange(ctx context.Context, token string) (SetupSession, error)
}

// SetupLinkQueries read links and resolve their bearers.
type SetupLinkQueries interface {
	List(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[SetupLink], error)
	// Session resolves a bearer (ik_setupsess_…) while it and its link are
	// live; anything else is a 401.
	Session(ctx context.Context, bearer string) (SetupGrant, error)
}

// SetupSecrets generates and hashes setup secrets.
type SetupSecrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}

// SetupLinkRepository persists links and their bearers.
type SetupLinkRepository interface {
	// Create inserts the link (at most config.SetupLinkMaxPerOrg live ones
	// per organization) and audits it.
	Create(ctx context.Context, m SetupMutation, link SetupLink, hash []byte) error
	List(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[SetupLink], error)
	// Revoke sets revoked_at and audits it (404 when not live).
	Revoke(ctx context.Context, m SetupMutation, link identity.SetupLinkID) error
	// Exchange finds the live link by its secret hash, stamps last_used_at,
	// stores the bearer hash (expiring at the earlier of now+ttl and the
	// link) and audits org_setup_link.used.
	Exchange(ctx context.Context, hash, bearer []byte, ttl time.Duration) (SetupExchanged, error)
	// Session resolves a live bearer through its live link.
	Session(ctx context.Context, bearer []byte) (SetupGrant, error)
}
