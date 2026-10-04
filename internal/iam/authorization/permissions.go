package authorization

// IAM resource permissions. These are the permissions assignable to service
// accounts when the resource is the built-in IAM resource. They control access
// to the /api/v1/* route group.
const (
	PermUsersRead            = "iam:users:read"
	PermUsersWrite           = "iam:users:write"
	PermOrgsRead             = "iam:orgs:read"
	PermOrgsWrite            = "iam:orgs:write"
	PermMembersRead          = "iam:members:read"
	PermMembersWrite         = "iam:members:write"
	PermAppsRead             = "iam:apps:read"
	PermAppsWrite            = "iam:apps:write"
	PermResourcesRead        = "iam:resources:read"
	PermResourcesWrite       = "iam:resources:write"
	PermRolesRead            = "iam:roles:read"
	PermRolesWrite           = "iam:roles:write"
	PermGrantsRead           = "iam:grants:read"
	PermGrantsWrite          = "iam:grants:write"
	PermServiceAccountsRead  = "iam:service-accounts:read"
	PermServiceAccountsWrite = "iam:service-accounts:write"
	PermDeliveryRead         = "iam:delivery:read"
	PermDeliveryWrite        = "iam:delivery:write"
	// PermEventsRead reads the environment's event log.
	PermEventsRead = "iam:events:read"
	// PermWebhooksRead / PermWebhooksWrite manage event webhook
	// subscriptions.
	PermWebhooksRead  = "iam:webhooks:read"
	PermWebhooksWrite = "iam:webhooks:write"
	// PermUsageRead reads the environment's usage and limits.
	PermUsageRead = "iam:usage:read"
)

// Organization-bound permissions. They only open the
// /organizations/:organization/admin routes of the organization the token
// was issued in (see orgadmin); iam:* permissions above stay
// environment-wide.
const (
	PermOrgRead             = "iam:org:read"
	PermOrgSettingsWrite    = "iam:org:settings:write"
	PermOrgMembersRead      = "iam:org:members:read"
	PermOrgMembersWrite     = "iam:org:members:write"
	PermOrgUsersWrite       = "iam:org:users:write"
	PermOrgRolesRead        = "iam:org:roles:read"
	PermOrgRolesAssign      = "iam:org:roles:assign"
	PermOrgInvitationsWrite = "iam:org:invitations:write"
	PermOrgDomainsWrite     = "iam:org:domains:write"
	PermOrgSSOWrite         = "iam:org:sso:write"
	PermOrgAuditRead        = "iam:org:audit:read"
	// Resources the organization owns (resources.owner_organization_id)
	// and their grants to other organizations.
	PermOrgResourcesRead  = "iam:org:resources:read"
	PermOrgResourcesWrite = "iam:org:resources:write"
)

// OrgPermissions lists every organization-bound permission.
var OrgPermissions = []string{
	PermOrgRead, PermOrgSettingsWrite,
	PermOrgMembersRead, PermOrgMembersWrite, PermOrgUsersWrite,
	PermOrgRolesRead, PermOrgRolesAssign,
	PermOrgInvitationsWrite, PermOrgDomainsWrite,
	PermOrgSSOWrite, PermOrgAuditRead,
	PermOrgResourcesRead, PermOrgResourcesWrite,
}

// IAMResourcePermissions is the canonical list of all built-in IAM resource
// permissions. Used when provisioning the system IAM resource for new
// environments and kept in sync with the constants above.
var IAMResourcePermissions = append([]string{
	PermUsersRead, PermUsersWrite,
	PermOrgsRead, PermOrgsWrite,
	PermMembersRead, PermMembersWrite,
	PermAppsRead, PermAppsWrite,
	PermResourcesRead, PermResourcesWrite,
	PermRolesRead, PermRolesWrite,
	PermGrantsRead, PermGrantsWrite,
	PermServiceAccountsRead, PermServiceAccountsWrite,
	PermDeliveryRead, PermDeliveryWrite,
	PermEventsRead,
	PermWebhooksRead, PermWebhooksWrite,
	PermUsageRead,
}, OrgPermissions...)

// Built-in roles of the IAM resource (roles.system_role). Every environment
// has them; they cannot be edited or deleted.
const (
	SystemRoleOrgOwner           = "org_owner"
	SystemRoleOrgViewer          = "org_viewer"
	SystemRoleOrgUserManager     = "org_user_manager"
	SystemRoleOrgSettingsManager = "org_settings_manager"
	SystemRoleOrgResourceManager = "org_resource_manager"
)

// SystemRole is a built-in role definition.
type SystemRole struct {
	Key         string
	Name        string
	Permissions []string
}

// SystemRoles are the built-in roles created on every IAM resource.
var SystemRoles = []SystemRole{
	{SystemRoleOrgOwner, "Organization owner", OrgPermissions},
	{SystemRoleOrgViewer, "Organization viewer", []string{PermOrgRead, PermOrgMembersRead, PermOrgRolesRead}},
	{SystemRoleOrgUserManager, "User manager", []string{PermOrgRead, PermOrgMembersRead, PermOrgMembersWrite, PermOrgUsersWrite,
		PermOrgRolesRead, PermOrgRolesAssign, PermOrgInvitationsWrite}},
	{SystemRoleOrgSettingsManager, "Settings manager", []string{PermOrgRead, PermOrgSettingsWrite, PermOrgDomainsWrite, PermOrgSSOWrite}},
	{SystemRoleOrgResourceManager, "Resource manager", []string{PermOrgRead, PermOrgResourcesRead, PermOrgResourcesWrite}},
}
