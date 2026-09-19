package authorization

// IAM resource permissions. These are the permissions assignable to service
// accounts when the resource is the built-in IAM resource. They control access
// to the /api/v1/* route group.
const (
	PermUsersRead    = "iam:users:read"
	PermUsersWrite   = "iam:users:write"
	PermOrgsRead     = "iam:orgs:read"
	PermOrgsWrite    = "iam:orgs:write"
	PermMembersRead  = "iam:members:read"
	PermMembersWrite = "iam:members:write"
	PermAppsRead     = "iam:apps:read"
	PermAppsWrite    = "iam:apps:write"
	PermResourcesRead  = "iam:resources:read"
	PermResourcesWrite = "iam:resources:write"
	PermRolesRead    = "iam:roles:read"
	PermRolesWrite   = "iam:roles:write"
	PermGrantsRead   = "iam:grants:read"
	PermGrantsWrite  = "iam:grants:write"
	PermServiceAccountsRead  = "iam:service-accounts:read"
	PermServiceAccountsWrite = "iam:service-accounts:write"
)
