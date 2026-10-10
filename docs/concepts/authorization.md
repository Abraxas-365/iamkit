# Authorization

For InvoiceCloud, define the Invoices API resource with audience
`https://api.example.com`, prefix `invoices` and catalog
`["invoices:read","invoices:write"]`. Link Web App to that resource. Add Alice to
Acme and grant `invoices:read` directly or via a resource role.

At login, IAMKit evaluates the selected environment, organization, application
and resource. An active user, membership, active application, resource binding
and effective grant are required. Neither a successful external-provider login
nor membership alone grants API access.

Your API checks **both permission and tenant**: an Acme token with `invoices:read`
cannot read another organization's invoices. Scope storage queries to the same
organization. Treat resource audiences as trusted configuration, not request input.

Direct grants and role assignments are distinct. Removing one direct permission
may not remove permission supplied by a role. Inspect both paths when revoking
access. Offline tokens contain issued permissions until expiry; use introspection
when immediate current-state evaluation is required.

A member's effective permissions for a resource are the union of three sources:
direct grants, directly assigned roles, and roles bound to groups the member
belongs to in that organization. Group roles are resolved when a token is
issued, never copied onto the user, so removing someone from a group revokes
only what the group supplied. `GET /effective-roles` shows which path supplies
each role; the console shows the same on each user's page. To set groups up,
see [groups and group roles](../guides/organizations/organizations.md#groups-and-group-roles).

A resource can also belong to a vendor organization and **require a grant**:
then only its owner and the organizations it is granted to (optionally just
some of its roles) receive its permissions, whatever roles or direct grants
exist elsewhere. See
[resource grants](../guides/organizations/organization-administration.md#resource-grants-vendor-organizations).

Permissions are exact strings, not wildcard patterns. Use the resource's catalog;
`iam:users:write` belongs to the built-in IAM resource, not the invoice catalog.
IAM administrative permissions deserve separate service credentials and review.
There is no wildcard superuser scope for application tokens.

Keep each catalog and its roles in one manifest in your repository, generate the
constants your code checks, and sync IAMKit from it without dropping permissions
that running code still checks: see [permissions as code](../guides/applications/permissions-as-code.md).

Follow [first application](../start/first-application.md) and
[protect an API](../start/protect-an-api.md) to verify both allowed access and denial.
