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

Permissions are exact strings, not wildcard patterns. Use the resource's catalog;
`iam:users:write` belongs to the built-in IAM resource, not the invoice catalog.
IAM administrative permissions deserve separate service credentials and review.
There is no wildcard superuser scope for application tokens.

Follow [first application](../start/first-application.md) and
[protect an API](../guides/protect-an-api.md) to verify both allowed access and denial.
