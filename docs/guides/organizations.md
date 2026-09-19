# Organizations and membership lifecycle

An organization is a tenant/business boundary within an environment. Add users
through management on a trusted backend. The alternative scoped IAM API has
[routing blockers](../reference/api/scoped-iam.md#deployment-blockers). Adding a
membership does not assign invoice permissions; grant those separately.

1. Create organization and capture its ID.
2. Add an existing local user with `POST /memberships`.
3. Assign a resource role or direct grant.
4. Test login in that organization's context and API tenant isolation.

When removing access, inspect direct grants and role assignments as well as
membership. Remove the membership for that organization rather than suspending a
shared user globally unless that is the policy. Revoke sessions for urgent
containment and use online introspection to observe it. Offline JWTs persist until
expiry from the consumer's perspective.

Units, positions and reporting managers describe your organization; they do not
implicitly create grants. Use delete-impact and hierarchy reads before structural
changes. Manager/parent relationships must stay within the organization and be
acyclic. SCIM-managed profiles have connection ownership constraints.

**Verify:** two memberships for one user can carry different permissions. Removing
Acme access must not grant access to, or silently rewrite, the other tenant.

See [API routes](../reference/api/users-and-organizations.md),
[authorization](../concepts/authorization.md) and [SCIM](scim-provisioning.md).
