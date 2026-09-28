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

To prove an organization owns an email domain, add it under Members → Domains
(or `POST /organizations/:organization/domains`), publish the TXT record shown
at your DNS provider and click **Check DNS now**. A domain belongs to one
organization per environment. Verified domains let SCIM adopt only members on
the organization's own domains, and power the organization's
[single sign-on](federation.md#organization-sso): email discovery,
just-in-time provisioning and enforcement.

To bring people in, use Members → Invitations (or
`POST /organizations/:organization/invitations`) with the roles and groups they
should get. IAMKit sends the invitation through [email delivery](email-delivery.md)
(to your webhook, or as an email it writes via SMTP/Resend);
your invitation page previews it and accepts it through the
[identity API](../reference/api/identity.md#invitations). New people choose a
password there (or use SSO when the organization enforces it); existing users
just join. The token is shown once in the console, for manual sharing when
delivery is not configured. Only operator-managed groups can be picked for an
invitation: a directory (SCIM) group's members come from the directory.

**Verify:** two memberships for one user can carry different permissions. Removing
Acme access must not grant access to, or silently rewrite, the other tenant.

## Groups and group roles

A group gives the same roles to many members at once. Each member holds the
group's roles in addition to their own, for as long as they are in the group;
nothing is copied onto the user. In the console:

1. Open the organization → **Groups** → **Create group**. The new group opens.
2. On the group, **Assign role** and pick a role. Roles the group already holds
   are marked *Assigned* and cannot be picked again.
3. **Add member** and pick active organization members. Directory (SCIM)
   groups are synced by the directory: their members can't be edited here, but
   you can still assign them roles.
4. Open a member's user page: under *Organizations & roles*, roles from a group
   show as `role via Group` and link to the group. Remove them there, not on
   the user.

**Roles → Role assignments** lists everything in one place: the *Users* tab
shows direct assignments and the *Groups* tab group roles, each with
**Assign role** for either kind. With the CLI:

```sh
GROUP=$(iam groups create --org $ORG --name Finance)
iam groups roles assign --org $ORG --group $GROUP --role $ROLE
iam groups members add --org $ORG --group $GROUP --user $USER
iam groups roles list --org $ORG --group $GROUP
```

Or through the API: `POST /organizations/:organization/groups`,
`POST /group-role-assignments`, `POST /organizations/:organization/groups/:group/members`
([routes](../reference/api/applications-and-authorization.md#group-roles)).

**Verify:** a member's token carries the group role's permissions; after
**Remove from group** the next token no longer does, while their direct roles
remain.

See [API routes](../reference/api/users-and-organizations.md),
[authorization](../concepts/authorization.md) and [SCIM](scim-provisioning.md).
