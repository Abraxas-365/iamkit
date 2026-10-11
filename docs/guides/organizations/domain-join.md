# Join an organization by verified domain

With **domain join** on, people whose verified email address is on one of an
organization's verified domains become members when they sign in or sign up, with
no invitation and no SSO. It is the "anyone at acme.com" setting of B2B products.

## Rules

A user joins an organization when all of these hold at sign-in:

- the user is a human with an **active** account and a **verified** email
  (`email_verified`); unverified addresses never join, machine users never join;
- the email's domain is a **verified** domain of the organization (see
  [domains](organizations.md)); a pending claim does nothing;
- the organization is **active**, in the same environment, and has
  `domain_join` on;
- the user has **no membership row** there yet.

Then the membership is created before the organizations the user may sign in to are
listed, so the organization appears in the chooser or token request of that very
sign-in. If the organization has a `domain_join_group_id`, the user also joins that
group and gets its roles. Access to your resources still comes from roles and grants:
without a group the new member has the membership only.

It runs for every method: password, email code, passkey, social and organization
SSO sign-ins, hosted pages and the identity API, and sign-up completion.

## What the verified email is worth

Domain join trusts `email_verified` exactly as the source set it, for every
sign-in method:

- **Email codes** and sign-up: the user proved they can read the mailbox.
- **Invitations**: accepting one verifies the invited address.
- **Identity providers**: the provider's `email_verified` claim is taken at its
  word. An absent claim from an organization connection is accepted; Microsoft
  work accounts count as verified only when the token says the tenant verified
  the domain (`xms_edov`) or the connection is single-tenant.

So anyone who can obtain a verified address on your domain, from any of those
sources, joins. Two consequences:

- Give `domain_join_group_id` a **low-privilege group**: read-only or
  self-service roles, never administration. Grant more with explicit
  assignments afterwards.
- Turn on `link_email` or sign-up only on connections whose `email_verified` you
  trust (your own identity provider, Google Workspace, a Microsoft tenant you
  control). A connection that lets users choose an unverified address, or an
  open social login whose provider does not verify it, would otherwise
  become a way into the organization.

## Removed members stay removed

Removing a member (or deactivating a membership, for example from SCIM) keeps the
membership row, inactive. Domain join only creates missing memberships, so it never
re-adds or reactivates someone who was removed. Only an explicit invitation
reactivates the member.

## Sign-in method policy

Domain join only adds the membership. The organization's sign-in methods
([policy](../sign-in/sign-in-methods.md)) still decide whether it is offered: when
it refuses the method used (say it turned password sign-in off), the user is a member
but the organization is not offered for that sign-in. Nothing fails.

The membership is created **even if** the organization's sign-in methods or SSO
enforcement then block that sign-in: a user who signs in with a password to an
organization that enforces SSO is refused, but is a member from then on. Turn
domain join off, or remove the member, if that is not what you want.

## Turn it on

Operators, with the management API or the `/api/v1` organization update
(`iam:orgs:write`):

```http
PATCH /organizations/:organization
{"domain_join": true, "domain_join_group_id": "<group id>"}
```

```bash
iam organizations update ORG_ID --domain-join --domain-join-group GROUP_ID
```

`domain_join_group_id` must be an operator-managed group of the same organization (not
one a SCIM directory owns), else 400; `""` clears it. `domain_join` and
`domain_join_group_id` are returned when the organization is read.

Organization administrators do it themselves from the portal's Domains page, or with
`PATCH …/organizations/:organization/admin` and `iam:org:settings:write`. The same
anti-escalation rule as for invitations applies: everyone who joins gets the group's
roles, so the administrator must hold every permission those roles carry (or the
roles belong to a resource the organization owns), else 403. Turning domain join off or
clearing the group is always allowed.

## Events

| Event | Data |
| --- | --- |
| `membership.created` | `organization_id`, `user_id`, `source: "domain_join"`; actor is the user |
| `group.members_changed` | `organization_id`, `user_id`, `source: "domain_join"`, `change: "added"`; subject is the group |

Domain join does not count against a quota: memberships have none.
