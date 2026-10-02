# Let customers administer their organization

In a B2B product your customers want to manage their own people: invite
colleagues, give them roles, suspend someone who left, connect their
company's SSO. IAMKit lets an organization's own administrators do that
through `/api/v1/environments/:environment/organizations/:organization/admin`,
limited to their organization, without operator access or an environment-wide
`iam:*` token.

## How it works

1. **Permissions.** Every environment's IAM resource (prefix `iam`) carries
   organization-bound permissions:

   | Permission | Allows |
   | --- | --- |
   | `iam:org:read` | Read the organization, its domains and SSO connections |
   | `iam:org:settings:write` | Change the name, MFA policy and sign-in methods |
   | `iam:org:members:read` | List members, home users, invitations |
   | `iam:org:members:write` | Remove members, set a member's SSO bypass |
   | `iam:org:users:write` | Create home users; edit, suspend, reactivate and unlock them |
   | `iam:org:roles:read` | List assignable roles and members' roles |
   | `iam:org:roles:assign` | Assign and remove roles (see the rules below) |
   | `iam:org:invitations:write` | Invite, resend and revoke invitations |
   | `iam:org:domains:write` | Add, verify and remove domains |
   | `iam:org:sso:write` | Create, change and disable the organization's SSO connections |
   | `iam:org:audit:read` | Read the organization's audit events |
   | `iam:org:resources:read` | List the resources the organization owns, their grants, and the grants it received |
   | `iam:org:resources:write` | Grant the organization's own resources to other organizations |

2. **Built-in roles.** Every IAM resource has five roles you cannot change or
   delete (they list with `system_role` set, and show as *Built-in* in the
   console):

   | Role (`system_role`) | Permissions |
   | --- | --- |
   | Organization owner (`org_owner`) | All `iam:org:*` |
   | Organization viewer (`org_viewer`) | `iam:org:read`, `iam:org:members:read`, `iam:org:roles:read` |
   | User manager (`org_user_manager`) | Read, members read/write, users write, roles read/assign, invitations write |
   | Settings manager (`org_settings_manager`) | Read, settings write, domains write, SSO write |
   | Resource manager (`org_resource_manager`) | Read, resources read/write |

   You may also create your own IAM-resource roles with any subset of the
   `iam:org:*` permissions.

3. **Tokens.** Give a customer's first administrator the owner role in their
   organization with the ordinary role-assignment API
   (`POST /management/v1/environments/:environment/role-assignments` with
   `organization_id`, `user_id` and the owner `role_id`). Then link your admin
   application to the IAM resource (`POST /application-resources`) and let the
   user sign in to that organization for the IAM resource (hosted login,
   OAuth, or `/identity/v1/login` with `resource_id` = the IAM resource). The
   access token carries the user's `iam:org:*` permissions for that
   organization. Operators and management keys are unaffected.

A request succeeds only when the token was issued **in the path's
organization** and holds the route's permission. Machine tokens and
impersonated sessions are refused, and the environment-wide
`iam:members:*`/`iam:users:*` routes still need their own permissions.

## Hosted portal

If you would rather not build these screens, turn on the **organization
admin portal**: a page IAMKit hosts at `/org-admin/<environment>` where your
customers' administrators manage their organization — members, home users,
invitations, roles, domains, single sign-on, resources, branding, password
rules and activity — using exactly the routes below.

```bash
iam org-admin-portal enable   # prints the link to share
iam org-admin-portal get
iam org-admin-portal disable
```

(Console: **Hosted login → Organization admin portal**; API:
`GET`/`PUT`/`DELETE /management/v1/environments/:environment/org-admin-portal`,
audited `org_admin_portal.enabled` / `org_admin_portal.disabled`.)

- **Sign-in.** Turning it on registers IAMKit's own public OAuth client
  (hosted login, authorization code + PKCE, refresh tokens) on the IAM
  resource, with the portal's callback as its only redirect URI. It shows in
  the OAuth client list with `system` = `org_admin` and cannot be edited or
  disabled there (409). The portal discovers it through the public
  `GET /identity/v1/org-admin/:environment` (`client_id`, `environment_id`,
  `url`; 404 when off). Users sign in through the hosted pages with the
  environment's methods, MFA and branding; add `?organization_id=ORG_ID` to
  the link to go straight to that organization.
- **What they see.** The portal reads the token's `iam:org:*` permissions to
  hide pages and buttons the token cannot use; the server checks every
  request again. A member without any `iam:org:*` permission is told to ask
  an owner.
- **Tokens** stay in the browser tab (`sessionStorage`), never in cookies;
  the page sends a strict CSP (`script-src 'self'`, no framing, no referrer).
- **Turning it off** deactivates the client and ends every portal session at
  once (refresh tokens stop working; access tokens already issued last until
  they expire, as usual). Turning it back on reuses the same client. The
  `/admin` API keeps working for your own app either way.

```go
portal, err := iamclient.New(baseURL, managementKey).Environment(envID).EnableOrgAdminPortal(ctx)
fmt.Println(portal.URL) // share with organization administrators
```

## Rules that stop escalation

- **Roles.** Administrators assign or remove roles of the IAM resource
  whose every permission they hold themselves, and roles of resources the
  organization owns or was granted (see below; `GET /roles` marks them
  `granted`). Only an owner assigns, removes
  or acts on the owner role. Invitations follow the same check for their
  `role_ids` and the roles carried by their `group_ids`.
- **Owners.** An owner cannot be removed from the organization, suspended or
  edited by a non-owner, and the last owner (directly assigned) cannot lose the
  role, leave or be suspended (422).
- **Home users.** Changing a user's record (name, username, avatar, phone,
  suspension, unlock) requires the user's `home_organization_id` to be the
  organization: users shared with other organizations stay under your control.
  A user is homed in an organization when an organization administrator
  creates it, when an invitation creates it, when an organization SSO
  connection provisions it, when SCIM creates it, or when an operator sets
  `home_organization_id` (`POST`/`PATCH /users`, `iam users create|update
  --home-organization`, or *Make home organization* in the console).
  Environments upgraded from earlier versions homed each user with exactly one
  membership.
- **What stays with operators.** Administrators cannot set the
  organization's `active` flag or metadata, user metadata, a connection's
  `secret_env` (it would read server environment variables; send a sealed
  `client_secret` instead) or another organization as a connection's signup
  target, and cannot see or change other organizations' users, invitations,
  domains or connections (404).

## Resource grants (vendor organizations)

When one organization ships an API to others — a vendor selling its product
to customer organizations — an operator makes it the resource's owner and
requires a grant:

```bash
iam resources access RESOURCE_ID --owner VENDOR_ORG_ID --require-grant
```

(`PUT /management/v1/environments/:environment/resources/:id/access` with
`owner_organization_id`, `require_grant`.) From then on only the owner and
organizations holding a **resource grant** get tokens, roles and permissions
for that resource. A grant names the organization and, optionally, the roles
it may use (`role_ids`; `null` = every role, current and future; `[]` = only
operators' direct permission grants). Without `require_grant` the resource
stays open to every organization, as before; ownership then only lets the
owner's administrators manage grants in advance.

The owner's administrators with `iam:org:resources:write` (the *Resource
manager* role) grant it themselves through `PUT /resource-grants`; operators
use the management API, `iam resources grants set`, or the resource's page in
the console. The granted organization's administrators then assign the
granted roles to their members like any other role. Narrowing a grant,
revoking it, changing the owner or turning `require_grant` on ends the
sessions for the resource of organizations that lost access (their refresh
tokens stop working); existing access tokens remain valid until they expire.
The IAM resource can be neither owned nor granted.

## Routes

All under `/api/v1/environments/:environment/organizations/:organization/admin`;
request and response bodies are the management API's.

| Route | Permission |
| --- | --- |
| `GET /`, `PATCH /` | `iam:org:read`, `iam:org:settings:write` |
| `GET /members`, `PATCH /members/:user` (`sso_bypass`), `DELETE /members/:user` | `iam:org:members:read`, `iam:org:members:write` |
| `GET /users` (home users, `?state=`), `GET /users/:user` (any member) | `iam:org:members:read` |
| `POST /users`, `PATCH /users/:user`, `POST /users/:user/deactivate`, `/reactivate`, `/unlock` | `iam:org:users:write` |
| `GET /roles`, `GET /members/:user/roles` | `iam:org:roles:read` |
| `POST /role-assignments` (`user_id`, `role_id`), `DELETE /role-assignments/:user/:role` | `iam:org:roles:assign` |
| `GET /invitations`, `POST /invitations`, `POST /invitations/:invitation/resend`, `DELETE /invitations/:invitation` | `iam:org:members:read`, `iam:org:invitations:write` |
| `GET /domains`, `POST /domains`, `POST /domains/:domain/verify`, `DELETE /domains/:domain` | `iam:org:read`, `iam:org:domains:write` |
| `GET /connections`, `GET /connections/:connection`, `POST`, `PATCH /connections/:connection`, `DELETE /connections/:connection` | `iam:org:read`, `iam:org:sso:write` |
| `GET /events` (`?action=` prefix) | `iam:org:audit:read` |
| `GET /branding`, `PUT /branding`, `DELETE /branding` ([organization branding](hosted-login.md#organization-branding): sign-in pages, invitation pages and emails) | `iam:org:read`, `iam:org:settings:write` |
| `GET /password-policy`, `PUT /password-policy`, `DELETE /password-policy` ([requirements](password-policy.md) that only tighten the environment's) | `iam:org:read`, `iam:org:settings:write` |
| `GET /resources` (owned), `GET /resource-grants` (`?resource_id=`), `GET /granted-resources` (received) | `iam:org:resources:read` |
| `PUT /resource-grants` (`resource_id` owned, `organization_id`, `role_ids`), `DELETE /resource-grants/:grant` | `iam:org:resources:write` |

## Audit

Every audit event records `actor_kind` (`operator`, `user`,
`service_account` or `system`) and the `organization_id` its target lies in.
`GET /events` returns the organization's events, newest first; operator
actors appear without their email. Operators see both fields in
`GET /audit-events`, and the console marks end-user actors.

## SDK

```go
admin := apiclient.New(baseURL, userAccessToken).Environment(envID).OrgAdmin(orgID)
created, err := admin.CreateUser(ctx, apiclient.CreateOrgUser{Email: "ana@acme.io", Name: "Ana"})
err = admin.AssignRole(ctx, created.ID, viewerRoleID)
events, err := admin.Events(ctx, "user.")
grant, err := admin.PutResourceGrant(ctx, apiclient.ResourceGrant{ResourceID: resourceID, OrganizationID: customerOrgID})
name := "Acme Corp"
_, err = admin.SaveBranding(ctx, apiclient.OrgBranding{DisplayName: &name}) // nil fields inherit
_, err = admin.SetPasswordPolicy(ctx, apiclient.OrgPasswordRequirements{MinLength: 16})
```

Source: `internal/iam/orgadmin`, `internal/server/api.go`,
`frontend/src/org-admin`,
`migrations/038_org_administration.up.sql`,
`migrations/039_resource_grants.up.sql`,
`migrations/044_org_admin_portal.up.sql`, `tests/e2e/org_admin_test.go`,
`tests/e2e/org_admin_portal_test.go`,
`tests/e2e/resource_grants_test.go`, `tests/e2e/organization_branding_test.go`.
