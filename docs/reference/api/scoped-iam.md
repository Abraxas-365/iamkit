# Permission-scoped IAM API

`/api/v1/environments/:environment` accepts **JWT access tokens** in
`Authorization: Bearer …`, unlike the management API's `X-API-Key`. Raw
`ik_mgmt_`, `ik_svc_` and `ik_scim_` credentials are rejected here; of the
`ik_key_` API keys only a machine user's is accepted.

## Isolation

Every route under `/api/v1/environments/:environment` requires the token's
environment to equal the path environment (`403 token not scoped to this
environment` otherwise, including a malformed ID), and each route family requires
exactly its own permission pair below — no other family's permission is needed.
`tests/e2e/scoped_api_test.go` covers cross-environment rejection on every route
family and least-permission access per family.

Before 2026-09-28 neither held: the environment check ran on `/api/v1` before
`:environment` was bound, so it was skipped, and some permission checks applied to
later route families. If you ran an earlier build with this API exposed, review
audit events for actors from another environment, and remove permissions granted
only to work around the old 403s.

These are environment-wide administrative permissions, not organization-limited
ones: a token with `iam:users:write` can change any user of its environment.
Keep such tokens on trusted backends. Organization-limited administration uses
the `iam:org:*` permissions under `/organizations/:organization/admin`; see
[organization administration](../../guides/organizations/organization-administration.md).

The setup is an application binding to the built-in IAM resource and a
service account with selected IAM permissions. Its credential is exchanged at
`/identity/v1/machine-token` for a JWT. A [machine user](../../guides/machines/machine-users.md)'s
[API key](../../guides/machines/api-keys.md#machine-keys) (`ik_key_…`) for the IAM
resource is accepted directly as the bearer, with the IAM permissions the machine
user holds in the token's organization. User and organization API keys are 401
here: they never carry `iam:*` permissions.

Every environment has an IAM resource with prefix `iam` and audience
`urn:iamkit:environment:ENV_UUID`. Discover its ID through the resources list;
do not create a second resource or guess its UUID.

## Route families

Request/response bodies are shared with the corresponding management handlers.
GET/HEAD select the read permission; mutations select write.

| Routes | Permissions |
| --- | --- |
| `/users`, `/users/import`, `/users/:id`, `/users/:id/permanent`, `/users/:id/factors`, `/users/:id/unlock`, `/users/:id/deactivate`, `/users/:id/reactivate`, `/users/:id/api-keys`, `/users/:id/api-keys/:key`, `/users/:id/keys`, `/users/:id/keys/:key`, `/users/:id/metadata/:key`, `/users/:id/profile`, `/user-schema` (create/list/get/patch/suspend/delete, factor list/reset, password unlock, deactivate/reactivate, metadata, profile, user schema) | `iam:users:read`, `iam:users:write` |
| `POST /users/import`, and `password_hash` or `email_verified` on `POST /users` (see [importing users](../../guides/migration/importing-users.md)) | `iam:users:write` and `iam:users:import` |
| `/organizations`, `/organizations/:id`, `/organizations/:id/metadata/:key` (create/list/get/patch, metadata) | `iam:orgs:read`, `iam:orgs:write` |
| `/organizations/:id/setup-links` (`GET`, `POST`, `DELETE /:link`; see [setup links](../../guides/organizations/organization-administration.md#setup-links)) | `iam:orgs:read` (`GET`), `iam:orgs:write` |
| `/memberships`, `/organizations/:organization/members`, member removal, structure and group routes | `iam:members:read`, `iam:members:write` |
| `/applications`, `/applications/:id` (create/list/get/patch) | `iam:apps:read`, `iam:apps:write` |
| Resources, `PUT /resources/:id/access`, `PUT /resources/:id/api-key-permissions`, application-resource bindings, application resource lists | `iam:resources:read`, `iam:resources:write` |
| Roles, role assignments, group role assignments, effective roles, `/resource-grants` | `iam:roles:read`, `iam:roles:write` |
| Grants | `iam:grants:read`, `iam:grants:write` |
| API keys (`/api-keys`, `/api-keys/:key`, `/api-key-policy`; see [API keys](../../guides/machines/api-keys.md)) | `iam:api-keys:read`, `iam:api-keys:write` |
| Service accounts (create/list/get/authentication/revoke) | `iam:service-accounts:read`, `iam:service-accounts:write` |
| Event log (`GET /events`, `GET /events/export`, see [event log](../events.md)) | `iam:events:read` |
| Entity history (`GET /users/:id/history`, also `organizations`, `applications`, `roles`, `resources`; see [change history](../events.md#change-history)) | `iam:events:read` and the collection's read permission |
| Event webhooks (`/webhooks…`, see [event webhooks](../event-webhooks.md)) | `iam:webhooks:read` / `iam:webhooks:write` |
| Log streams (`/log-streams…`, see [log streams](../../guides/platform/log-streams.md)) | `iam:audit-logs:read` / `iam:audit-logs:manage` |
| Bot protection and risk (`/captcha`, `POST /captcha/test`, `/risk-policy`, `/risk-restrictions`, `/sign-in-attempts`, `/users/:id/devices`, `GET /risk/status`; see [bot protection](../../guides/sign-in/bot-protection.md) and [risk signals](../../guides/sign-in/risk-signals.md)) | `iam:security:read` (`GET`), `iam:security:write` (others) |
| Daily usage (`GET /usage`, see [usage and limits](../../guides/platform/usage-limits.md)) | `iam:usage:read` |
| Delivery configuration (`GET`, `PUT`, `DELETE /delivery`; `GET /delivery/status`; `POST /delivery/test`; `GET`, `POST /delivery/preview`; `GET /delivery/templates`; `GET`, `PUT`, `DELETE /delivery/templates/:purpose/:locale`) | `iam:delivery:read` (`GET`), `iam:delivery:write` (others, including draft `POST /delivery/preview`) |

There are no workspace/operator, federation, OAuth-client or SCIM-credential
administration routes in this API family.
Organization admins manage their own organization's SCIM tokens through
`/api/v1/environments/:environment/organizations/:organization/admin/directories`
(`GET` with `iam:org:read` returns the tokens and `scim_url`; `POST` and
`DELETE /directories/:credential` need `iam:org:sso:write`). Those routes belong
to the `iam:org:*` family, not to the environment-wide permissions above; see
[SCIM provisioning](../../guides/enterprise/scim-provisioning.md#self-service-for-organization-admins). Owners also manage setup links at `…/admin/setup-links` (every `iam:org:*`
permission), and a setup bearer (`ik_setupsess_…`) is accepted only on
`…/admin` routes of its own organization, limited to its intents; see
[setup links](../../guides/organizations/organization-administration.md#setup-links). Application DELETE is not registered
here; use PATCH `active:false` with the appropriate authority.

The middleware validates JWTs online (revoked sessions and removed permissions stop
working immediately). Grants/roles/service-account writes can delegate
access; never expose them as an unrestricted browser signup proxy.

See [service accounts](../../guides/machines/service-accounts.md) and
[signup](../../guides/sign-in/signup-and-onboarding.md). Source:
`internal/server/api.go`, `internal/server/apiauth/middleware.go` and
`migrations/001_initial.up.sql`.
