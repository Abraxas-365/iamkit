# Permission-scoped IAM API

`/api/v1/environments/:environment` accepts **JWT access tokens** in
`Authorization: Bearer …`, unlike the management API's `X-API-Key`. Raw
`ik_mgmt_`, `ik_svc_` and `ik_scim_` credentials are rejected here.

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
Keep such tokens on trusted backends.

The setup is an application binding to the built-in IAM resource and a
service account with selected IAM permissions. Its credential is exchanged at
`/identity/v1/machine-token` for a JWT.

Every environment has an IAM resource with prefix `iam` and audience
`urn:iamkit:environment:ENV_UUID`. Discover its ID through the resources list;
do not create a second resource or guess its UUID.

## Route families

Request/response bodies are shared with the corresponding management handlers.
GET/HEAD select the read permission; mutations select write.

| Routes | Permissions |
| --- | --- |
| `/users`, `/users/:id`, `/users/:id/permanent`, `/users/:id/factors`, `/users/:id/unlock` (create/list/get/patch/suspend/delete, factor list/reset, password unlock) | `iam:users:read`, `iam:users:write` |
| `/organizations`, `/organizations/:id` (create/list/get/patch) | `iam:orgs:read`, `iam:orgs:write` |
| `/memberships`, `/organizations/:organization/members`, member removal, structure and group routes | `iam:members:read`, `iam:members:write` |
| `/applications`, `/applications/:id` (create/list/get/patch) | `iam:apps:read`, `iam:apps:write` |
| Resources, application-resource bindings, application resource lists | `iam:resources:read`, `iam:resources:write` |
| Roles, role assignments, group role assignments, effective roles | `iam:roles:read`, `iam:roles:write` |
| Grants | `iam:grants:read`, `iam:grants:write` |
| Service accounts (create/list/revoke) | `iam:service-accounts:read`, `iam:service-accounts:write` |
| Delivery configuration (`GET`, `PUT`, `DELETE /delivery`; `GET /delivery/status`; `POST /delivery/test`; `GET`, `POST /delivery/preview`; `GET /delivery/templates`; `GET`, `PUT`, `DELETE /delivery/templates/:purpose/:locale`) | `iam:delivery:read` (`GET`), `iam:delivery:write` (others, including draft `POST /delivery/preview`) |

There are no workspace/operator, federation, OAuth-client or SCIM-credential
administration routes in this API family. Application DELETE is not registered
here; use PATCH `active:false` with the appropriate authority.

The middleware validates JWTs online (revoked sessions and removed permissions stop
working immediately). Grants/roles/service-account writes can delegate
access; never expose them as an unrestricted browser signup proxy.

See [service accounts](../../guides/service-accounts.md) and
[signup](../../guides/signup-and-onboarding.md). Source:
`internal/server/api.go`, `internal/server/apiauth/middleware.go` and
`migrations/014_system_iam_resource.up.sql`.
