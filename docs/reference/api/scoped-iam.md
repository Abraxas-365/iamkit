# Permission-scoped IAM API

`/api/v1/environments/:environment` accepts **JWT access tokens** in
`Authorization: Bearer …`, unlike the management API's `X-API-Key`. Raw
`ik_mgmt_`, `ik_svc_` and `ik_scim_` credentials are rejected here.

## Deployment blockers

**Do not rely on this API for environment-isolated administration in the current
routing implementation.** Source review found that authentication runs on
`/api/v1` before `:environment` is available; its conditional environment check
is skipped. A token authorized in one environment can reach another environment's
handlers. Also, empty-prefix permission middleware applies to later route
families, requiring additional permissions beyond the intended table below.
Do not broaden grants to work around those unexpected 403 responses.

Keep `/api/v1` inaccessible to untrusted callers until route scoping is corrected
and cross-environment/least-permission regression tests pass. The documented
onboarding tutorial uses workspace-operator `/management/v1` authority instead;
that key is deliberately workspace-wide and must remain on a trusted backend.
These findings are from source review, not a live exploit reproduction.

The intended setup is an application binding to the built-in IAM resource and a
service account with selected IAM permissions. Its credential is exchanged at
`/identity/v1/machine-token` for a JWT. These are administrative capabilities, not
organization-limited permissions; this setup does not resolve the blockers above.

Every environment has an IAM resource with prefix `iam` and audience
`urn:iamkit:environment:ENV_UUID`. Discover its ID through the resources list;
do not create a second resource or guess its UUID.

## Route families

Request/response bodies are shared with the corresponding management handlers.
The table lists intended permissions, **not currently sufficient credentials**
for all routes. GET/HEAD select read; mutations select write. For example, grants
also encounter member/resource/role checks, and service accounts encounter those
plus grant checks because of middleware registration order.

| Routes | Permissions |
| --- | --- |
| `/users`, `/users/:id`, `/users/:id/permanent` (create/list/get/patch/suspend/delete) | `iam:users:read`, `iam:users:write` |
| `/organizations`, `/organizations/:id` (create/list/get/patch) | `iam:orgs:read`, `iam:orgs:write` |
| `/memberships`, `/organizations/:organization/members`, member removal and structure routes | `iam:members:read`, `iam:members:write` |
| `/applications`, `/applications/:id` (create/list/get/patch) | `iam:apps:read`, `iam:apps:write` |
| Resources, application-resource bindings, application resource lists | `iam:resources:read`, `iam:resources:write` |
| Roles and role assignments | `iam:roles:read`, `iam:roles:write` |
| Grants | `iam:grants:read`, `iam:grants:write` |
| Service accounts (create/list/revoke) | `iam:service-accounts:read`, `iam:service-accounts:write` |
| Delivery configuration (`GET`, `PUT`, `DELETE /delivery`) | `iam:delivery:read`, `iam:delivery:write` |

There are no workspace/operator, federation, OAuth-client or SCIM-credential
administration routes in this API family. Application DELETE is not registered
here; use PATCH `active:false` with the appropriate authority.

The middleware validates JWTs online, but that does not repair path-environment
or route-permission scoping. After fixes, test missing permissions and cross-environment
rejection before enabling this API. Grants/roles/service-account writes can delegate
access; never expose them as an unrestricted browser signup proxy.

See [service accounts](../../guides/service-accounts.md) and
[signup](../../guides/signup-and-onboarding.md). Source:
`internal/server/api.go`, `internal/server/apiauth/middleware.go` and
`migrations/014_system_iam_resource.up.sql`.
