# Credentials and boundaries

| Credential | Where it is accepted | Authority |
| --- | --- | --- |
| `ik_mgmt_…` | `X-API-Key` on `/management/v1` | Workspace operator role |
| Operator cookie | Management console/API | Operator role, one-hour session |
| User access JWT | Bearer on identity consumers/protected APIs | Environment/org/app/resource and permissions |
| Machine access JWT | Bearer on protected APIs, including authorized `/api/v1` routes | Environment/app/resource and permissions; no organization |
| `ik_svc_…` | Bearer on `/identity/v1/machine-token` | Exchange for bound machine JWT |
| `ik_key_…` (machine) | Bearer on `/api/v1`, `/identity/v1/introspect`, `/identity/v1/token-exchange` | A machine user in one organization for one resource; live permissions, optionally narrowed by the key's list |
| `ik_key_…` (user, organization) | Bearer on **your** API, validated with `/identity/v1/introspect`; never on IAMKit's own API | A person in one organization, or the organization itself, for one resource; key list ∩ the resource's [allowlist](../guides/machines/api-keys.md#2-choose-what-each-resource-lets-keys-do) ∩ the owner's live reach; never `iam:*` |
| Machine user key assertion | `assertion` of the `jwt-bearer` grant at `/oauth/token` | A machine user; the boundary is chosen per sign-in; single use |
| `ik_scim_…` | `Authorization: Bearer` or `X-API-Key` on `/scim/v2` | Provisioning connection/organization |
| Refresh token | `/identity/v1/refresh` with full original boundary | Rotate an existing user session |
| OAuth client secret | OAuth token/revocation protocol | Authenticate a confidential client, not an operator |
| Provider client secret | Server-side OIDC exchange | Authenticate IAMKit to external provider |

Access JWTs last 15 minutes; user sessions have a fixed 24-hour window. Operator
cookies last one hour. Bootstrap/recovery keys last 24 hours. Issued management,
service and provisioning credentials support explicit lifetimes; see
[configuration](../reference/configuration.md), never infer lifetime from a prefix.

Keep long-lived credentials in server secret storage. IDs and OAuth public client
IDs are not secrets. Management API keys are not environment-limited. Tokens for
the [JWT IAM API](../reference/api/scoped-iam.md) are limited to their environment,
but within it IAM permissions are environment-wide, so users and service accounts
with IAM permissions are privileged.

User and organization API keys are never accepted by IAMKit's API and cannot
be exchanged for tokens; see [API keys](../guides/machines/api-keys.md).

Never send raw service keys to ordinary API routes. Exchange them first. Never
accept an OIDC ID token where an access token is required.
