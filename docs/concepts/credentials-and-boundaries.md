# Credentials and boundaries

| Credential | Where it is accepted | Authority |
| --- | --- | --- |
| `ik_mgmt_…` | `X-API-Key` on `/management/v1` | Workspace operator role |
| Operator cookie | Management console/API | Operator role, one-hour session |
| User access JWT | Bearer on identity consumers/protected APIs | Environment/org/app/resource and permissions |
| Machine access JWT | Bearer on protected APIs, including authorized `/api/v1` routes | Environment/app/resource and permissions; no organization |
| `ik_svc_…` | Bearer on `/identity/v1/machine-token` | Exchange for bound machine JWT |
| `ik_scim_…` | `X-API-Key` on `/scim/v2` | Provisioning connection/organization |
| Refresh token | `/identity/v1/refresh` with full original boundary | Rotate an existing user session |
| OAuth client secret | OAuth token/revocation protocol | Authenticate a confidential client, not an operator |
| Provider client secret | Server-side OIDC exchange | Authenticate IAMKit to external provider |

Access JWTs last 15 minutes; user sessions have a fixed 24-hour window. Operator
cookies last one hour. Bootstrap/recovery keys last 24 hours. Issued management,
service and provisioning credentials support explicit lifetimes; see
[configuration](../reference/configuration.md), never infer lifetime from a prefix.

Keep long-lived credentials in server secret storage. IDs and OAuth public client
IDs are not secrets. Management API keys are not environment-limited. The
alternative JWT IAM API has [routing blockers](../reference/api/scoped-iam.md#deployment-blockers);
do not rely on it for environment isolation until corrected and tested. Users
with IAM permissions are also privileged.

Never send raw service keys to ordinary API routes. Exchange them first. Never
accept an OIDC ID token where an access token is required.
