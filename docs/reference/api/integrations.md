# Integration administration API

All paths below are relative to `/management/v1/environments/:environment`.
Use operator `X-API-Key`; writes require owner/admin except impersonation, which
requires owner. Credential responses are secrets and must be captured once.

| Method/path | JSON body | Success |
| --- | --- | --- |
| `POST /federation-connections` | `name,issuer,client_id,secret_env` | 201 `{id}` |
| `GET /federation-connections` | — | 200 page with linked counts |
| `GET /federation-connections/:id` | — | 200 detail, including secret variable name (not secret value) |
| `GET /federation-connections/:id/identities` | — | 200 page of subject/user links |
| `DELETE /federation-connections/:id` | — | 204; disable |
| `POST /external-identities` | `connection_id,user_id,subject` | 204 |
| `DELETE /external-identities/:connection/:user` | — | 204 |
| `POST /oauth-clients` | `application_id,resource_id,redirect_uris,public` | 201 `{id,client_id,client_secret}` |
| `GET /oauth-clients` | — | 200 page |
| `DELETE /oauth-clients/:id` | — | 204 |
| `POST /service-accounts` | `name,application_id,resource_id,permissions`, optional `expires_in` | 201 `{id,secret,expires_at}` |
| `GET /service-accounts` | — | 200 page |
| `DELETE /service-accounts/:id` | — | 204 |
| `POST /provisioning-credentials` | `name,organization_id`, optional `connection_id,expires_in` | 201 `{id,secret,expires_at,connection_id}` |
| `GET /provisioning-credentials` | — | 200 array |
| `DELETE /provisioning-credentials/:id` | — | 204 |
| `POST /provisioned-identities` | `connection_id,user_id,external_id` | 204 |
| `POST /impersonations` | `organization_id,application_id,resource_id,user_id,reason` | 200 access token without refresh |

Federation issuer/client/secret reference must match deployment approval exactly.
SCIM rotation should reuse the stable connection ID to retain identity mappings.
Impersonation reasons must be 10–1000 trimmed characters. Do not confuse a
provisioned external ID with an OIDC subject link: they serve different protocols.

See [federation](../../guides/federation.md), [service accounts](../../guides/service-accounts.md),
[SCIM](../../guides/scim-provisioning.md), [impersonation](../../guides/impersonation.md).
