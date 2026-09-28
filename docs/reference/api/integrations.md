# Integration administration API

All paths below are relative to `/management/v1/environments/:environment`.
Use operator `X-API-Key`; writes require owner/admin except impersonation, which
requires owner. Credential responses are secrets and must be captured once.

| Method/path | JSON body | Success |
| --- | --- | --- |
| `POST /federation-connections` | `name,client_id`, `provider` (`oidc` default \| `google` \| `microsoft` \| `github` \| `apple`), `issuer` (`oidc` only), `options` (see below) and exactly one of `client_secret` (stored encrypted; Apple: the `.p8` PEM) or `secret_env` (not Apple); optional `organization_id,jit_provisioning,jit_group_id,enforcement`, or without `organization_id`: `signup,signup_organization_id,signup_group_id,link_email` | 201 `{id}` |
| `GET /federation-connections` | Optional `organization_id` filter | 200 page with `provider,organization_id,organization_name,jit_provisioning,enforcement,signup,link_email` and linked counts |
| `GET /federation-connections/:id` | — | 200 detail with `provider,organization_name,options,callback_url`, sign-up settings, `secret_source` (`sealed`\|`env`), secret variable name for `env`; never the secret |
| `PATCH /federation-connections/:id` | Any of `name,client_secret,jit_provisioning,jit_group_id` (`""` clears),`enforcement,options,signup,link_email,signup_organization_id,signup_group_id` (`""` clears) | 204 |
| `GET /federation-connections/:id/identities` | — | 200 page of subject/user links with `origin` (`linked`\|`jit`\|`email`\|`signup`) and `created_at` |
| `DELETE /federation-connections/:id` | — | 204; disable |
| `POST /external-identities` | `connection_id,user_id,subject` | 204 |
| `DELETE /external-identities/:connection/:user` | — | 204 |
| `POST /oauth-clients` | `application_id,resource_id,redirect_uris,public`, optional `hosted_login` | 201 `{id,client_id,client_secret}` |
| `GET /oauth-clients` | Optional `application_id` | 200 page (includes `hosted_login`) |
| `GET /oauth-clients/:id` | — | 200 client `{id,application_id,application_name,resource_id,resource_name,redirect_uris,public,hosted_login,active}` |
| `PATCH /oauth-clients/:id` | `hosted_login` and/or `redirect_uris` (non-empty, validated like create) | 204 |
| `DELETE /oauth-clients/:id` | — | 204 |
| `GET /login-settings` | — | 200 `{environment_id,display_name,logo_url,accent_color,theme,updated_at}` (defaults when unset) |
| `PUT /login-settings` | `display_name` (≤100), `logo_url` (HTTPS), `accent_color` (`#rrggbb`), `theme` (see [hosted login](../../guides/hosted-login.md#branding)) | 200 normalized settings |
| `GET /login-settings/clients` | — | 200 page of client styles (`client_id` set) |
| `GET /login-settings/clients/:client` | — | 200 style; 404 when the client uses the default |
| `PUT /login-settings/clients/:client` | same as `PUT /login-settings` | 200 normalized style; 404 unknown client |
| `DELETE /login-settings/clients/:client` | — | 204; 404 when it has no style |
| `GET /login-settings/sign-in` | — | 200 page of clients with their own sign-in methods |
| `GET /login-settings/clients/:client/sign-in` | — | 200 `{client_id,password,email_code,organization_sso,all_connections,connection_ids,custom,updated_at}`; every method with `custom:false` when unset |
| `PUT /login-settings/clients/:client/sign-in` | `password,email_code,organization_sso,all_connections,connection_ids` (≤50 active environment connections); at least one method | 200 normalized options; 404 unknown client |
| `DELETE /login-settings/clients/:client/sign-in` | — | 204; the client offers every method again |
| `GET /login-settings/preview` | `?page=`, `?scheme=light\|dark`, optional `?client=` | 200 `{html}` with the saved style |
| `POST /login-settings/preview` | `{page,scheme,settings}` | 200 `{html}` with the unsaved style (write access) |
| `POST /service-accounts` | `name,application_id,resource_id,permissions`, optional `expires_in` | 201 `{id,secret,expires_at}` |
| `GET /service-accounts` | — | 200 page |
| `DELETE /service-accounts/:id` | — | 204 |
| `POST /provisioning-credentials` | `name,organization_id`, optional `connection_id,expires_in,adopt_existing_members,adopt_scope` (`any`\|`verified_domains`) | 201 `{id,secret,expires_at,connection_id}` |
| `GET /provisioning-credentials` | — | 200 array (includes `organization_name,connection_name,adopt_existing_members,adopt_scope`) |
| `DELETE /provisioning-credentials/:id` | — | 204 |
| `POST /provisioned-identities` | `connection_id,user_id,external_id`; also re-anchors deprovisioned or internally anchored identities | 204 |
| `POST /impersonations` | `organization_id,application_id,resource_id,user_id,reason` | 200 access token without refresh |

`jit_provisioning` (default `true`), `jit_group_id` and `enforcement`
(`optional`\|`enforced`) require `organization_id`. The default group must be
an operator-managed group of that organization with JIT on; enforcement needs
a verified domain (422) and at most one enforced connection per organization
(409). `client_secret` requires `IAMKIT_ENCRYPTION_KEY`.

`options`: Microsoft requires `tenant` (`common`\|`organizations`\|`consumers`\|tenant
ID, fixed after creation) and takes `tenants` (tenant IDs allowed under
`common`/`organizations`); Apple requires `team_id` and `key_id` (a new `key_id`
needs a new `client_secret`). Other providers take none. `signup` requires
`signup_organization_id`; `signup_group_id` requires `signup`; `signup: false`
clears both. Organization connections reject `signup` and `link_email`. See
[social login](../../guides/social-login.md) and
[sign-in methods](../../guides/hosted-login.md#sign-in-methods). A `secret_env`
issuer/client/secret reference must match deployment approval exactly.
SCIM rotation should reuse the stable connection ID to retain identity mappings.
Impersonation reasons must be 10–1000 trimmed characters. Do not confuse a
provisioned external ID with an OIDC subject link: they serve different protocols.

See [federation](../../guides/federation.md), [service accounts](../../guides/service-accounts.md),
[SCIM](../../guides/scim-provisioning.md), [impersonation](../../guides/impersonation.md).
