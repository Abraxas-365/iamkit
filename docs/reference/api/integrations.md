# Integration administration API

All paths below are relative to `/management/v1/environments/:environment`.
Use operator `X-API-Key`; writes require owner/admin except impersonation, which
requires owner. Credential responses are secrets and must be captured once.

| Method/path | JSON body | Success |
| --- | --- | --- |
| `POST /federation-connections` | `name,client_id`, `provider` (`oidc` default \| `google` \| `microsoft` \| `github` \| `apple` \| `gitlab` \| `github_enterprise` \| `oauth2` \| `saml` \| `ldap`), `issuer` (`oidc` only), `options` (see below) and exactly one of `client_secret` (stored encrypted; Apple: the `.p8` PEM) or `secret_env` (not Apple) — `saml`: no `client_id`, secret or issuer, `organization_id` required, `options.metadata_url` or `options.metadata_xml` ([SAML](../../guides/saml.md)); `ldap`: no `client_id`, `secret_env` or issuer, `organization_id` required, `options.url` and `options.user_base_dn`, `client_secret` = the `bind_dn` password exactly when `options.bind_dn` is set ([LDAP](../../guides/ldap.md)); optional `link_email,update_profile`, `organization_id,jit_provisioning,jit_group_id,enforcement`, or without `organization_id`: `signup,signup_organization_id,signup_group_id` | 201 `{id}`; 409 when the environment (or the organization) already has a connection with the same `issuer` and `client_id`, disabled ones included |
| `GET /federation-connections` | Optional `organization_id` filter; optional `scope` (`environment`: social login connections \| `organization`: organization SSO connections) | 200 page with `provider,organization_id,organization_name,jit_provisioning,enforcement,signup,link_email` and linked counts |
| `GET /federation-connections/:id` | — | 200 detail with `provider,organization_name,options,callback_url`, sign-up settings, `secret_source` (`sealed`\|`env`\|`none` for SAML and anonymous LDAP), secret variable name for `env`; never the secret; SAML connections add `saml` `{entity_id,acs_url,metadata_url}` (the service provider values to give the identity provider) |
| `PATCH /federation-connections/:id` | Any of `name,client_secret,jit_provisioning,jit_group_id` (`""` clears),`enforcement,options,signup,link_email,update_profile,signup_organization_id,signup_group_id` (`""` clears) | 204 |
| `GET /federation-connections/:id/identities` | — | 200 page of subject/user links with `origin` (`linked`\|`jit`\|`email`\|`signup`) and `created_at` |
| `DELETE /federation-connections/:id` | — | 204; disable |
| `POST /external-identities` | `connection_id,user_id,subject` | 204 |
| `DELETE /external-identities/:connection/:user` | — | 204 |
| `POST /oauth-clients` | `application_id,resource_id,redirect_uris,public`, optional `hosted_login`, `grant_types`, `access_token_format` (`jwt`/`opaque`) | 201 `{id,client_id,client_secret}` |
| `GET /oauth-clients` | Optional `application_id` | 200 page (includes `hosted_login`) |
| `GET /oauth-clients/:id` | — | 200 client `{id,application_id,application_name,resource_id,resource_name,redirect_uris,public,hosted_login,grant_types,access_token_format,active}` |
| `PATCH /oauth-clients/:id` | `hosted_login`, `grant_types`, `access_token_format` and/or `redirect_uris` (non-empty, validated like create) | 204 |
| `DELETE /oauth-clients/:id` | — | 204 |
| `GET /login-settings` | — | 200 `{environment_id,display_name,logo_url,accent_color,theme,legal,locale,languages,updated_at}` (defaults when unset) |
| `PUT /login-settings` | `display_name` (≤100), `logo_url` (HTTPS), `accent_color` (`#rrggbb`), `theme` (incl. `font`/`heading_font`), `legal` (`privacy_url`,`terms_url`,`help_url`,`support_email`; omitted = keep), `locale`, `languages` (see [hosted login](../../guides/hosted-login.md#branding)) | 200 normalized settings |
| `GET /login-settings/clients` | — | 200 page of client styles (`client_id` set) |
| `GET /login-settings/clients/:client` | — | 200 style; 404 when the client uses the default |
| `PUT /login-settings/clients/:client` | same as `PUT /login-settings` | 200 normalized style; 404 unknown client |
| `DELETE /login-settings/clients/:client` | — | 204; 404 when it has no style |
| `GET /login-settings/organizations/:organization` | — | 200 `{environment_id,organization_id,display_name,logo_url,accent_color,theme,updated_at?}`; `null` fields inherit (all `null` when unset) |
| `PUT /login-settings/organizations/:organization` | `display_name`, `logo_url`, `accent_color`, `theme` — each optional, `null`/missing inherits (see [organization branding](../../guides/hosted-login.md#organization-branding)) | 200 normalized overrides; 404 unknown organization; audited |
| `DELETE /login-settings/organizations/:organization` | — | 204; 404 when it has none |
| `GET /login-settings/texts/catalog` | `?locale=` (default `en`) | 200 `{locale,items:[{key,default,placeholders,max_length}]}` |
| `GET /login-settings/texts` | — | 200 page of `{environment_id,client_id?,organization_id?,locale,texts,updated_at}` |
| `GET /login-settings[/clients/:client\|/organizations/:organization]/texts/:locale` | — | 200 `{environment_id,client_id?,organization_id?,locale,texts,updated_at?}` (`texts` empty when none) |
| `PUT /login-settings[/clients/:client\|/organizations/:organization]/texts/:locale` | `{texts:{key:message}}` — catalog keys of the language, plain text, same placeholders, ≤ `max_length` (see [sign-in texts](../../guides/hosted-login.md#sign-in-texts)) | 200 normalized texts; 404 unknown client/organization; audited, event `sign_in_texts.updated` |
| `DELETE /login-settings[/clients/:client\|/organizations/:organization]/texts/:locale` | — | 204; 404 when there are none; event `sign_in_texts.deleted` |
| `POST /login-settings/texts/preview` | `{page,locale?,texts,client_id?,organization_id?}` | 200 `{html}` with unsaved texts over the saved branding (write access) |
| `GET /login-settings/sign-in` | — | 200 page of clients with their own sign-in methods |
| `GET /login-settings/clients/:client/sign-in` | — | 200 `{client_id,password,email_code,organization_sso,all_connections,connection_ids,custom,updated_at}`; every method with `custom:false` when unset |
| `PUT /login-settings/clients/:client/sign-in` | `password,email_code,organization_sso,all_connections,connection_ids` (≤50 active environment connections); at least one method | 200 normalized options; 404 unknown client |
| `DELETE /login-settings/clients/:client/sign-in` | — | 204; the client offers every method again |
| `GET /login-settings/preview` | `?page=`, `?scheme=light\|dark`, optional `?client=`, optional `?organization=`, optional `?sign_in=` (JSON, see [previews](../../guides/hosted-login.md#previews)) | 200 `{html}` with the saved style |
| `POST /login-settings/preview` | `{page,scheme,settings,sign_in?}`, or `organization` (unsaved overrides over the default) instead of `settings` | 200 `{html}` with the unsaved style (write access) |
| `POST /service-accounts` | `name,application_id,resource_id,permissions`, optional `expires_in`, `token_endpoint_auth_method` (`client_secret_basic` default, `client_secret_post`, `private_key_jwt`), `token_endpoint_auth_signing_alg` (RS256 default; RS/PS/ES 256–512), `jwks` or `jwks_uri` (private_key_jwt, exactly one) | 201 `{id,secret,expires_at}` |
| `GET /service-accounts` | — | 200 page (with the authentication fields) |
| `GET /service-accounts/:id` | — | 200 account (never its secret) |
| `PUT /service-accounts/:id/authentication` | `token_endpoint_auth_method`, `token_endpoint_auth_signing_alg`, `jwks`, `jwks_uri` (the whole configuration) | 200 account; audited `service_account.authentication` |
| `PUT /service-accounts/:id/impersonation` | `allowed` (bool) — the account may impersonate users through [token exchange](oauth-oidc.md) | 200 account (`can_impersonate`); workspace owners only (403 otherwise); audited `service_account.impersonation`; `false` ends the sessions it opened |
| `DELETE /service-accounts/:id` | — | 204 |
| `POST /provisioning-credentials` | `name,organization_id`, optional `connection_id,expires_in,adopt_existing_members,adopt_scope` (`any`\|`verified_domains`), `map_phone` (sync SCIM mobile numbers) | 201 `{id,secret,expires_at,connection_id}` |
| `GET /provisioning-credentials` | — | 200 array (includes `organization_name,connection_name,adopt_existing_members,adopt_scope,map_phone`) |
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
`common`/`organizations`); Google takes `domains` (only Google Workspace
accounts of these domains, by the ID token's `hd` claim); Apple requires
`team_id` and `key_id` (a new `key_id`
needs a new `client_secret`); GitLab takes `base_url` (a self-managed
instance, else `https://gitlab.com`) and GitHub Enterprise requires it (the
server; IAMKit calls `/login/oauth/*` and `/api/v3`) — `base_url` becomes the
issuer and cannot change. `oauth2` requires `authorize_url,token_url,userinfo_url`
(HTTPS) and `claims` `{subject, email, email_verified, name}` — dotted member
paths into the user info JSON, `subject` required — plus optional `scopes`
(≤ 20); its issuer is the authorization URL's origin, so `authorize_url`
must keep its host. An `oauth2` email counts as verified only when the
`email_verified` member is `true`. `saml` requires exactly one of `metadata_url` (HTTPS, public address, fetched on create and on every `PATCH` that sends it) or `metadata_xml` (≤ 512 KiB) and takes `name_id_format` (`unspecified`\|`persistent`\|`email`\|`transient`), `attributes` `{subject,email,name}` (attribute names; `transient` requires `subject`) and `sign_requests`; its issuer is the IdP entity ID and cannot change (400). `ldap` takes `url` (`ldaps://` or `ldap://` with `start_tls: true`; plaintext is refused), `user_base_dn`, optional `bind_dn`, `user_filter` (with `{email}`/`{username}`, default `(|(mail={email})(userPrincipalName={email}))`), `ca_pem` and `attributes` `{subject,email,name}`; its issuer is the server `ldaps://host:port` and neither the host nor `user_base_dn` can change (400); clearing `bind_dn` drops the stored password. Other providers take none. `signup` requires
`signup_organization_id`; `signup_group_id` requires `signup`; `signup: false`
clears both. Organization connections reject `signup`; their `link_email`
links, even without JIT, an unlinked identity whose verified email is on a
verified domain of the organization to the existing **member** with that
email (origin `email`, audited `federation.email`); anyone else gets 401.
`update_profile` refreshes the linked user's name and avatar at every sign-in, and its
email when the provider verifies a new one, the account is passwordless and
not SCIM-managed, no other account has it and (organization connections) it
is on a verified domain (audited `federation.profile_updated`). See
[social login](../../guides/social-login.md) and
[sign-in methods](../../guides/hosted-login.md#sign-in-methods). A `secret_env`
issuer/client/secret reference must match deployment approval exactly.
SCIM rotation should reuse the stable connection ID to retain identity mappings.
Impersonation reasons must be 10–1000 trimmed characters. Do not confuse a
provisioned external ID with an OIDC subject link: they serve different protocols.

See [federation](../../guides/federation.md), [service accounts](../../guides/service-accounts.md),
[SCIM](../../guides/scim-provisioning.md), [impersonation](../../guides/impersonation.md).
