# API walkthrough

JSON request bodies; management endpoints require `Authorization: Bearer ik_mgmt_...`. IDs are UUIDs returned by creation endpoints. Secrets are returned once; keep them server-side. Responses with credentials and identity tokens are sensitive.

For task-oriented, end-to-end walkthroughs (new product onboarding, Google login, SCIM, service accounts, impersonation, OAuth clients), see [Recipes](recipes.md).

## Errors

Backend errors use `internal/errx`. HTTP failures return a structured envelope:

```json
{"error":{"code":"FORBIDDEN","message":"insufficient permissions","type":"AUTHORIZATION","http_status":403}}
```

Clients should inspect `code` and the HTTP status, not match message text. Wrapped errors preserve their classification. Causes and internal details are not exposed; server failures use generic messages. Invalid-token introspection still returns `{"active":false}`.

## Provision a product

1. `GET /management/v1/me` → workspace/operator IDs and administrative role.
2. `POST /management/v1/projects` with `{"name":"InvoiceCloud"}` → project ID.
3. `POST /management/v1/projects/{project}/environments` with `{"name":"production"}` → environment ID. Repeat for development; identities remain separate.

The following paths have prefix `/management/v1/environments/{environment}`:

| Method / path | Example body |
| --- | --- |
| POST `/users` | `{"email":"alice@example.com","name":"Alice","password":"a-long-initial-password"}` |
| POST `/organizations` | `{"name":"Acme"}` |
| POST `/memberships` | `{"organization_id":"ORG","user_id":"USER","role":"owner"}` |
| POST `/applications` | `{"name":"Web","redirect_uris":["https://app.example/callback"]}` |
| POST `/resources` | `{"name":"Billing API","audience":"https://billing.example","permissions":["invoices:read"]}` |
| POST `/application-resources` | `{"application_id":"APP","resource_id":"RESOURCE"}` |
| PUT `/grants` | `{"organization_id":"ORG","user_id":"USER","resource_id":"RESOURCE","permissions":["invoices:read"]}` |
| POST `/service-accounts` | `{"name":"Worker","application_id":"APP","resource_id":"RESOURCE","permissions":["invoices:read"]}` |

Application names have no special semantics. An organization owner still needs a resource grant to use that resource. An empty grant gives a valid session with no resource permissions; membership alone does not issue a token. No email ownership verification is inferred from provisioning.

Users/organizations can be listed with GET on their collection paths (first 100). Projects and environments also have GET collection routes. Additional inventories and management operations are described below.

## User login

`POST /identity/v1/login` (no management key):

```json
{
  "environment_id": "ENV",
  "organization_id": "ORG",
  "application_id": "APP",
  "resource_id": "RESOURCE",
  "email": "alice@example.com",
  "password": "a-long-initial-password"
}
```

Response: `access_token`, `refresh_token`, `token_type: Bearer`, `expires_in: 900`. The token is bound to that environment/client/resource/organization. To switch organizations, authenticate for that organization; its independent membership/grant is checked. `POST /identity/v1/refresh` accepts the same four boundary IDs plus `refresh_token`. Each use rotates the refresh credential; replay revokes the session family. The family has a fixed 24-hour lifetime.

## Machine login

`POST /identity/v1/machine-token` with `Authorization: Bearer ik_svc_...` returns a `purpose: machine` access token. It has no user membership or organization-owner privileges.

## Validate and revoke

`POST /identity/v1/introspect` with the application/machine access token as Bearer and body:

```json
{"environment_id":"ENV","audience":"https://billing.example"}
```

Returns `{"active":false}` or `{"active":true,"claims":{...}}`. Consumers must additionally enforce expected client/resource/organization and the required exact permission. Never derive expected audience/environment solely from the incoming token. The current Go SDK offline validator requires these configured boundaries, but cannot detect immediate revocation.

`POST /identity/v1/logout` accepts the same body and a user access token and revokes its session. Machine tokens cannot use user logout.

Management revocation:

- `DELETE /environments/{environment}/users/{id}` suspends a user.
- `DELETE /environments/{environment}/organizations/{org}/members/{user}` disables membership.
- `DELETE /environments/{environment}/grants/{id}` removes business access and revokes its sessions.
- `DELETE /environments/{environment}/service-accounts/{id}` revokes a machine credential and its tokens online.

These paths above use the `/management/v1` prefix. Offline JWT verifiers observe expiration, not these live revocations.

## Operator administration

- `POST /management/v1/keys` rotates by issuing another credential for the authenticated operator, including viewers. Revoke the old one separately.
- `GET /management/v1/keys` lists own credential metadata (owners see the workspace inventory); hashes/secrets are never returned.
- `DELETE /management/v1/keys/{id}` revokes an own key, or any workspace key for owners.
- `POST /management/v1/operators` with `{"email":"admin@example.com","role":"admin"}` delegates access (owner only); `viewer` is also supported. Response contains operator ID, key ID, one-time secret and expiry. Repeating the request for an active member with the same role issues a replacement key (including after expiry); it does not change roles, reactivate disabled members or revoke existing keys.
- `DELETE /management/v1/operators/{id}` disables a non-owner and all their keys (owner only).

Owner transfer/removal and per-project operator roles are not yet exposed. Local `recover-owner` replaces all credentials for an existing active owner after expiry or loss, never promotes another operator.

## Organization self-service

`POST /identity/v1/memberships` with a user Bearer token and `{"environment_id":"ENV","audience":"API_AUDIENCE","user_id":"EXISTING_USER"}` lets an active organization owner/admin add a same-environment user as an ordinary member. The destination organization comes from the authenticated session, not request input. This neither assigns a resource grant nor creates management authority. Invitation email flows are future work.

## Profiles, OTP and recovery

- `GET /identity/v1/me` and `/identity/v1/organizations`: user bearer, trusted `environment_id` and `audience` query parameters. Only the authenticated user's profile/organizations are returned.
- `PATCH /identity/v1/me`: user bearer and `{environment_id,audience,name}`. Impersonated tokens cannot change this profile.
- `POST /identity/v1/challenges`: `{environment_id,email,purpose}` where purpose is `login`, `email_verification` or `password_reset`. Always returns a generic 202 challenge response for eligible/unknown users. Requires a configured email webhook.
- `POST /identity/v1/challenges/verify`: `{environment_id,challenge_id,purpose,code}` plus the four login boundary IDs for `login`, or `password` for reset. Login returns a token pair; verification/reset return 204.
- OTP login requires management user `otp_enabled:true`. Turning it off invalidates pending login challenges. Enabling OTP does not mark an email verified. Password reset requires an existing password; it cannot add one to a federation-only account.
- Management user creation permits an omitted password for passwordless/federated identities; email/name are still required.

`EMAIL_WEBHOOK_URL` must be HTTPS; the POST JSON body contains `email`, `purpose`, `code`. `EMAIL_WEBHOOK_TOKEN` is sent as Bearer when configured. Never log codes.

## Administration extensions

All paths below are relative to `/management/v1/environments/{environment}`. Mutations require operator owner/admin; read-only viewers can inspect inventories.

- GET collections: `/applications`, `/resources`, `/grants`, `/roles`, `/service-accounts`, `/sessions`, `/audit-events`.
- GET detail: `/users/{id}`, `/organizations/{id}`, `/applications/{id}`, `/resources/{id}`, `/roles/{id}`, `/grants/{id}`.
- PATCH `/users/{id}`: `name`, `active`, `metadata`, `otp_enabled`. PATCH `/organizations/{id}`: `name`, `active`, `metadata`. PATCH `/applications/{id}`: `name`, `active`, `redirect_uris`.
- PUT `/resources/{id}`: `name`, `permissions`. Audience stays immutable. Removed permissions are stripped from existing direct grants, roles and service accounts; concurrent permission writers must obey the current catalog.
- POST `/roles`, PUT `/roles/{id}`: `{name,resource_id,permissions}`; DELETE removes a role. POST `/role-assignments`: `{organization_id,user_id,role_id}`. DELETE `/role-assignments/{role}/{organization}/{user}` removes an assignment.
- Organization paths use `/organizations/{organization}`: GET `/members`, PUT `/members/{user}/profile` with `{org_unit_id,manager_id}` (nullable; full replacement of both).
- GET/POST `/org-units`; GET/PUT/DELETE `/org-units/{id}`. Body `{name,kind,parent_id}`; kind is configurable. `/org-units/{id}/ancestors`, `/descendants`, `/delete-impact` are GET reads. GET `/tree` returns ordered nodes with parent IDs/path, not a nested UI tree. GET `/org-chart` returns membership reporting relationships. Referenced units cannot be deleted until dependants are reassigned.
- GET/POST `/positions`; PUT/DELETE `/positions/{id}` with `{name,code}`. GET/POST `/position-assignments` with `{position_id,user_id,org_unit_id}`; DELETE `/position-assignments/{id}`.
- DELETE `/sessions/{id}` revokes a user session. Audit records cover selected mutations/impersonation, not every request.
- POST `/impersonations`: `{organization_id,application_id,resource_id,user_id,reason}`. Owner only; reason 10–1000 characters. Returns a 15-minute token with `actor_id`, never refresh. Target access is checked normally.

## External federation

1. Deployment administrator sets `FEDERATION_CREDENTIAL_BINDINGS` to a JSON array of exact `{environment_id,issuer,client_id,secret_env}` tuples. Secret variable names must match `IAMKIT_PROVIDER_[A-Z0-9_]+`. Bindings are rechecked at runtime; changing them withdraws credential approval.
2. Management POST `/federation-connections` with `{name,issuer,client_id,secret_env}`. Issuer and provider endpoints must use HTTPS. Google uses `https://accounts.google.com`; Microsoft should use a tenant-specific OIDC issuer. Test your actual provider configuration before deployment.
3. Management POST `/external-identities` with `{connection_id,user_id,subject}` explicitly links a provider subject. No email auto-linking or public account enumeration.
4. Browser POST `/identity/v1/federation/start` with `{connection_id,environment_id,organization_id,application_id,resource_id}` returns `authorization_url` and sets a secure binding cookie. Navigate to that URL.
5. Provider callback `/identity/v1/federation/callback` verifies binding/state/code/issuer/nonce/subject and returns an IAMKit token pair. Register this exact HTTPS callback at the provider. This is headless JSON, not a hosted post-login redirect UI.

DELETE `/federation-connections/{id}` disables the connection.

## OAuth/OIDC server

Management POST `/oauth-clients` with `{application_id,resource_id,redirect_uris,public}`. Public clients have no secret; confidential credentials are returned once. DELETE `/oauth-clients/{id}` disables the client. OAuth clients have their own exact redirect allow-list, separate from application metadata.

Discovery: `GET /.well-known/openid-configuration`, signing keys: `GET /.well-known/jwks.json`.

1. GET `/oauth/authorize` with `client_id`, exact `redirect_uri`, `response_type=code`, `scope=openid offline_access`, random `state`/`nonce`, `code_challenge_method=S256`, `code_challenge`. Returns an `authorization_ticket` and secure browser-binding cookie.
2. Your UI authenticates the user with the matching application/resource context, obtains explicit approval and POSTs `/oauth/authorize/complete` with user Bearer, cookie and `{authorization_ticket,approve:true}`. The response redirects to the registered URI with code/state. Impersonation tokens are rejected. `prompt` and `max_age` are currently unsupported and rejected; no fresh-authentication claim is fabricated.
3. Form POST `/oauth/token`: authorization code, original `redirect_uri`, `code_verifier`, `client_id`, `grant_type=authorization_code`. Confidential clients use HTTP Basic authentication. Tokens include resource-bound access, OIDC ID token, and refresh when requested. ID tokens must never authorize API requests.
4. Form POST `/oauth/token` with `grant_type=refresh_token`, `refresh_token`, client authentication rotates the family. Replay (including concurrent replay) invalidates the family's OAuth access/refresh credentials.
5. Form POST `/oauth/revoke` with `token` and client authentication revokes OAuth tokens. IAMKit `/identity/v1/introspect` is the supported live API-token validation endpoint; no general RFC token introspection or userinfo endpoint is advertised.

Use HTTPS in browsers. Authorization binding cookies are `__Host-`/Secure; this interaction intentionally does not work on arbitrary plain-HTTP deployments. OAuth errors use protocol-standard envelopes instead of the regular errx envelope.

## SCIM

Management POST `/provisioning-credentials`: `{name,organization_id,connection_id?}` returns a one-time `ik_scim_` secret, ID, connection ID and expiry. Supply the existing connection ID during rotation, then DELETE `/provisioning-credentials/{id}` to revoke the old credential. External identity ownership survives rotation.

Explicit operator linking: POST `/provisioned-identities` with `{connection_id,user_id,external_id}` requires an existing membership in the connection's organization. This is the only way to attach an existing identity; SCIM email collisions never auto-link.

Use the scoped secret as Bearer under `/scim/v2`:

- GET `/ServiceProviderConfig`, `/ResourceTypes`, `/ResourceTypes/User`, `/Schemas`, `/Schemas/{schemaURN}`.
- GET/POST `/Users`, GET/PUT/PATCH/DELETE `/Users/{id}`. DELETE deactivates the organization membership, not other memberships.
- List supports `startIndex`, `count` (0–100), and `filter=userName eq "..."` or `externalId eq "..."`.
- Create accepts `userName`, `externalId`, `displayName`, `active`. Email collisions fail rather than implicitly attaching an existing user.
- PATCH supports add/replace `active`, `displayName`, enterprise `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value` or `:manager`. Empty manager value clears it. Manager IDs must be provisioned by the same connection; cycles fail. Unspecified PATCH fields are not rewritten.
- Identity identifiers remain immutable. SCIM errors use SCIM Error schemas; bulk/groups/sort/password changes are not supported.

## Go SDK

`sdk/iamclient` provides typed environment management plus a generic management-relative `Do`. `sdk/authclient` includes password/challenge/refresh/profile clients, OAuth exchange/refresh/revoke, PKCE generation, offline validation and live `Introspect`. `sdk/authclient/fiberauth` accepts a configured validator and enforces exact permissions/organization. `sdk/scimclient` supplies typed user provisioning operations. SDK errors use public `apierror.Error`; OAuth errors use `OAuthError`. All credential-carrying clients refuse redirects.

