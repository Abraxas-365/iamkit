# Node.js SDK

`@iamkit/node` (`clients/node`) is the server-side SDK for Node.js 20 and
later. It is the TypeScript counterpart of the [Go SDK](go.md): token
verification and middleware, the OAuth client, machine-user key login,
webhook and action verification, plus typed REST clients generated from the
[OpenAPI document](../api/openapi.md) (`@iamkit/api`). Browser sign-in UIs use
`@iamkit/js` and `@iamkit/react` instead
([custom sign-in UI](../../guides/applications/custom-sign-in-ui.md)).

| Need | Use |
| --- | --- |
| Accept access tokens in an API | `createJwtVerifier` (offline, cached JWKS) or `createIntrospectionVerifier` (online, sees revocation at once) + `authenticate` |
| Authorize a route | `requirePermissions`, `requireOrganization`, `requireMFA` |
| Sign users in to a server-rendered app | `OAuthClient` (`authorizationUrl`, `exchangeCode`, `refresh`, `endSessionUrl`), `createPKCE`, `verifyIdToken` |
| End sessions on back-channel logout | `verifyLogoutToken` |
| Call APIs as a service | `OAuthClient.clientCredentials` (secret or `private_key_jwt`), `IdentityClient.machineToken` |
| Sign a machine user in | `KeyLogin` (JWT-bearer grant), `IdentityClient.exchangeAccessToken` (`ik_pat_`) |
| Act for a user | `OAuthClient.exchangeToken` (another resource), `OAuthClient.impersonate` (service account with `can_impersonate`) |
| Devices without a browser | `OAuthClient.authorizeDevice` + `waitForDevice` |
| Receive events and actions | `verifyWebhook`, `verifyAction`, `deny` |
| Administer an environment | `createManagementClient` (`X-API-Key`), `createApiClient` (bearer, `/api/v1` and SCIM) |

## Verification rules

`createJwtVerifier` accepts RS256 tokens of the configured issuer and audience
whose `environment_id`, `application_id` and `resource_id` match the
configuration. `application` tokens must carry an organization and a session;
`machine` tokens must carry neither; any other purpose is refused. Failures
reject with `IAMKitError` 401 `UNAUTHORIZED`; a JWKS that cannot be fetched is
503 `JWKS_UNAVAILABLE`, which `authenticate` answers as 503 rather than 401.
Personal access tokens (`ik_pat_`) and opaque OAuth tokens (`ory_at_`) are not
JWTs: exchange or introspect them.

`requireOrganization` takes a fixed ID or a function reading the requested
organization from the request; the token's `organization_id` must match, so a
route parameter is never trusted on its own. See [token claims](../token-claims.md)
and the Go [middleware](middleware.md) rules, which these mirror.

## Errors

Every failure is an `IAMKitError` with `status`, `code`, `message` and
`details`. IAMKit envelopes keep their code (`PASSWORD_CHANGE_REQUIRED`,
`QUOTA_EXCEEDED`, …); OAuth endpoints keep the OAuth `error`
(`invalid_grant`, `authorization_pending`, …). Requests time out after 10 s
(`timeoutMs`), follow no redirects and read at most 1 MiB.

Usage examples are in the [package README](../../../clients/node/README.md).
Build and test: `cd clients/node && npm ci && npm run typecheck && npm test && npm run build`.
