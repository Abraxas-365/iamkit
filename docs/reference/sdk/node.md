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
| Sign a machine user in | `KeyLogin` (JWT-bearer grant), `IdentityClient.exchangeAPIKey` (a machine `ik_key_` API key) |
| Accept customers' [API keys](../../guides/machines/api-keys.md) | `createAPIKeyValidator` (or `validateAPIKey`), or `authenticate` with `allowApiKeys` |
| Act for a user | `OAuthClient.exchangeToken` (another resource), `OAuthClient.impersonate` (service account with `can_impersonate`) |
| Devices without a browser | `OAuthClient.authorizeDevice` + `waitForDevice` |
| Receive events and actions | `verifyWebhook`, `verifyAction`, `deny` |
| Emit and read [app audit logs](../../guides/audit-logs.md) | `AuditLogsClient` (`createEvent` with `idempotencyKey`, `listEvents`, `getEvent`, `exportEvents` + `decodeAuditLogEvents`) |
| Protect an OAuth resource server (MCP) | `@iamkit/node/resource-server`: `createResourceServer` (`metadataHandler`, `protect`, `require`, `verify`), `resourceClaimsOf`; see [protect an MCP server](../../guides/applications/protect-mcp-server.md) |
| Register protected resources | `ProtectedResourcesClient` (`list`, `get`, `create`, `update`, `delete`, `impact`, `policy`, `setPolicy`; client admission: `clients`, `client`, `clientRequests`, `approveClient`, `blockClient`, `unblockClient`, `forgetClient`, `createClientFromTemplate`, `allowlist`, `createAllowlistEntry`, `deleteAllowlistEntry`, `presets`, `applyPreset`) |
| Administer an environment | `createManagementClient` (`X-API-Key`), `createApiClient` (bearer, `/api/v1` and SCIM) |

## Verification rules

`createJwtVerifier` accepts RS256 tokens of the configured issuer and audience
whose `environment_id`, `application_id` and `resource_id` match the
configuration. `application` tokens must carry an organization and a session;
`machine` tokens must carry neither; any other purpose is refused. Failures
reject with `IAMKitError` 401 `UNAUTHORIZED`; a JWKS that cannot be fetched is
503 `JWKS_UNAVAILABLE`, which `authenticate` answers as 503 rather than 401.
API keys (`ik_key_`) and opaque OAuth tokens (`ory_at_`) are not JWTs: validate
API keys with `createAPIKeyValidator`/`validateAPIKey`, and resolve opaque OAuth
tokens through a confidential OAuth client's introspection endpoint.

`requireOrganization` takes a fixed ID or a function reading the requested
organization from the request; the token's `organization_id` must match, so a
route parameter is never trusted on its own. See [token claims](../token-claims.md)
and the Go [middleware](middleware.md) rules, which these mirror.

## API keys

`createAPIKeyValidator({baseUrl, environmentId, audience})` returns an
`APIKeyValidator` whose `validate(rawKey)` checks an `ik_key_`
[API key](../../guides/machines/api-keys.md#validate-keys-in-your-backend)
online with `POST /identity/v1/introspect` and resolves to an `APIKey`:
`id`, `name`, `owner` (`type` `user`, `organization` or `machine`; `id`;
`organization_id`), `organization_id`, `resource_id`, the **effective**
`permissions` and `expires_at` (Unix seconds, `0` = never). Unknown, revoked,
expired or disabled keys, values that are not API keys and an audience other
than the key's resource reject with 401 `UNAUTHORIZED`; an unreachable IAMKit
rejects with its own error, so fail closed. `validateAPIKey(rawKey, options)` is
the one-shot form; `isAPIKey`, `APIKeyPrefix` and `hasAPIKeyPermission(key,
…permissions)` are small helpers.

```ts
const keys = createAPIKeyValidator({ baseUrl, environmentId, audience })
app.use(authenticate(verifier, { allowApiKeys: keys }))
app.get("/invoices", requirePermissions("invoices:read"), (req, res) => {
  const key = apiKeyOf(req) // set instead of claimsOf(req) for an API key
})
```

`authenticate(verifier, { allowApiKeys })` accepts keys only when given a
validator (otherwise an `ik_key_` bearer is 401); the key lands on
`req.iamkitKey` (`apiKeyOf(req)`) and `claimsOf(req)` is `undefined`.
`principalOf(req)` returns `{claims}` or `{apiKey}`; `requirePermissions` and
`requireOrganization` accept both, and `requireMFA` refuses keys (no session).
`new IdentityClient({baseUrl}).exchangeAPIKey(key)` trades a machine user's key
for an access token (user and organization keys cannot be exchanged), and
`identity.me(accessToken, environmentId, audience)` returns a `MeAPIKeys` for
the user's own keys (`list({limit, offset})`, `options()`,
`create({resourceId, name, permissions, expiresIn})`, `revoke(id)`; creating
needs a sign-in within 10 minutes).
`APIKeysClient({baseUrl, token})` administers keys on `/api/v1`: `list`, `get`,
`create` (organization keys), `revoke`, `policy`, `savePolicy`,
`setResourceAPIKeyPermissions`, `userKeys`, `createMachineKey`,
`revokeUserKey`, and for organization administrators `listOrganization`,
`organizationOptions`, `getOrganizationKey`, `createOrganizationKey` and
`revokeOrganizationKey`; each takes the environment (and organization) ID first.

## Audit logs

`AuditLogsClient({baseUrl, token})` (`token` is a string or a function) wraps
`/api/v1/environments/:env/audit-logs/events`: `createEvent(env, event, {idempotencyKey})`
(`iam:audit-logs:write`; a retry with the same key answers the first receipt, a
different event under it is 409 `IDEMPOTENCY_KEY_REUSED`), `listEvents(env, filter)`
→ `{items, next}`, `getEvent(env, id)` and `exportEvents(env, filter, {format, signal})`
→ a `ReadableStream` of NDJSON (default) or CSV that `decodeAuditLogEvents`
turns into events. Organization administrators call `listOrganizationEvents` and
`exportOrganizationEvents` (`iam:org:audit:read`, own organization only). The
raw typed client (`createApiClient`) also covers actions and
[log streams](../../guides/platform/log-streams.md).

## Errors

Every failure is an `IAMKitError` with `status`, `code`, `message` and
`details`. IAMKit envelopes keep their code (`PASSWORD_CHANGE_REQUIRED`,
`QUOTA_EXCEEDED`, …); OAuth endpoints keep the OAuth `error`
(`invalid_grant`, `authorization_pending`, …). Requests time out after 10 s
(`timeoutMs`), follow no redirects and read at most 1 MiB.

Usage examples are in the [package README](../../../clients/node/README.md).
Build and test: `cd clients/node && npm ci && npm run typecheck && npm test && npm run build`.
