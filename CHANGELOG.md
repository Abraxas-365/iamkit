# Changelog

Changes that can affect existing deployments, newest first. Each entry lists
its **incompatible changes** first: what behaved differently before, and what
to do about it.

## Unreleased — MCP authorization, phase (a): protected resources

IAMKit can act as the authorization server of remote MCP servers and other
OAuth resource servers: protected resources (migration 018), the RFC 8707
`resource` parameter, RFC 8414 discovery, and resource-server SDKs for Go
(`sdk/resourceserver`) and Node.js (`@iamkit/node/resource-server`). See
[Protect an MCP server](docs/guides/applications/protect-mcp-server.md).
OpenID Connect clients that never send `resource` behave as before, apart
from the changes below.

### Incompatible changes

- **An unknown `resource` is refused with `invalid_target`.** An authorize or
  token request whose `resource` is not the protected URL of the client's
  resource (or that repeats `resource`) now fails with `invalid_target`
  ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). Before, the
  parameter was ignored. *Action:* clients that send `resource` must send the
  protected resource's exact URL, or stop sending it.
- **`/.well-known` documents no longer allow credentialed CORS.** The
  discovery documents (`/.well-known/openid-configuration`,
  `/.well-known/oauth-authorization-server`) and the JWKS answer any origin
  with `Access-Control-Allow-Origin: *` and without
  `Access-Control-Allow-Credentials`, even for the deployment's
  `CORS_ALLOWED_ORIGINS`, as browser-based MCP clients need. *Action:* browser
  code that fetched them with `credentials: "include"` must drop it; none of
  them reads cookies. `/oauth/token` and `/oauth/revoke` keep credentialed
  CORS for configured origins and, for any other origin, accept the
  preflight and expose the answer only to public clients.
- **Deactivating or deleting a protected resource ends its sessions.** Every
  OAuth session of the resource ends at once, including those of OpenID
  Connect clients of that resource that never sent `resource`; their users
  must sign in again. `GET …/protected-resources/:id/impact` returns how many
  sessions that is, and the console shows the number before you confirm.
- **Lowering the environment's lifetime ceiling cuts existing
  authorizations.** At each refresh an authorization ends at the earlier of
  its original end and its sign-in plus the current
  `max_lifetime_ttl_seconds`. Cutting the ceiling from 90 to 30 days ends
  authorizations older than 30 days at their next refresh.
- **Resource servers refuse tokens without the `resource` claim.** Access
  tokens of the resource flow carry `resource` = the protected URL. The Go
  and Node.js resource-server SDKs require it by default: an ordinary OpenID
  Connect token, even one whose `aud` is the server's URL, gets `401
  invalid_token`. Accepting such tokens takes an explicit
  `AllowTokensWithoutResource: true` / `allowTokensWithoutResource: true`.
- **Resource-server permissions come from the granted scopes.** The SDKs'
  `Permissions` / `permissions` and `require` checks use the token's granted
  scopes (OAuth protocol scopes such as `openid` removed), not its
  `permissions` claim.
- **`resource` is a reserved claim.** Actions answering with a `resource`
  claim now fail like any other reserved claim (`ACTION_FAILED` when the
  target interrupts on error).
