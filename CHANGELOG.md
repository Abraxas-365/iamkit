# Changelog

Changes that can affect existing deployments, newest first. Each entry lists
its **incompatible changes** first: what behaved differently before, and what
to do about it.

## Unreleased — MCP authorization, phase (c): dynamic client registration

### Incompatible changes

- **External client views carry `source`.** `GET …/protected-resources/:id/clients`
  and `…/clients/:client` add `source` (`cimd` or `dcr`). A `dcr` client has
  an empty `host`: its `client_id` (`dcr_…`) is all there is to show.
  `iamclient.ExternalClient.Source` and the Node/Python types follow; the CLI
  `clients list` adds a `KIND` column and prints `(unverified)` for the host.
- **The `client_documents_reconcile` job follows both features.** It now also
  demotes approved dynamically registered clients of environments whose
  `dynamic_client_registration` feature is off (`feature_disabled`).

Dynamic client registration (RFC 7591, migration 023) is off by default:
the environment feature `dynamic_client_registration` and a server's
`allow_dynamic_registration` turn it on. `POST /oauth/register` and
discovery's `registration_endpoint` exist only while some environment takes
such clients (404 and absent otherwise). Registrations are public,
immutable and inert until a signed-in user asks for a server that allows
them; no allowlist entry or preset admits them. New job
`client_registration_prune`. See
[Protect an MCP server](docs/guides/applications/protect-mcp-server.md#dynamic-client-registration).

## Unreleased — MCP authorization, phase (b): client admission

### Incompatible changes

- **Approving a document client needs `metadata_hash`.** `POST
  …/protected-resources/:id/clients/:client/approve` (management and
  `/api/v1`) now requires `metadata_hash`, the value `GET …/clients/:client`
  (and the list) returns for the redirect URIs, `jwks_uri` and authentication
  method you reviewed. Without it the answer is 400; if the document changed
  since, 409 `CLIENT_METADATA_CHANGED` and nothing is approved. Callers send
  the hash they read: `iamclient.ClientApproval.MetadataHash`,
  `approveClient(…, {metadata_hash})`, `approve_client(…, metadata_hash=…)`,
  `iam protected-resources clients approve --metadata-hash`. The console does
  it itself.
- **Discovery no longer always says `client_id_metadata_document_supported`.**
  It is `true` only when the `client_metadata_documents` feature is on in
  some environment that has an active protected resource allowing metadata
  documents; otherwise `false`.
- **Template and document redirect URIs follow RFC 8252.** A custom scheme
  must be a reverse-domain private-use scheme (`com.example.app:/cb`); bare
  schemes (`cursor:`) are refused. The `cursor`, `antigravity` and
  `gemini_cli` templates use the redirects those tools actually send.
- **Several replicas without Redis are refused when declared.** With
  `IAMKIT_REPLICAS` above 1 and no `REDIS_URL` IAMKit does not start; the
  Helm chart fails to render for `replicaCount` (or `autoscaling.maxReplicas`)
  above 1 without `redis.existingSecret`. Set up Redis, or run one replica.

- **Approvals by policy end with the policy, and turning documents off ends
  them all.** Removing an allowlist entry or preset, or switching a server
  from `open` to `allowlist`, returns the clients only that rule admitted to
  pending and revokes their grants; turning `allow_client_metadata` or the
  `client_metadata_documents` feature off stops every document client of the
  server at once, manual approvals included (they return to pending,
  `oauth_client.demoted`). Before, approvals outlived the rule that gave
  them. Turning documents back on does not restore everything: turning
  `allow_client_metadata` on again re-admits the waiting clients the
  server's policy covers, while clients demoted when the feature went off
  stay pending until IT approves them (or the policy is touched again).
  Manual approvals are never restored. Removing an allowlist entry or preset
  leaves manual approvals alone. New job `client_documents_reconcile`
  (migration 022 adds the supporting indexes and
  `oauth_client_access_requests.organization_id`).
- **New 429 codes.** `CLIENT_ACCESS_REQUEST_LIMIT` (a user keeps 5 requests
  for waiting clients, an organization 50, per 24 h) and
  `CLIENT_METADATA_FETCH_BUDGET` (replaces the generic `TOO_MANY_REQUESTS`
  for document fetches; adds a limit of 10 fetches a minute per client
  address, so set `IAMKIT_TRUSTED_PROXIES` behind a proxy). Approved clients
  whose host is down keep working from stored metadata for up to 48 hours.

Clients named by a Client ID Metadata Document wait for IT before they can
sign anyone in (migrations 020 and 021). See
[Protect an MCP server](docs/guides/applications/protect-mcp-server.md#admit-clients-named-by-a-metadata-document).

- **Deleting a protected resource now deletes its document clients** with
  their grants, sessions and device codes (before, the grants blocked it).
  `…/impact` adds `external_clients`.
- **Blocking a client, or the end of its approval, stops its tokens at
  once**: refresh, introspection and opaque tokens are refused, and the
  sessions are revoked in the same transaction (blocking) or by the
  `client_admission_expire` job.
- **Console, CLI and SDKs manage admission.** The resource page lists the
  clients (pending/approved/blocked) and the server's admission settings; the
  environment has an *MCP client allowlist* page with the known-clients
  gallery; `iam protected-resources clients`, `iam client-allowlist` and
  `iam client-presets`, `iamclient`, `@iamkit/node` and `iamkit` expose the
  same routes. Nothing changes for existing callers.
- **Refused external clients get a hosted page**, never a redirect: pending,
  blocked, too many waiting, registered clients only, documents disabled.
  `Accept: application/json` still gets the error.

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
