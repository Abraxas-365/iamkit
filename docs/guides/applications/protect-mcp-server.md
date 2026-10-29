# Protect an MCP server with IAMKit

Use IAMKit as the OAuth 2.1 authorization server of a remote
[MCP](https://modelcontextprotocol.io) server (Streamable HTTP), as the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
describes. MCP clients such as Claude Code, MCP Inspector, VS Code or Codex
discover IAMKit from your server, sign the user in through IAMKit's hosted
pages and call your server with an access token issued for it alone.

This guide covers what ships today: pre-registered clients, RFC 8707 resource
indicators, scopes mapped to permissions with step-up, and the
resource-server SDKs, and clients named by a Client ID Metadata Document
with IT approval (see below). Dynamic client registration comes in a later
phase.

A runnable example with a seeded stack is in
[`examples/mcp-server`](../../../examples/mcp-server/README.md).

## How it fits together

1. The client calls your server without a token. Your server answers `401`
   with `WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`.
2. The client reads that protected resource metadata
   ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)), which names IAMKit's
   issuer in `authorization_servers`, then IAMKit's
   `/.well-known/oauth-authorization-server`
   ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414); the same document as
   `/.well-known/openid-configuration`).
3. The client runs authorization code + S256 PKCE with
   `resource=https://mcp.example.com/mcp`
   ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). The user signs in on
   IAMKit's hosted pages and picks an organization.
4. IAMKit issues an access token whose `aud` is your server's URL and whose
   `scope` lists the permissions granted, plus a refresh token.
5. Your server verifies the token and serves the request, or answers `403
   insufficient_scope` when a tool needs more, and the client authorizes
   again with the wider scope.

Each MCP server is an IAMKit **resource** whose audience is the server's
canonical URL, registered as a **protected resource** of the application
that holds its clients. A token for one server is never accepted by another,
and the server never forwards it.

## Register the server

Create the resource, link it to an application and register it as a protected
resource (management API; `/api/v1` needs `iam:protected-resources:write`):

```sh
# The resource: audience = the server's URL, one permission per scope.
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/resources" -H "X-API-Key: $MGMT" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Notes MCP","prefix":"notes","audience":"https://mcp.example.com/mcp","permissions":["notes:read","notes:write"]}'

curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/application-resources" -H "X-API-Key: $MGMT" \
  -H 'Content-Type: application/json' -d "{\"application_id\":\"$APP\",\"resource_id\":\"$RESOURCE\"}"

curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/protected-resources" -H "X-API-Key: $MGMT" \
  -H 'Content-Type: application/json' \
  -d "{\"application_id\":\"$APP\",\"resource_id\":\"$RESOURCE\",\"name\":\"Notes\",\"default_scopes\":[\"notes:read\"]}"
```

The resource's audience must already be canonical, and is the protected
resource's `uri`:

- an absolute `https` URL (`http` only on `localhost`, `127.0.0.1` or `[::1]`);
- lowercase scheme and host, no default port, no userinfo, query or fragment;
- no empty, `.` or `..` path segments and no trailing slash
  (`https://mcp.example.com` rather than `https://mcp.example.com/`).

Path case and percent-encoding are kept as given. Otherwise creation
answers `422`. A URL belongs to one protected resource in the whole
deployment (`409` otherwise), and the IAM resource cannot be protected.

| Field | Default | Meaning |
|-------|---------|---------|
| `default_scopes` | `[]` | Granted when a client asks for no scope; publish them as your metadata's `scopes_supported` |
| `idle_ttl_seconds` | 7 days | How long a refresh token lives unused |
| `max_ttl_seconds` | 30 days | How long the whole authorization lives from sign-in, refreshes included |
| `active` | `true` | `false` ends every authorization of the server (`PATCH`) |

`GET`/`PATCH`/`DELETE …/protected-resources/:id` read, change and remove it.
Deleting or deactivating a protected resource ends the OAuth sessions of
its resource, including those of OpenID Connect clients that never sent
`resource`. After that, `resource=<uri>` is refused with `invalid_target`.
`GET …/protected-resources/:id/impact` answers `{"active_sessions": n}`, the
live sessions either would end; the console shows it before confirming.

The environment's ceilings are at `…/protected-resource-policy`.
`max_idle_ttl_seconds` defaults to 30 days and `max_lifetime_ttl_seconds` to
90 days. A server's TTLs above a ceiling are refused, and lowering a ceiling
trims the servers above it. A lowered ceiling also applies to authorizations
already granted: at each refresh an authorization ends at the earlier of its
original end and its start (the sign-in) plus the current lifetime. Cutting
the lifetime from 90 to 30 days refuses the next refresh of an authorization
that is 40 days old, and one that is 10 days old now ends at day 30. Raising
a ceiling never extends an authorization. The next refresh token also gets
the new idle window. Changes are audited as
`protected_resource.created`, `.updated`, `.deleted` and
`protected_resource_policy.updated`.

## Register the MCP clients

Each MCP client is a **public** OAuth client of the same application and
resource, with `hosted_login` and its loopback redirect URIs:

```sh
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/oauth-clients" -H "X-API-Key: $MGMT" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"Claude Code\",\"application_id\":\"$APP\",\"resource_id\":\"$RESOURCE\",\"public\":true,\"hosted_login\":true,
       \"redirect_uris\":[\"http://localhost:19876/callback\",\"http://127.0.0.1:19876/callback\"]}"
```

| Client | Redirect URIs | Use the client ID with |
|--------|---------------|------------------------|
| Claude Code | `http://localhost:<port>/callback` | `claude mcp add --transport http --client-id <id> --callback-port <port> <name> <url>` |
| MCP Inspector (CLI) | `http://127.0.0.1:6276/oauth/callback` | `npx @modelcontextprotocol/inspector --cli <url> --client-id <id> …` |
| MCP Inspector (web) | `http://localhost:6274/oauth/callback` | the client ID field of the web UI's OAuth settings |

A registered `http://127.0.0.1` or `http://[::1]` redirect matches any port,
so it suits clients that pick a port at random. A `http://localhost` redirect
must match exactly. IAMKit's token, revocation and metadata endpoints allow
any origin without credentials, so browser-based clients such as MCP
Inspector's web UI can call them.

## Admit clients named by a metadata document

An MCP client such as Claude Code or VS Code does not need a pre-registered
client: its `client_id` is the https URL of its Client ID Metadata Document.
IAMKit reads the document (guarded, cached, never from a private address)
the first time a user signs in with it, and the client **waits for IT**. The
user sees a page that shows the client's host first (the one thing IAMKit
can vouch for), the document's own name marked *unverified* unless the URL
is a known preset, and "your request was sent to IT". Nothing redirects to
the client until someone approves it.

Per protected resource, with `iam:protected-resources:read`/`write`
(management `…/environments/$ENV/…` or `/api/v1`):

| Route | Does |
|-------|------|
| `GET …/protected-resources/:id/clients?admission=pending\|approved\|blocked` | The clients that asked, with the people who asked (`…/clients/:client/requests`) |
| `POST …/clients/:client/approve` `{"metadata_hash": …, "expires_at": …}` | Approves (optionally until a time) for the redirect URIs, `jwks_uri` and authentication method you reviewed: `metadata_hash` is the one `GET …/clients/:client` showed. If the document changed since, the answer is 409 `CLIENT_METADATA_CHANGED` and nothing is approved; review it again. An approved client whose document later changes the three waits again |
| `POST …/clients/:client/block` | Refuses the client and **revokes its sessions and refresh tokens in the same transaction**. Access tokens already issued are JWTs that your server verifies locally: they work until they expire (15 minutes at most, see [Lifetimes](#what-a-client-asks-for-and-gets)) |
| `POST …/clients/:client/unblock` | Back to pending |
| `DELETE …/clients/:client` | Forgets the client; it is discovered afresh |
| `PATCH …/protected-resources/:id` `{"allow_client_metadata", "client_admission": "allowlist"\|"open"}` | `false` takes registered clients only; `open` approves every document client |

`metadata_hash` is required (400 without it) so that what you approve is what
you looked at: a client can serve a harmless document while you review it and
another one after. The console sends the hash of the row on screen, shows the
redirect URIs and authentication method in the approval dialog and refreshes
the list when the answer is a 409; `iam protected-resources clients approve`
takes `--metadata-hash` (without it, it reads the client, prints what it is
approving to stderr and approves that), and the SDKs take the field
(`ClientApproval.MetadataHash`, `approveClient(…, {metadata_hash})`,
`approve_client(…, metadata_hash=…)`).

The hash covers what decides where tokens go and who may ask for them: the
redirect URIs, `jwks_uri` and the authentication method. The name, logo and
`client_uri` are not part of it. A client can change them without a new
review, which is why the console marks the name as unverified and shows
the logo only from the client_id's own host. Judge a client by its
client_id host, not by its name.

An approval with an expiry ends at that time: the check at use refuses the
client's refresh and introspected tokens at once (JWT access tokens run out within their 15 minutes), and the `client_admission_expire` job revokes its
sessions and returns it to pending, recording `oauth_client.expired`.

### Approvals by policy and by hand

An approval is either **manual** (someone approved that client, optionally
until a time) or **by policy**: the allowlist, a preset or an `open` server
admits every client its rule covers (`admission_source` `allowlist`,
`preset` or `open`). They end differently:

- A **manual** approval stands until someone changes it, the document's
  redirect URIs, `jwks_uri` or authentication method change (the client
  returns to pending), or it expires.
- An approval **by policy** follows the policy. Delete the allowlist entry,
  take a preset away or switch the server from `open` to `allowlist`, and
  every client only that rule admitted returns to pending **with its tokens
  and sessions revoked in the same transaction**; one that another entry
  still admits stays, relabelled. Adding an entry, a preset or turning the
  server `open` admits the clients already waiting, in the same way.
- Turning `allow_client_metadata` off, or the `client_metadata_documents`
  feature off for the environment, stops **every** document client of the
  server at once, whoever approved it: the check at use refuses their
  refresh tokens and sign-ins immediately (JWT access tokens run out within 15 minutes), and they return to pending (the
  `client_documents_reconcile` job follows the feature, which is another
  module's setting, within a minute). Turning the setting back on does not
  re-approve them all: turning `allow_client_metadata` on again approves the
  waiting clients the server's policy covers (allowlist, preset, `open`).
  Clients demoted because the feature went off stay pending when it comes
  back, and manual approvals are never restored: IT approves those again.

Each return to pending records `oauth_client.demoted` with
`data.reason` (`metadata_documents_disabled`, `feature_disabled` or
`admission_policy_ended`), `protected_resource_id` and the former
`admission_source`; the actor is the operator who changed the setting, or
`system` for the job. An approval whose document changed has its own
`oauth_client.updated` (`approval_metadata_changed`, `revoked_sessions`).

### Allowlist and presets

`/oauth-client-allowlist` (`POST` `{origin, path_prefix, protected_resource_id?}`,
`GET`, `DELETE /:entry`) approves matching clients without review, when they
are discovered and those already waiting. `GET /oauth-client-presets` lists
the known clients; `POST /oauth-client-presets` `{"preset": "claude_code", "protected_resource_id": …}`
adds the entry in one click. Presets whose client connects from the vendor's
cloud (ChatGPT) come back with `network: "public"` and a warning: your MCP
server and IAMKit must be reachable from the internet.

| Preset | Key | Mechanism | Network |
|--------|-----|-----------|---------|
| Claude Code | `claude_code` | metadata document | local |
| Claude (web and desktop) | `claude` | metadata document | **public**: connects from `160.79.104.0/21` |
| ChatGPT | `chatgpt` | metadata document (`private_key_jwt`) | **public** |
| Codex | `codex` | metadata document | local |
| Visual Studio Code | `vscode` | metadata document | local |
| Cursor | `cursor` | template | local (its web and cloud agents return to cursor.com: public) |
| Antigravity | `antigravity` | template | local |
| Gemini CLI | `gemini_cli` | template | local |
| MCP Inspector | `mcp_inspector` | template | local, development only |

*Public* clients connect from their vendor's cloud, so your MCP server and
IAMKit must be reachable from the internet; *local* clients run on the user's
machine. See [Behind a VPN or on-premises](#behind-a-vpn-or-on-premises).

### Templates: Cursor, Antigravity and Gemini CLI

These tools do not publish a metadata document, so they need a client ID you
create. `POST …/protected-resources/:id/client-templates {"preset": "cursor"}`
(also `antigravity` and `gemini_cli`) creates a registered public client with
hosted login and the tool's known redirect URIs, and answers `201` with its
`client.client_id` (`200` when the server already had one). `mcp_inspector` is
offered only where the environment turns on the `development_clients`
feature, and only for development. Give the client ID to the tool:

Cursor, `~/.cursor/mcp.json` (`auth.CLIENT_ID`; no secret):

```json
{
  "mcpServers": {
    "invoices": {
      "url": "https://mcp.example.com/mcp",
      "auth": { "CLIENT_ID": "<client_id>" }
    }
  }
}
```

Gemini CLI, `~/.gemini/settings.json` (`oauth.clientId`; it picks a random
localhost port, which the template accepts):

```json
{
  "mcpServers": {
    "invoices": {
      "httpUrl": "https://mcp.example.com/mcp",
      "oauth": { "enabled": true, "clientId": "<client_id>" }
    }
  }
}
```

Antigravity, `mcp_config.json` (`oauth.clientId`; it returns to
`https://antigravity.google/oauth-callback` and the user pastes the code into
the app):

```json
{
  "mcpServers": {
    "invoices": {
      "serverUrl": "https://mcp.example.com/mcp",
      "oauth": { "clientId": "<client_id>" }
    }
  }
}
```

The console prints exactly this snippet, with the real URL and client ID,
after creating the client. Check the tool's own documentation if its
configuration format changed.

Redirect URIs of templates, and of the documents of clients that use one,
follow RFC 8252: `https`, `http` on a loopback address (`127.0.0.1`,
`[::1]`, `localhost`) or a **private-use scheme named by a reverse domain**
(`com.example.app:/callback`: at least two dot-separated labels of lowercase
letters, digits and hyphens, the first starting with a letter). A bare scheme
such as `cursor:` or `vscode:` is refused: nothing stops another application
on the user's machine from registering it and receiving the code. One
validator (`identity.ValidateClientRedirects`) checks documents and
templates, so the two never disagree.

### Limits

A page full of unknown URLs cannot exhaust IAMKit or its IT queue:

| Limit | Value | What happens |
|-------|-------|--------------|
| Pending clients per environment | 200 | 429 `CLIENT_ADMISSION_BACKLOG` (hosted page *Too many applications are waiting*) |
| Requests a user keeps for clients still waiting | 5 in 24 h | 429 `CLIENT_ACCESS_REQUEST_LIMIT`; nothing is stored. It frees when IT answers or the day passes |
| The same, per organization | 50 in 24 h | the same |
| Document fetches per environment | 60 a minute; 45 for clients with no row | 429 `CLIENT_METADATA_FETCH_BUDGET`. The other 15 are reserved for clients IAMKit knows, so a flood of new URLs does not stop them refreshing |
| Document fetches per client address | 10 a minute (IPv6: per /64) | the same code. Cached documents are free |

Behind a proxy set `IAMKIT_TRUSTED_PROXIES`, or every request counts as the
proxy's address. With `REDIS_URL` the budgets are shared by the replicas.

**Stale metadata.** When an **approved** client's document cannot be read
now (the host does not answer or answers an error status, or the fetch
budget is spent) IAMKit signs the client in with the metadata it stored,
up to 24 hours after the longest time a document is cached (so 48 hours
after the last read), and logs a warning. A document that is read but
invalid, a pending client and a client never seen get the error as usual; a
stored copy is never used to approve anything new.

A pending client nobody used is deleted after 30 days without a request for
it (the latest request counts, not the day it was discovered).

### What discovery says, and what to tell users

`/.well-known/oauth-authorization-server` advertises
`client_id_metadata_document_supported: true` only when it is true in
practice: the `client_metadata_documents` feature is on in at least one
environment that has an active protected resource allowing metadata
documents (`allow_client_metadata`). Otherwise the field is `false`, so an
MCP client does not offer a `client_id` URL that every server would refuse.
The answer is cached for a minute (shared by the replicas with `REDIS_URL`),
so a change shows within it. IAMKit advertises no `registration_endpoint`:
there is no dynamic client registration.

When an MCP client uses a URL anyway (the feature is off in the environment,
or the server takes registered clients only), the user sees a page that says
so and what to do: ask the administrator for a client ID made from a
[template](#allowlist-and-presets) for the server and enter it in the
application (Claude Code: `--client-id`). Administrators: create the
template with `…/client-templates`, or turn the feature on and allow
documents on the server.

Deleting or deactivating a server also ends the sessions and grants of its
document clients; `…/impact` counts them in `external_clients`. Deleting
forgets them; clients created from templates belong to the application and
stay (only their sessions for the server end), so a server recreated at the
same URL can reuse them.

### What the document can say about itself

Everything in a client's document except the host it is served from is
written by the client's author. Treat it as untrusted wherever it is shown
or forwarded:

- `client_name` (also in `oauth_client.discovered` and `.updated` events,
  and so in **webhooks and log streams**) is attacker-chosen text: render it
  as text, never as HTML or a command, and do not let it decide routing or
  alerting. The host in the same events (`client_id`, `host`) is the
  verified part.
- `logo_uri` is shown on the hosted page and in the console only when it is
  served from the `client_id`'s own host, and then the **viewer's browser
  fetches it from that host**: the client's operator sees the IP address and
  User-Agent of every user who opens the page. If that matters, remove the
  logo (the page works without it) by serving `Content-Security-Policy`
  `img-src 'self'` on the hosted pages from your proxy, or approve only
  presets.

### In the console

- **Resource → MCP server → Client settings** has the `allow_client_metadata`
  switch and the admission mode (*Allowlist* or *Open*). *Open* asks for
  confirmation: **any URL that serves a valid document is admitted without
  review**, so anyone on the internet can make a client ask your users for
  access. Use it for development.
- **Resource → Clients** lists the clients by *Pending*, *Approved* and
  *Blocked* (with counts). Each row shows the client's **host** in bold; a
  verified preset name with a check, or the document's own name marked
  *Unverified*; a logo only when it is served from the client's own host;
  the source, when it was last used, and the approval's expiry. Row actions:
  approve (with an optional expiry date), block, unblock, delete and the
  people who asked.
- **Applications → MCP client allowlist** manages the environment's entries
  (origin and path prefix) and shows the known-clients gallery: each card
  says *Requires public exposure* (with the source addresses) or *Local
  client*; metadata-document presets enable in one click, templates open
  *Create client from template*, which shows the client ID and the
  configuration snippet. MCP Inspector appears only with the
  `development_clients` feature.
- Deactivating or deleting a server counts its external clients next to the
  active sessions.

## What a client asks for and gets

A client opts into the resource flow by sending `resource` with the
protected resource's URI. Then:

| Request | Result |
|---------|--------|
| `resource` is the client resource's protected URI | Resource flow: `aud` = the URI, scopes = permissions |
| `resource` is anything else, or appears twice | `invalid_target` |
| No `resource` | Unchanged OpenID Connect behaviour (`aud` = the resource's audience, every permission the user holds) |

In the resource flow:

- **Scopes are the resource's permissions.** `notes:read` is the OAuth scope
  `notes:read`. With no `scope`, the server's `default_scopes` apply.
  Requested permissions the user does not hold are left out: IAMKit grants
  less rather than failing, and the token response's `scope` says what was
  granted.
- **OpenID Connect is optional.** `openid` (and so `nonce`) is not required.
  `state` and S256 PKCE are.
- **Refresh is implicit.** A client with the `refresh_token` grant (the
  default) gets `offline_access` and a refresh token without asking.
- **Every refresh recomputes the scopes.** The new token carries the
  consented scopes the user still holds: a permission removed from the user
  disappears at the next refresh, and comes back if it is given back. Removing
  the user from the organization, suspending the user or changing their direct
  grants or roles ends the authorization.
- **Refresh tokens rotate.** Reusing a spent refresh token revokes the whole
  authorization. A refresh may send a narrower `scope` and gets only those
  scopes. The refresh token keeps the consent, so later refreshes can get the
  rest again. A scope never granted is `invalid_scope`.
- A `resource` on the token request must equal the authorization's. When it
  is absent, the authorization's applies.
- **Lifetimes.** The access token lives 15 minutes. The authorization lives
  the server's `idle_ttl_seconds` / `max_ttl_seconds`, held to the
  environment's ceilings. Every refresh applies the current values: the
  authorization ends at its sign-in plus the server's current
  `max_ttl_seconds` (itself held to the current ceiling) when that comes
  before its stored end. Lowering the ceiling (for example from 90 to 30
  days after an incident) ends older authorizations at their next refresh.

The access token is a JWT
([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)) with `aud` = your URL,
`resource` = your URL (only tokens of the resource flow carry it),
`scope` (string) and `scp` (list), `permissions`, `sub` (user),
`organization_id`, `environment_id`, `oauth_client_id`, `sid` and the usual
`iss`/`exp`/`iat`; see [token claims](../../reference/token-claims.md).

## Verify tokens in your server

The resource-server SDKs serve the metadata, verify tokens and write the
challenges. Both canonicalize the configured URL with the same rule and test
vectors as IAMKit.

### Node.js

```ts
import express from "express";
import { createResourceServer, resourceClaimsOf, ResourceError } from "@iamkit/node/resource-server";

const rs = createResourceServer({
  issuer: "https://iam.example.com",
  resource: "https://mcp.example.com/mcp",
  environmentId: process.env.IAMKIT_ENVIRONMENT_ID!,
  scopesSupported: ["notes:read"],          // = the protected resource's default_scopes
  resourceName: "Notes",
});

const app = express();
app.use(rs.metadataHandler());              // /.well-known/oauth-protected-resource/mcp (+ the root path)
app.post("/mcp", rs.protect(), express.json(), (req, res) => {
  const claims = resourceClaimsOf(req)!;    // sub, organizationId, scopes, permissions, …
  try {
    if (isToolCall(req.body, "add_note")) rs.require(claims, "notes:write");
  } catch (error) {
    if (error instanceof ResourceError) return rs.deny(res, error);   // 403 insufficient_scope
    throw error;
  }
  // … hand the request to the MCP transport
});
```

### Go

```go
import "github.com/Abraxas-365/iamkit/sdk/resourceserver"

rs, err := resourceserver.New(resourceserver.Config{
	Issuer:          "https://iam.example.com",
	Resource:        "https://mcp.example.com/mcp",
	EnvironmentID:   environmentID,
	ScopesSupported: []string{"notes:read"},
	ResourceName:    "Notes",
})
mux := http.NewServeMux()
rs.Mount(mux) // the metadata paths
mux.Handle("/mcp", rs.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, _ := resourceserver.FromContext(r.Context())
	if isToolCall(r, "add_note") && !rs.RequireScopes(w, r, "notes:write") {
		return // 403 insufficient_scope written
	}
	serveMCP(w, r, claims)
})))
```

A token is accepted when:

- it is an RS256 JWT signed by a key of IAMKit's JWKS;
- `iss` is the issuer and `exp` has not passed (30 s leeway);
- `aud` contains the server's canonical URL;
- `environment_id` is the configured environment and the token is an
  application token with a session;
- its `resource` claim is the server's canonical URL, so it was issued by an
  authorization that named this server;
- with `organizations` / `Organizations` set, the organization is one of
  them.

Otherwise the answer is `401` with
`WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"`, or
without `error` when there was no token. Opaque access tokens are not
accepted: keep the MCP clients on JWT access tokens (the default). When
IAMKit's JWKS cannot be fetched and no keys are cached, the answer is `503`
without a challenge, so clients keep their tokens through the outage.

The claims' `scopes` / `Scopes` are the granted scopes and `permissions` /
`Permissions` the granted scopes that are permissions. The token's
`permissions` claim is never read: authorization decisions rest on what the
user consented to.

An MCP client's token request without `resource` is plain OpenID Connect:
its token also has `aud` = your URL and every permission the user holds, but
no `resource` claim, so the SDKs refuse it. Admitting such tokens takes an
explicit `allowTokensWithoutResource: true` / `AllowTokensWithoutResource:
true`; even then only their granted scopes count.

**Step-up.** `require(claims, …scopes)` / `Require` fails with
`insufficient_scope`, and `deny` / `Deny` answers:

```
403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="…", scope="notes:read notes:write"
```

The challenge's `scope` is what the token already has plus what is missing,
because clients replace their scope with the challenge's when they authorize
again. Check scopes before handing the request to the MCP transport, so a
`tools/call` that needs more can still answer `403`; the example's
[`scopes.ts`](../../../examples/mcp-server/src/scopes.ts) maps tool names to
scopes. If the user does not hold the permission, IAMKit grants less and the
client reports it. Give the user the permission and the next authorization
gets it.

`protect()` / `Protect` removes the `Authorization` header before your handler
runs. Do not forward the client's token to other services.

## Call other APIs as the user

To reach a downstream API (another resource of the same application) for the
user, give the MCP server its own **confidential** client with the token
exchange grant, and exchange the incoming token
([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)):

```ts
import { OAuthClient } from "@iamkit/node";

const iam = new OAuthClient({ baseUrl: issuer, clientId: process.env.SERVER_CLIENT_ID!, clientSecret: process.env.SERVER_CLIENT_SECRET! });
const { access_token } = await iam.exchangeToken(incomingToken, "https://notes-api.example.com");
```

The new token is for the downstream API (`aud`), carries the user's
permissions **there** and lives in a child session that ends with the MCP
authorization. Its audience must be a resource of the same application,
else `invalid_target`. Public clients cannot exchange. `protect()` /
`Protect` strip the incoming token, so a server that exchanges reads the
`Authorization` header and verifies it itself with `rs.verify(token)` /
`Verify(ctx, token)`. See
[token exchange](oauth-oidc.md#calling-another-api-as-the-user-token-exchange).

## Behind a VPN or on-premises

Which clients work depends on where the MCP server and IAMKit are reachable:

- **Local clients** (Claude Code, Codex, VS Code, Cursor and Gemini CLI on the
  desktop, Antigravity) run on the user's machine, so a server behind the
  company VPN works while the user is connected.
- **Public clients** (Claude on the web and desktop, ChatGPT) call the server
  and IAMKit from their vendor's cloud. Behind a VPN they fail to connect.
  To use them, expose both over the internet and, for Claude, allow
  `160.79.104.0/21` at the edge. The console and the preset API flag this
  before you enable them.

Metadata documents are fetched by IAMKit, never by the browser, over the
internet: an IAMKit without outbound access to `https://claude.ai` and the
other document hosts cannot admit those clients, whatever the allowlist says.
Use templates (fixed client IDs) there.

## Several replicas

Run more than one IAMKit replica only with `REDIS_URL`. The fetched metadata
documents and key sets, the discovery answer, the refetch throttle for unknown
key ids and the rate limits are shared through it; without it each replica
keeps its own copy and counter, so a client can make every replica fetch its
URL and the limits multiply. IAMKit refuses to start with `IAMKIT_REPLICAS`
above 1 and no Redis, and the Helm chart does not render. Approvals, blocks
and expiries are stored in the database and checked at use, so they apply on
every replica at once. The fetch budgets (per environment and per address)
and the limits on waiting requests are counted in Redis and the database, so
they hold across replicas as well.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `invalid_target` at authorize | `resource` is not the URI of a protected resource of the client's resource, or the protected resource is inactive or deleted |
| `401 invalid_token` with a fresh token | The server's configured URL differs from the protected resource's `uri` (compare the canonical forms), or another environment |
| The client loops on `403` | The user lacks the permission. The client stops after one retry and reports the scopes that were not granted |
| The browser shows "Sign-in expired" | The hosted pages need HTTPS: IAMKit's issuer must be `https` outside loopback |
| Claude Code cannot complete sign-in | Its `--callback-port` must match a registered `http://localhost:<port>/callback` |
| `429 CLIENT_ACCESS_REQUEST_LIMIT` | The user (or their organization) already has as many requests waiting for IT as allowed; IT answers some, or wait a day |
| `429 CLIENT_METADATA_FETCH_BUDGET` | Too many documents read this minute for the environment or from the caller's address; retry in a minute. Behind a proxy without `IAMKIT_TRUSTED_PROXIES` every user shares one address |
| An approved client stopped working after you turned a setting off | `allow_client_metadata` off, the `client_metadata_documents` feature off, or a removed allowlist entry returns it to pending (`oauth_client.demoted`); see [Approvals by policy and by hand](#approvals-by-policy-and-by-hand) |
| A client waits forever on "your request was sent to IT" | It is *Pending*: approve it (Resource → Clients), or add it to the MCP client allowlist |
| Claude on the web cannot reach a server behind a VPN | Claude connects from its cloud (`160.79.104.0/21`); expose the server and IAMKit, or use Claude Code |
