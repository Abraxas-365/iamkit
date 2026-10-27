# Protect an MCP server with IAMKit

Use IAMKit as the OAuth 2.1 authorization server of a remote
[MCP](https://modelcontextprotocol.io) server (Streamable HTTP), as the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
describes. MCP clients such as Claude Code, MCP Inspector, VS Code or Codex
discover IAMKit from your server, sign the user in through IAMKit's hosted
pages and call your server with an access token issued for it alone.

This guide covers what ships today: pre-registered clients, RFC 8707 resource
indicators, scopes mapped to permissions with step-up, and the
resource-server SDKs. Client ID Metadata Documents, dynamic client
registration and a consent screen with client approval come in later phases;
until then every MCP client needs a pre-registered OAuth client.

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

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `invalid_target` at authorize | `resource` is not the URI of a protected resource of the client's resource, or the protected resource is inactive or deleted |
| `401 invalid_token` with a fresh token | The server's configured URL differs from the protected resource's `uri` (compare the canonical forms), or another environment |
| The client loops on `403` | The user lacks the permission. The client stops after one retry and reports the scopes that were not granted |
| The browser shows "Sign-in expired" | The hosted pages need HTTPS: IAMKit's issuer must be `https` outside loopback |
| Claude Code cannot complete sign-in | Its `--callback-port` must match a registered `http://localhost:<port>/callback` |
