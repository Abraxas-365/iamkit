# Remote MCP server protected by IAMKit

A minimal remote [MCP](https://modelcontextprotocol.io) server (Streamable HTTP) that uses IAMKit as its OAuth 2.1 authorization server, with
[`@iamkit/node/resource-server`](../../clients/node/src/resource-server.ts). The server:

- publishes its protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource/mcp`;
- answers `401` with `WWW-Authenticate: Bearer resource_metadata="…"` when a request has no valid token;
- accepts only IAMKit access tokens issued for its URL (`aud` = `http://localhost:3333/mcp`, RFC 8707), its environment and an organization;
- asks for more scope with `403 insufficient_scope` (step-up) when a tool needs a permission the token lacks.

Each scope is an IAMKit permission of the server's resource:

| Tool | Scope |
|------|-------|
| `list_notes` | `notes:read` (the default scope) |
| `add_note` | `notes:write` |
| `whoami` | a valid token |

The step-by-step guide is [Protect an MCP server with IAMKit](../../docs/guides/applications/protect-mcp-server.md).

## Run it

```sh
npm install
npm run stack          # needs go, node ≥ 20, openssl and docker
# or, with an existing PostgreSQL (a database is created and dropped):
IAMKIT_STACK_DSN=postgres://user@127.0.0.1:5432/postgres npm run stack
```

`scripts/stack.sh` builds IAMKit from this checkout, serves it at `https://localhost:18443` behind a TLS proxy (with `MKCERT=1`, using a
certificate from your local mkcert CA), seeds an environment (`scripts/seed.mjs`), starts this server on `http://localhost:3333/mcp` and
prints the commands below with the seeded client IDs. Two users exist: `reader@mcp.example` (`notes:read`) and `writer@mcp.example`
(`notes:read`, `notes:write`), both with the printed password.

The seed pre-registers one public client per MCP client in the server's application, so the example works without metadata documents or dynamic client registration (both are off by default; see [the guide](../../docs/guides/applications/protect-mcp-server.md#dynamic-client-registration)):

| Client | Redirect URIs |
|--------|---------------|
| MCP Inspector | `http://127.0.0.1:6276/oauth/callback`, `http://localhost:6274/oauth/callback` |
| Claude Code | `http://localhost:19876/callback`, `http://127.0.0.1:19876/callback` |

### MCP Inspector

```sh
NODE_EXTRA_CA_CERTS=.stack/tls.crt npx @modelcontextprotocol/inspector --cli http://localhost:3333/mcp \
  --client-id <inspector client id> --method tools/call --tool-name add_note --tool-arg text=hello
```

Sign in as `writer@mcp.example`. The first authorization asks for `notes:read` (the metadata's `scopes_supported`); `add_note` answers
`403 insufficient_scope scope="offline_access notes:read notes:write"`, the Inspector offers a step-up and authorizes again with that scope.
Signed in as `reader@mcp.example`, IAMKit grants only what the user holds and the Inspector reports that `notes:write` was not granted.

### Claude Code

```sh
claude mcp add --transport http --client-id <claude client id> --callback-port 19876 iamkit-notes http://localhost:3333/mcp
NODE_EXTRA_CA_CERTS=.stack/tls.crt claude
```

Then `/mcp` → `iamkit-notes` → **Authenticate**, and sign in in the browser.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `IAMKIT_ISSUER` | — | IAMKit's issuer URL |
| `IAMKIT_ENVIRONMENT_ID` | — | The environment whose tokens are accepted |
| `MCP_RESOURCE_URL` | `http://localhost:3333/mcp` | The server's canonical URL = the resource's audience in IAMKit |
| `IAMKIT_JWKS_URL` | `<issuer>/.well-known/jwks.json` | Where to fetch IAMKit's keys |
| `PORT` | `3333` | Listening port (loopback) |

The notes live in memory, per organization. The server is stateless (`sessionIdGenerator: undefined`): every POST builds an `McpServer`
bound to the request's claims. It never forwards the client's token: to call another API on the user's behalf, exchange it
(`OAuthClient.exchangeToken`, RFC 8693) for a token of that API.
