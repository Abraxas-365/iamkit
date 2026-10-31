# Remote MCP server in Python, protected by IAMKit

A minimal remote [MCP](https://modelcontextprotocol.io) server in Python (the official `mcp` package's `FastMCP`, Streamable HTTP) that
uses IAMKit as its OAuth 2.1 authorization server, with [`iamkit.resource_server`](../../clients/python/src/iamkit/resource_server.py).
It behaves like the [Node.js example](../mcp-server): the server

- publishes its protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource/mcp`;
- answers `401` with `WWW-Authenticate: Bearer resource_metadata="…"` when a request has no valid token;
- accepts only IAMKit access tokens issued for its URL (`aud` = `http://localhost:3333/mcp`, RFC 8707), its environment and an organization;
- asks for more scope with `403 insufficient_scope` (step-up) when a tool needs a permission the token lacks;
- optionally asks IAMKit whether each token is still live (introspection, fails closed with `503`), so a user who disconnects the
  client stops it at once.

| Tool | Scope |
|------|-------|
| `list_notes` | `notes:read` (the default scope) |
| `add_note` | `notes:write` |
| `whoami` | a valid token |

The layers, outermost first (see [`server.py`](server.py) and [`scopes.py`](scopes.py)): `ResourceServerMiddleware` (metadata, token,
challenges) → `ToolScopes` (the scope each `tools/call` needs, read from the JSON-RPC body) → FastMCP's Streamable HTTP app. The tools read
the verified claims with `claims_of(request.scope)`.

The step-by-step guide is [Protect an MCP server with IAMKit](../../docs/guides/applications/protect-mcp-server.md#python).

## Run it

Against a disposable stack (needs `go`, `uv`, `node` ≥ 20 for the TLS proxy, `openssl` and `docker`):

```sh
./scripts/stack.sh
# or, with an existing PostgreSQL (a database is created and dropped):
IAMKIT_STACK_DSN=postgres://user@127.0.0.1:5432/postgres ./scripts/stack.sh
```

`scripts/stack.sh` builds IAMKit from this checkout, serves it at `https://localhost:18443` behind a TLS proxy (with `MKCERT=1`, using a
certificate from your local mkcert CA), seeds an environment (`scripts/seed.py`, standard library only), starts this server on
`http://localhost:3333/mcp` with introspection on and prints the commands below with the seeded client IDs. Two users exist:
`reader@mcp.example` (`notes:read`) and `writer@mcp.example` (`notes:read`, `notes:write`), both with the printed password.

Against your own IAMKit, register the server as in [the guide](../../docs/guides/applications/protect-mcp-server.md#register-the-server)
and run:

```sh
uv sync
IAMKIT_ISSUER=https://iam.example.com IAMKIT_ENVIRONMENT_ID=<environment id> uv run python server.py
```

### MCP Inspector

```sh
NODE_EXTRA_CA_CERTS=.stack/tls.crt npx @modelcontextprotocol/inspector --cli http://localhost:3333/mcp \
  --client-id <inspector client id> --method tools/call --tool-name add_note --tool-arg text=hello
```

Sign in as `writer@mcp.example`. The first authorization asks for `notes:read`; `add_note` answers
`403 insufficient_scope` and the Inspector authorizes again with `notes:read notes:write`. Signed in as `reader@mcp.example`, IAMKit grants
only what the user holds and the Inspector reports that `notes:write` was not granted.

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
| `IAMKIT_INTROSPECTION_CLIENT_ID`, `IAMKIT_INTROSPECTION_CLIENT_SECRET` | unset | A confidential OAuth client of the environment; when set, every token is also checked with IAMKit |
| `IAMKIT_INTROSPECTION_CACHE_TTL` | `0` | Seconds an *active* answer is kept (never past `exp`); `0` asks on every request |
| `IAMKIT_INTROSPECTION_URL` | the issuer | IAMKit's origin when it differs from the issuer |
| `PORT` | `3333` | Listening port (loopback) |

A private CA for IAMKit is trusted with `SSL_CERT_FILE=<ca.pem>`. The notes live in memory, per organization. The server is stateless
(`stateless_http=True`): every POST stands alone, bound to the claims of its own token. It never forwards the client's token: to call
another API on the user's behalf, exchange it (`OAuthClient.exchange_token`, RFC 8693) for a token of that API.

## Develop

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run pytest -q
```

The end-to-end test `tests/e2e/python_resource_server_test.go` starts this server with `uv run` against an in-process IAMKit and walks
metadata → challenge → token → tool calls → step-up → disconnect.
