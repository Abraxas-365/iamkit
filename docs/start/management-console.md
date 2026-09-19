# Management console

The operator management console is a React/Vite SPA **embedded in the IAMKit
Docker image**. When you start IAMKit, the console is available at the root URL
(e.g. `http://localhost:8080/`). No separate frontend deployment is needed.

Operators log in with a password and a Secure HttpOnly cookie; do not put
management keys in `VITE_*` variables or browser storage.

## Set your operator password

After explicit bootstrap, use a trusted shell and a private JSON file containing
`{"password":"YOUR_UNIQUE_12_TO_72_BYTE_PASSWORD"}`. Keep it outside source control:

```sh
curl --fail --silent --show-error "$IAMKIT_URL/management/v1/password" \
  -H "X-API-Key: $MGMT" -H 'Content-Type: application/json' \
  --data-binary @.dev-secrets/operator-password.json
```

Expect 204. Securely remove the temporary file after setup. This changes the
currently authenticated operator's password, not an arbitrary user's password.

## How the embed works

The Dockerfile has three stages:

1. **Node stage** — builds the React frontend (`npm run build`)
2. **Go stage** — copies the built `dist/` into `internal/console/dist/`, then
   compiles the Go binary with `//go:embed` so the SPA is inside the binary
3. **Runtime stage** — a minimal Alpine image with just the binary

The server serves static assets (JS, CSS, fonts) directly from the embedded
filesystem. Any GET request that doesn't match an API route (`/management/`,
`/identity/`, `/api/`, `/scim/`, `/health`, `/.well-known/`) falls back to
`index.html` for client-side routing.

When the frontend is not embedded (e.g. a plain `go build` without running the
Node build first), the server runs in API-only mode — no SPA is served.

## Local frontend development

For frontend development with hot reload, run Vite separately against the
backend. Use Node 22+ and from `frontend/`:

```sh
npm ci
IAMKIT_API_URL=http://localhost:8080 npm run dev
```

The Vite dev server proxies all API paths (`/management`, `/identity`, `/api`,
`/scim`, `/health`, `/.well-known`) to the backend. Open the URL printed by
Vite.

For HTTPS (required for Secure cookies in some browsers):

```sh
CONSOLE_TLS_CERT=/absolute/path/localhost-cert.pem \
CONSOLE_TLS_KEY=/absolute/path/localhost-key.pem \
IAMKIT_API_URL=http://localhost:8080 npm run dev
```

## Production notes

In production, the console is served from the same origin as the API — no CORS
or separate reverse-proxy configuration needed. The embedded SPA adds ~500 KB
(gzipped) to the binary.

Console capability is bounded by backend operator roles, not merely hidden
buttons. Restrict container access as appropriate; do not expose a dev server
for production.

**Verify:** sign in, read the workspace, create a test project, sign out and
prove its former cookie no longer authenticates. Viewer mutation must fail at
the API. If login appears to succeed but the next request is 401, inspect
HTTPS/cookie scope and proxy behavior. See
[reverse proxy](../operations/reverse-proxy.md).
