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

With the [`iam` CLI](../reference/cli.md) configured with that key, the same step
needs no file and keeps the password out of the shell history:

```sh
iam password set                       # prompts without echo, asks twice
printf '%s\n' "$NEW" | iam password set --password-stdin
iam password status                    # {set, usable, fresh, mode}
```

## Sign in with your identity provider instead of a password

Operators can sign in to the console with Google, Microsoft or any OIDC
provider, so they do not need a console password. The variables are in
[operator single sign-on](../reference/configuration.md#operator-single-sign-on).
Roll it out in this order so nobody is locked out:

1. Invite every operator first (`iam operators create --email … --role admin|viewer`).
   SSO never creates operators; the first sign-in links the identity to the
   active operator with that email, which must be in `ALLOWED_DOMAINS`.
2. Register `<JWT_ISSUER>/management/v1/sso/callback` at the provider, add the
   `IAMKIT_OPERATOR_SSO_*` variables and restart. Keep
   `IAMKIT_OPERATOR_PASSWORD_LOGIN=enabled` while you check that each operator
   can sign in with SSO.
3. Give the owner an emergency password, then restrict passwords:
   `iam operators password-access OWNER_ID --allow`. With a provider
   configured the default is `break_glass`: only operators with that access
   can still use a password, everyone else must use SSO (403 `SSO_REQUIRED`).
4. Optionally set `IAMKIT_OPERATOR_PASSWORD_LOGIN=disabled` to refuse
   passwords altogether (403 `PASSWORD_LOGIN_DISABLED`). Management keys keep
   working, so the CLI is unaffected.

Roles apply the same way to both sign-in methods. `iam operators role
OPERATOR_ID --role viewer` changes one at once, including live sessions. A
`viewer` can still set its own password when passwords are permitted.

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
