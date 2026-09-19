# IAMKit Console

Pure React + TypeScript + Vite, using Tailwind CSS 4 and shadcn/Base UI components.
The design system is copied/adapted from `~/Personal/freerouter/web`: identical
light/dark color tokens, Inter body text, JetBrains Mono headings, 4px base radius,
and Base UI button/input/card/dialog/table/badge primitives. The shell uses its
inset sidebar, compact navigation, and monospace section labels. Dark is the default;
the theme toggle preserves your preference. No Next.js, SSR, or BFF.

IAM-specific forms, searchable entity selectors, authorization, and routing remain
local. Dialogs retain scroll limits and page headers wrap on small screens.

## Included in this first slice

- Operator password login, cookie-session verification, logout, and password changes.
- Responsive sidebar, light/dark theme, workspace overview.
- Project/environment creation, selection, and URL-scoped navigation.
- Users: list/create, edit name/status, suspend.
- Organizations: list/create/rename, add memberships.
- Applications: list/create/edit, deactivate, link resources.
- Resources: list/create/edit scope catalogs (audience is immutable).
- Roles: list/create/edit/delete, assign to organization members.
- Grants: list/upsert/edit permissions/delete. Editing cannot change the recipient.
- End-user sessions: list/revoke; audit events: list.
- Management API keys: create, show secret once, list/revoke.

Actions follow the backend role rules. Viewer environment mutations are hidden;
the server remains the authorization boundary. The API currently caps users/orgs
at 100 and sessions/audit events at 1,000; search filters only loaded records.
There is no invented pagination or fabricated dashboard data.

Not yet included: federation/OAuth/SCIM/service-account screens, operator delegation,
organization charts, membership removal, role unassignment, or user metadata/OTP
editing. Several of these need additional backend read contracts for a complete UI.

## Local setup

1. Follow the [root setup guide](../README.md#get-started) to start the database,
   apply migrations (including `012_operator_sessions`), bootstrap an owner, and
   start the Go API. The default API address is `http://localhost:8080`.
2. Set an operator password from a **trusted terminal**, using the bootstrap
   management key. Never paste the management key into the console or store it in
   a `VITE_*` environment variable. For example, with `MGMT` already set securely:

   ```sh
   # Use a local, permission-restricted JSON file containing:
   # {"password":"your unique 12–72 byte password"}
   curl --fail-with-body http://localhost:8080/management/v1/password \
     -H "X-API-Key: $MGMT" \
     -H 'Content-Type: application/json' \
     --data-binary @/path/to/private-password.json
   ```

   Keep that temporary file outside the repository and remove it securely after
   setup. This endpoint changes the authenticated operator's own password.
3. Install Node.js 22.12+ (or another version supported by Vite 8) and dependencies:

   ```sh
   cd frontend
   npm ci
   ```

4. Use trusted local HTTPS. With `mkcert` installed, generate a localhost certificate
   from the repository root:

   ```sh
   mkdir -p .dev-secrets
   mkcert -install
   mkcert -cert-file .dev-secrets/console.pem -key-file .dev-secrets/console-key.pem localhost 127.0.0.1 ::1
   ```

   Then, from `frontend/`, run Vite:

   ```sh
   CONSOLE_TLS_CERT=../.dev-secrets/console.pem \
   CONSOLE_TLS_KEY=../.dev-secrets/console-key.pem \
   npm run dev
   ```

   Open `https://localhost:5173`. Certificates/private keys are ignored by Git.
   `mkcert -install` changes your local trust store; use only on your own development
   machine. An existing trusted HTTPS reverse proxy is an alternative.

The development proxy forwards `/management`, `/identity`, `/api`, `/scim`,
`/health` and `/.well-known` to the API. Override its target with
`IAMKIT_API_URL=http://localhost:YOUR_PORT` if needed. These are server-side Vite
configuration variables, not browser credentials. Without TLS variables Vite uses
HTTP; do not rely on browser-specific localhost exceptions for Secure cookies.

## Auth and deployment

All API calls use relative `/management/v1` URLs and same-origin cookies. The
`__Host-iamkit-operator` cookie is Secure, HttpOnly, SameSite=Strict, Path=/, and
expires after one hour. The client verifies `/me` after login and redirects to login
on expired sessions; there is no refresh endpoint and no auth token in localStorage.
Only the theme preference is persisted in localStorage.

Login and cookie-authenticated mutations send `X-IAMKit-Console: 1`. The backend
requires this header and rejects cross-site fetch metadata. Do **not** configure
credentialed management CORS for untrusted origins. X-API-Key automation does not
require the console header. Logout reports revocation failures instead of pretending
that clearing a cookie invalidated the server session.

Build with `npm run build`. In production, the frontend is **embedded into the Go
binary** via `//go:embed` — the Dockerfile handles this automatically. The server
serves static assets and falls back to `index.html` for client-side routes. No
separate static server or proxy configuration is needed. Vite's dev proxy is for
local development only.

### Recovery and deployment controls

`recover-owner` requires an existing active owner, revokes their management keys
and console sessions, and clears their password. Re-establish console credentials
after recovery; see the [incident runbook](../docs/operations/incident-response.md).
Password login assumes one active workspace membership per operator;
multi-workspace selection is not implemented. Operator MFA and distributed rate
limiting are not implemented; use appropriate ingress and operator-access controls.

## Validation

```sh
npm run build     # TypeScript + production bundle
npm run lint
npm test          # API client and rendered UI regression tests
```

Go HTTP tests cover Host-cookie attributes, console CSRF checks, bearer access,
and logout failure propagation. Run `go test ./...` from the repository root.
Database E2E tests require the separate disposable-database harness; ordinary Go
unit tests do not prove a live browser/database login flow.

## Structure

```text
src/
  components/layout/    authenticated shell and context selectors
  components/library/   page, table, form, confirmation and error patterns
  components/ui/        shadcn/Base UI primitives
  hooks/                cancellable list loading
  lib/                  API client, auth context, utilities
  pages/                workspace and environment management screens
  index.css             FreeRouter design tokens (dark default + light)
```
