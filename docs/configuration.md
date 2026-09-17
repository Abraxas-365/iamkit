# Configuration

Every environment variable IAMKit reads, in one place. Local development uses `.env.example` as
a starting point (`cp .env.example .env`, then `set -a; . ./.env; set +a` — only the process
environment is loaded, nothing is auto-sourced from a file at runtime).

## Required

| Variable | Used by | Format / notes |
| :--- | :--- | :--- |
| `DATABASE_URL` | `internal/bootstrap/container.go` | PostgreSQL DSN, e.g. `postgres://iamkit:iamkit_local@localhost:55432/iamkit?sslmode=disable`. Must point at an empty, managed database on first `migrate` — see [Getting started](getting-started.md). |
| `JWT_ISSUER` | `internal/bootstrap/container.go` | The `iss` claim on every issued token and the OIDC discovery `issuer`. Must be a stable HTTPS URL in any non-local deployment; plain HTTP is fine for local password/machine login only. |
| `JWT_PRIVATE_KEY_PATH` | `internal/bootstrap/container.go` | Path to a PEM-encoded RSA private key (2048+ bits), read once at startup. Generate locally with `openssl genrsa -out .dev-secrets/jwt.pem 2048 && chmod 600 .dev-secrets/jwt.pem`. Protect this file in any real deployment — it signs every token. |
| `SERVER_PORT` | `cmd/iamkit/main.go` | Defaults to `8080` if unset. |

## Optional: OAuth/OIDC server

| Variable | Used by | Format / notes |
| :--- | :--- | :--- |
| `OIDC_HMAC_SECRET` | `internal/bootstrap/container.go` (passed into the OAuth module) | At least 32 random bytes. Required only if you use the `/oauth/*` authorization-code server (see `api.md#oauthoidc-server`); leave unset if you only use `/identity/v1/login`. Authorization/browser-binding cookies use `Secure`/`__Host-` restrictions, so the OAuth flow requires HTTPS in any browser-facing deployment. |

## Optional: email delivery (OTP login, verification, password reset)

| Variable | Used by | Format / notes |
| :--- | :--- | :--- |
| `EMAIL_WEBHOOK_URL` | `internal/bootstrap/container.go` | Must be HTTPS. Your own trusted delivery service; IAMKit POSTs `{"email":...,"purpose":...,"code":...}` to it with a ten-second timeout and no redirects followed. Leave unset to disable OTP/verification/reset challenges entirely — `POST /identity/v1/challenges` will fail without it. |
| `EMAIL_WEBHOOK_TOKEN` | `internal/bootstrap/container.go` | Sent as `Authorization: Bearer <token>` to the webhook when set. Optional even when `EMAIL_WEBHOOK_URL` is set, but recommended. |

Never log the webhook payload — it contains the raw OTP code.

## Optional: external federation (Google, Microsoft, any OIDC provider)

| Variable | Used by | Format / notes |
| :--- | :--- | :--- |
| `FEDERATION_CREDENTIAL_BINDINGS` | `internal/iam/federation/adapters/fedoidc/provider.go` | JSON array of `{"environment_id","issuer","client_id","secret_env"}` tuples. This is a deployment-controlled allow-list: a `federation-connections` management API call is rejected unless it exactly matches one of these entries. Defaults to `[]` (federation entirely disabled) if unset/empty. |
| `IAMKIT_PROVIDER_*` | Referenced indirectly, via each binding's `secret_env` | The actual provider client secret. The variable name **must** match `^IAMKIT_PROVIDER_[A-Z0-9_]+$` (enforced by `fedsvc.Service.Create`). Never commit real values; keep out of browser-reachable config. |

See [Recipes → let a product's users sign in with Google](recipes.md#recipe-let-a-products-users-sign-in-with-google)
for a worked example of setting both of these together.

## Full example

```sh
# .env — local only
DATABASE_URL=postgres://iamkit:iamkit_local@localhost:55432/iamkit?sslmode=disable
SERVER_PORT=8080
JWT_PRIVATE_KEY_PATH=.dev-secrets/jwt.pem
JWT_ISSUER=http://localhost:8080

OIDC_HMAC_SECRET=

EMAIL_WEBHOOK_URL=
EMAIL_WEBHOOK_TOKEN=

FEDERATION_CREDENTIAL_BINDINGS='[]'
# IAMKIT_PROVIDER_GOOGLE=your-private-provider-client-secret
```

## Not yet configurable

- IP rate limiting is process-local and fixed in code (`internal/server/server.go`), not
  environment-configurable. Distributed/per-account abuse prevention is deployment work — see
  [Security status](../SECURITY.md).
- Management/service/SCIM credential lifetimes (24 hours) are fixed, not environment-configurable.
- Access token lifetime (15 minutes) and refresh session lifetime (24 hours) are fixed, not
  environment-configurable.

## Database, not environment variables

`docker-compose.yml` provisions a local PostgreSQL with `POSTGRES_USER=iamkit`,
`POSTGRES_PASSWORD=iamkit_local`, `POSTGRES_DB=iamkit`, exposed on `127.0.0.1:55432`, matching
the default `DATABASE_URL` above. The `identity_data` volume is **not** cleared or upgraded by
Compose — always point `migrate` at an empty database (see [Getting started](getting-started.md)).
