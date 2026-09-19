# Configuration reference

IAMKit reads **process environment**, not `.env` automatically. Compose
`--env-file` provides interpolation values; a variable must also be listed in
`environment:` or supplied through `env_file:` to enter the container. Restart
containers after changes. Keep secrets outside source control and frontend builds.

| Variable | Requirement/default | Behavior |
| --- | --- | --- |
| `DATABASE_URL` | Required | PostgreSQL connection string; CLI commands need it too |
| `JWT_ISSUER` | Required to serve | Absolute HTTPS URL; HTTP allowed only for localhost/127.0.0.1; no query/fragment; trailing slash normalized |
| `JWT_PRIVATE_KEY_PATH` | Required to serve | Readable PEM RSA key, PKCS#1 or PKCS#8, at least 2048 bits |
| `SERVER_PORT` | `8080` | Listening port; image healthcheck assumes 8080 |
| `OIDC_HMAC_SECRET` | OAuth provider needs at least 32 bytes | Stable secret for OAuth; Compose templates require it explicitly |
| `EMAIL_WEBHOOK_URL` | Unset disables global fallback only | Trusted HTTPS endpoint; environment delivery overrides take precedence; no URL userinfo/fragment |
| `EMAIL_WEBHOOK_TOKEN` | Sent as Bearer token | Secret authenticating delivery requests |
| `FEDERATION_CREDENTIAL_BINDINGS` | No approved bindings when unset | JSON array of exact environment/issuer/client/secret-reference approvals |
| `IAMKIT_PROVIDER_*` | As referenced by a binding | External provider client secret; server-only |
| `CORS_ALLOWED_ORIGINS` | Empty: no CORS middleware | Comma-separated allowed origins; enables credentials, so never use untrusted origins or wildcard |
| `RATE_LIMIT_PER_MINUTE` | 120 | Per-IP, per-process limit on authenticated management and scoped API routes; invalid/non-positive values fall back to default |
| `IAMKIT_BOOTSTRAP_EMAIL` | Unset: no automatic bootstrap | First-boot owner email; automatic bootstrap logs a one-time key |
| `IAMKIT_BOOTSTRAP_WORKSPACE` | `Default` | First-boot workspace name |
| `IAMKIT_BOOTSTRAP_PASSWORD` | Optional | Sets password only when bootstrap creates the owner; not a reset mechanism |

Per-environment email URL/token overrides are stored in PostgreSQL and managed
through `GET/PUT/DELETE /management/v1/environments/:environment/delivery`.
Deleting one restores global fallback; unsetting global variables does not remove
it. See [delivery precedence and containment](../guides/email-delivery.md).

Provider example (replace values with approved registration data):

```dotenv
FEDERATION_CREDENTIAL_BINDINGS='[{"environment_id":"ENV_UUID","issuer":"https://accounts.google.com","client_id":"REGISTERED_CLIENT_ID","secret_env":"IAMKIT_PROVIDER_GOOGLE"}]'
IAMKIT_PROVIDER_GOOGLE=PRIVATE_CLIENT_SECRET
```

The `secret_env` name must reference a deployment-approved provider variable.
Do not allow app users to choose arbitrary outbound issuers or secret names.

## Compose-only variables

`IAMKIT_PORT` controls host publishing. The source-build template uses
`POSTGRES_PASSWORD`; the image template uses `IAMKIT_DB_PASSWORD`. Both compose
`DATABASE_URL` for you. Use a random hex password or URL-encode special characters.
A published host port defaults to all interfaces unless explicitly restricted.

## Fixed contracts (not environment settings)

- Password length: 12–72 bytes; bcrypt cost 12.
- JWTs: 15 minutes; user session/refresh window: 24 hours; operator session: 1 hour.
- Challenges: 5 minutes, 8-character code, at most 5 wrong attempts; a new challenge
  consumes previous unconsumed challenges of the same purpose.
- Outbound email HTTP timeout: 10 seconds; redirects refused.
- HTTP body limit: 64 KiB. Endpoint-specific unauthenticated rate limits remain
  separate from `RATE_LIMIT_PER_MINUTE`.
- Credential `expires_in`: Go duration from `1h` through `8760h`; omitted/empty
  means `24h`. `never` means approximately 100 years, not literal infinity. Prefer
  finite expiry with tested rotation. Bootstrap/recovery uses 24h.

Do not invent environment overrides for these constants. Source:
`internal/config/constants.go`, `internal/identity/model.go`,
`internal/bootstrap/container.go`, `internal/server/server.go` and `cmd/iamkit/main.go`.

See [CLI](cli.md), [webhook](webhooks.md) and [deployment](../operations/deployment.md).
