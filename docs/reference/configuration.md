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
| `EMAIL_*`, `SMTP_*`, `RESEND_API_KEY` | Unset: no global email delivery | Deployment-wide email fallback; see [email](#email) |
| `IAMKIT_ALLOW_PRIVATE_DELIVERY` | `false` | **Development only.** Lets environment email webhooks and SMTP servers reach localhost and private networks; see [private delivery addresses](#private-delivery-addresses-development-only) |
| `FEDERATION_CREDENTIAL_BINDINGS` | No approved bindings when unset | JSON array of exact environment/issuer/client/secret-reference approvals |
| `IAMKIT_PROVIDER_*` | As referenced by a binding | External provider client secret; server-only |
| `IAMKIT_ENCRYPTION_KEY` | Unset: features storing secrets fail | Base64 of 32 bytes; encrypts stored secrets (organization SSO client secrets, SMTP passwords, Resend API keys). See [encryption key](#encryption-key) |
| `IAMKIT_ENCRYPTION_KEYS_OLD` | Empty | Comma-separated previous keys, decrypt-only, for rotation |
| `CORS_ALLOWED_ORIGINS` | Empty: no CORS middleware | Comma-separated allowed origins; enables credentials, so never use untrusted origins or wildcard |
| `RATE_LIMIT_PER_MINUTE` | 120 | Per-IP, per-process limit on authenticated management and scoped API routes; invalid/non-positive values fall back to default |
| `IAMKIT_BOOTSTRAP_EMAIL` | Unset: no automatic bootstrap | First-boot owner email; automatic bootstrap logs a one-time key |
| `IAMKIT_BOOTSTRAP_WORKSPACE` | `Default` | First-boot workspace name |
| `IAMKIT_BOOTSTRAP_PASSWORD` | Optional | Sets a temporary password only when bootstrap creates the owner: the first console sign-in must replace it. Not a reset mechanism; remove it after bootstrap (a warning is logged while it stays set) |

## Email

The global fallback for environments without their own
[delivery configuration](../guides/email-delivery.md). Values are validated at
startup; an invalid one stops the server naming the variable.

| Variable | Requirement/default | Behavior |
| --- | --- | --- |
| `EMAIL_PROVIDER` | `webhook` | `webhook`, `smtp` or `resend` |
| `EMAIL_WEBHOOK_URL` | webhook: unset disables global fallback | Trusted HTTPS endpoint (HTTP on localhost/127.0.0.1); may be private; no URL userinfo/fragment |
| `EMAIL_WEBHOOK_TOKEN` | webhook | Sent as Bearer token and used to [sign requests](webhooks.md#signature) |
| `EMAIL_FROM` | smtp, resend: required | Sender address |
| `EMAIL_FROM_NAME`, `EMAIL_REPLY_TO` | Optional | Sender name, Reply-To address |
| `SMTP_HOST` | smtp: required | Host name or IP, no scheme or port; may be private |
| `SMTP_PORT` | `587` | |
| `SMTP_TLS` | `tls` on 465, else `starttls` | `starttls` or `tls` (implicit); plaintext is not supported |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | Optional; password required with a username | Server-only secret |
| `RESEND_API_KEY` | resend: required | Server-only secret |
| `EMAIL_LOCALE` | English | Default language of emails IAMKit writes: `en`, `es` |

Per-environment configurations are stored in PostgreSQL and managed through
`/management/v1/environments/:environment/delivery`. Deleting one restores global
fallback; unsetting global variables does not remove it.

### Private delivery addresses (development only)

Environment delivery settings are edited by operators, not by whoever runs the
server, so by default IAMKit connects to an environment's webhook or SMTP server
only on public addresses: loopback (`localhost`, `127.0.0.1`), private
(`10.x`, `192.168.x`, …), link-local (including cloud metadata at
`169.254.169.254`) and other reserved ranges are refused after DNS resolution,
as `webhook address is not allowed` / `email provider address is not allowed`.
This stops an operator from using "Send test" to make the server call internal
services (SSRF). The global `EMAIL_*`/`SMTP_*` settings are not restricted.

To test environment delivery against a receiver on your machine or a local
Mailpit from the console, set:

```dotenv
IAMKIT_ALLOW_PRIVATE_DELIVERY=true
```

Accepted values are those of Go's `strconv.ParseBool` (`true`/`false`, `1`/`0`,
…); anything else stops startup. When on, the server logs a warning at startup
and environment webhooks and SMTP servers may reach any address. The Resend API
endpoint is fixed and unaffected.

> **Never enable it in production or on any deployment where operators are not
> fully trusted with the server's network access.** It lets anyone who can edit
> delivery settings send requests from the server to your internal network and
> cloud metadata endpoint. For local testing without it, point the global
> `EMAIL_WEBHOOK_URL` (or `SMTP_HOST`) at the local receiver instead.

Provider example (replace values with approved registration data):

```dotenv
FEDERATION_CREDENTIAL_BINDINGS='[{"environment_id":"ENV_UUID","issuer":"https://accounts.google.com","client_id":"REGISTERED_CLIENT_ID","secret_env":"IAMKIT_PROVIDER_GOOGLE"}]'
IAMKIT_PROVIDER_GOOGLE=PRIVATE_CLIENT_SECRET
```

The `secret_env` name must reference a deployment-approved provider variable.
Do not allow app users to choose arbitrary outbound issuers or secret names.

## Encryption key

Organization SSO connections store their client secret, and environment email
delivery its SMTP password or Resend API key, encrypted with
AES-256-GCM under `IAMKIT_ENCRYPTION_KEY`. Generate one with
`openssl rand -base64 32` and keep it with your other deployment secrets.
The server starts without it, but saving such a secret then fails. A malformed
key stops startup.

Back the key up with the database: a restored database is useless for these
secrets without it. To rotate, set the new key, move the old one to
`IAMKIT_ENCRYPTION_KEYS_OLD`, restart, then re-save each secret
(`PATCH {"client_secret":…}` for connections, `PUT …/delivery` with the password
or API key for email) before dropping the old key. Stored values carry
the ID of their key, so old and new values coexist during rotation.

## Compose-only variables

`IAMKIT_PORT` controls host publishing. The source-build template uses
`POSTGRES_PASSWORD`; the image template uses `IAMKIT_DB_PASSWORD`. Both compose
`DATABASE_URL` for you. Use a random hex password or URL-encode special characters.
A published host port defaults to all interfaces unless explicitly restricted.

## Fixed contracts (not environment settings)

- Password length: 12–72 bytes for operators and, by default, end users (an
  environment's [password policy](../guides/password-policy.md) can raise the
  end-user minimum and add rules); bcrypt cost 12.
- JWTs: 15 minutes; user session/refresh window: 24 hours; operator session: 1 hour.
- Challenges: 5 minutes, 8-character code, at most 5 wrong attempts; a new challenge
  consumes previous unconsumed challenges of the same purpose.
- Outbound email timeout (webhook, SMTP, Resend): 10 seconds; HTTP redirects refused.
- HTTP body limit: 64 KiB. Endpoint-specific unauthenticated rate limits remain
  separate from `RATE_LIMIT_PER_MINUTE`.
- Credential `expires_in`: Go duration from `1h` through `8760h`; omitted/empty
  means `24h`. `never` means approximately 100 years, not literal infinity. Prefer
  finite expiry with tested rotation. Bootstrap/recovery uses 24h.

Do not invent environment overrides for these constants. Source:
`internal/config/constants.go`, `internal/identity/model.go`,
`internal/bootstrap/container.go`, `internal/server/server.go` and `cmd/iamkit/main.go`.

See [CLI](cli.md), [webhook](webhooks.md) and [deployment](../operations/deployment.md).
