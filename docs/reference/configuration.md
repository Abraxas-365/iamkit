# Configuration reference

IAMKit reads **process environment**, not `.env` automatically. Compose
`--env-file` provides interpolation values; a variable must also be listed in
`environment:` or supplied through `env_file:` to enter the container. Restart
containers after changes. Keep secrets outside source control and frontend builds.

| Variable | Requirement/default | Behavior |
| --- | --- | --- |
| `DATABASE_URL` | Required | PostgreSQL connection string; CLI commands need it too |
| `JWT_ISSUER` | Required to serve | Absolute HTTPS URL; development HTTP allowed only for localhost/127.0.0.1/[::1] (including OAuth/hosted sign-in); no credentials/query/fragment; trailing slash normalized |
| `JWT_PRIVATE_KEY_PATH` | Required to serve | Readable PEM RSA key, PKCS#1 or PKCS#8, at least 2048 bits |
| `SERVER_PORT` | `8080` | Listening port; image healthcheck assumes 8080 |
| `OIDC_HMAC_SECRET` | OAuth provider needs at least 32 bytes | Stable secret for OAuth; Compose templates require it explicitly |
| `EMAIL_*`, `SMTP_*`, `RESEND_API_KEY` | Unset: no global email delivery | Deployment-wide email fallback; see [email](#email) |
| `IAMKIT_ALLOW_PRIVATE_DELIVERY` | `false` | **Development only.** Lets environment email/SMS webhooks, SMTP servers, event webhooks, action targets, OAuth clients' `jwks_uri` and back-channel logout URIs, and federation identity providers reach localhost and private networks; see [private delivery addresses](#private-delivery-addresses-development-only) |
| `FEDERATION_CREDENTIAL_BINDINGS` | No approved bindings when unset | JSON array of exact environment/issuer/client/secret-reference approvals |
| `IAMKIT_PROVIDER_*` | As referenced by a binding | External provider client secret; server-only |
| `IAMKIT_ENCRYPTION_KEY` | Unset: features storing secrets fail | Base64 of 32 bytes; encrypts stored secrets (organization SSO client secrets, SMTP passwords, Resend API keys). See [encryption key](#encryption-key) |
| `IAMKIT_ENCRYPTION_KEYS_OLD` | Empty | Comma-separated previous keys, decrypt-only, for rotation |
| `IAMKIT_LDAP_ALLOWED_HOSTS` | Empty: public addresses only | Comma-separated hosts or `host:port` of [LDAP directories](../guides/enterprise/ldap.md) on private networks that IAMKit may dial; every other directory must resolve to a public address |
| `IAMKIT_WEBAUTHN_ORIGINS` | Empty: only the issuer's origin | Comma-separated extra origins (custom sign-in UIs) allowed to run [security key and passkey](../guides/sign-in/mfa.md#security-keys-and-passkeys) ceremonies; the relying-party ID stays the issuer's host |
| `CORS_ALLOWED_ORIGINS` | Empty: no CORS middleware | Comma-separated allowed origins; enables credentials, so never use untrusted origins or wildcard |
| `IAMKIT_TRUSTED_PROXIES` | Empty: the socket address is the client | Comma-separated IPs/CIDRs of the reverse proxies whose `X-Forwarded-For` names the client (and whose `X-Forwarded-Proto`/`-Host` are read); see [forwarded headers](../operations/reverse-proxy.md#forwarded-headers). An invalid entry stops start-up |
| `RATE_LIMIT_PER_MINUTE` | 120 | Per-IP limit on authenticated management and scoped API routes, per process (shared by the replicas with `REDIS_URL`); invalid/non-positive values fall back to default |
| `REDIS_URL` | Unset: everything per process, no cache | Optional `redis://` or `rediss://` URL. Replicas then share per-IP rate limits and per-minute [usage limits](../guides/platform/usage-limits.md), and cache a few hot reads; PostgreSQL stays the source of truth. See [scaling](../operations/scaling-and-abuse.md#redis-optional). An invalid URL stops start-up; an unreachable server does not |
| `IAMKIT_BOOTSTRAP_EMAIL` | Unset: no automatic bootstrap | First-boot owner email; automatic bootstrap logs a one-time key |
| `IAMKIT_BOOTSTRAP_WORKSPACE` | `Default` | First-boot workspace name |
| `IAMKIT_BOOTSTRAP_PASSWORD` | Optional | Sets a temporary password only when bootstrap creates the owner: the first console sign-in must replace it. Not a reset mechanism; remove it after bootstrap (a warning is logged while it stays set) |
| `IAMKIT_OPERATOR_SSO_PROVIDERS` | Unset: operators sign in with a password only | Comma-separated IDs of the identity providers operators sign in to the console with; each is configured by `IAMKIT_OPERATOR_SSO_<ID>_*`. See [operator single sign-on](#operator-single-sign-on) |
| `IAMKIT_OPERATOR_PASSWORD_LOGIN` | `enabled` without SSO, `break_glass` with SSO | Console password sign-in: `enabled`, `break_glass` (only operators an owner granted emergency access) or `disabled` (`true`/`false` mean enabled/disabled). Restricting it needs an SSO provider; an invalid value stops start-up |
| `OTEL_EXPORTER_OTLP_ENDPOINT` and other standard `OTEL_*` | Unset: no traces or metrics exported | OpenTelemetry export over OTLP/HTTP; see [observability](../operations/observability.md#tracing-and-metrics) |
| `IAMKIT_EVENT_RETENTION` | `2160h` (90 days) | How long the [event log](events.md) keeps events (Go duration, at least `1h`); older ones are pruned hourly |
| `IAMKIT_WORKERS` | `true` | `false` turns off background jobs (back-channel logout delivery, event pruning) on this replica; keep them on in at least one. See [background jobs](../operations/observability.md#background-jobs) |
| `IAMKIT_FEATURES` | — | Deployment values of IAMKit's [feature flags](../guides/platform/feature-flags.md): `name=true\|false,…` (e.g. `saml_idp=false`); unknown names are logged and ignored |
| `IAMKIT_LIMITS` | — | Deployment caps of the [usage limits](../guides/platform/usage-limits.md): `name=value,…` (e.g. `users_max=10000,requests_per_minute=600`); environments can only tighten them. Unknown names or invalid values stop start-up |
| `IAMKIT_METRICS_ADDR` | Unset: no Prometheus listener | Address (for example `127.0.0.1:9464`) of a separate listener serving Prometheus `/metrics`; never the public port |

## Local HTTP development

For local OAuth and hosted sign-in, set `JWT_ISSUER=http://localhost:8080`
(or `http://127.0.0.1:8080`). Use that same hostname consistently in browser
URLs and client configuration. HTTP is refused for public hosts, LAN addresses
and `0.0.0.0`; use HTTPS for those deployments.

Browser bindings retain their `Secure`, `HttpOnly` and `__Host-` cookie
protections. Use a browser that supports secure cookies on HTTP loopback
(verified with Chrome), or a local TLS proxy if your browser or OIDC client
requires HTTPS. Operator console SSO still requires an HTTPS issuer.

## Email

The global fallback for environments without their own
[delivery configuration](../guides/platform/email-delivery.md). Values are validated at
startup; an invalid one stops the server naming the variable.

| Variable | Requirement/default | Behavior |
| --- | --- | --- |
| `EMAIL_PROVIDER` | `webhook` | `webhook`, `smtp` or `resend` |
| `EMAIL_WEBHOOK_URL` | webhook: unset disables global fallback | Trusted HTTPS endpoint (HTTP on localhost/127.0.0.1); may be private; no URL userinfo/fragment |
| `EMAIL_WEBHOOK_TOKEN` | webhook | Sent as Bearer token and used to [sign requests](email-webhooks.md#signature) |
| `EMAIL_FROM` | smtp, resend: required | Sender address |
| `EMAIL_FROM_NAME`, `EMAIL_REPLY_TO` | Optional | Sender name, Reply-To address |
| `SMTP_HOST` | smtp: required | Host name or IP, no scheme or port; may be private |
| `SMTP_PORT` | `587` | |
| `SMTP_TLS` | `tls` on 465, else `starttls` | `starttls` or `tls` (implicit); plaintext is not supported |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | Optional; password required with a username | Server-only secret |
| `RESEND_API_KEY` | resend: required | Server-only secret |
| `EMAIL_LOCALE` | English | Default language of emails IAMKit writes: any available [language](../guides/applications/hosted-login.md#language) code (`en`, `es`, `de`, `fr`, …) |

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
and these outbound calls may reach any address:

- environment email and SMS webhooks and SMTP servers;
- [event webhooks](event-webhooks.md) and [action](../guides/platform/actions.md) targets;
- OAuth clients' `jwks_uri` (`private_key_jwt`) and `backchannel_logout_uri`
  (still https only: give the local receiver a TLS certificate);
- identity providers of federation connections with a stored client secret.

The Resend and Twilio API endpoints are fixed and unaffected; LDAP directories
use `IAMKIT_LDAP_ALLOWED_HOSTS` instead.

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

Organization SSO connections store their client secret (LDAP: bind password),
environment email delivery its SMTP password or Resend API key, and SMS
providers, event webhooks, action targets, TOTP factors and environment
signing keys their secrets, encrypted with
AES-256-GCM under `IAMKIT_ENCRYPTION_KEY`. Generate one with
`openssl rand -base64 32` and keep it with your other deployment secrets.
The server starts without it, but saving such a secret then fails. A malformed
key stops startup.

Back the key up with the database: a restored database is useless for these
secrets without it. To rotate, set the new key, move the old one to
`IAMKIT_ENCRYPTION_KEYS_OLD`, restart, then re-seal each secret before
dropping the old key (TOTP secrets cannot be re-sealed: keep the old key
while they are in use); the steps per secret are in
[secrets and keys](../operations/secrets-and-keys.md#encryption-key-rotation). Stored values carry
the ID of their key, so old and new values coexist during rotation.

## Operator single sign-on

Operators (the console's users, not your applications' users) can sign in
with your organization's identity provider instead of a password. Register
an OIDC web application at the provider with the redirect URI
`<JWT_ISSUER>/management/v1/sso/callback`, then list it:

```dotenv
IAMKIT_OPERATOR_SSO_PROVIDERS=corp
IAMKIT_OPERATOR_SSO_CORP_TYPE=oidc
IAMKIT_OPERATOR_SSO_CORP_NAME=Acme SSO
IAMKIT_OPERATOR_SSO_CORP_ISSUER=https://idp.example.com
IAMKIT_OPERATOR_SSO_CORP_CLIENT_ID=REGISTERED_CLIENT_ID
IAMKIT_OPERATOR_SSO_CORP_CLIENT_SECRET_FILE=/run/secrets/operator_sso_corp
IAMKIT_OPERATOR_SSO_CORP_ALLOWED_DOMAINS=example.com
```

| `IAMKIT_OPERATOR_SSO_<ID>_…` | Meaning |
| --- | --- |
| `TYPE` | `oidc`, `google` or `microsoft`; may be left out when the ID is one of these. GitHub and Apple are refused (personal accounts outlive offboarding) |
| `NAME` | Button label, at most 100 characters; defaults to Google, Microsoft or the capitalized ID |
| `ISSUER` | `oidc` only: HTTPS issuer URL without credentials, query or fragment. Google and Microsoft set it themselves |
| `CLIENT_ID` | Required |
| `CLIENT_SECRET` or `CLIENT_SECRET_FILE` | Exactly one is required |
| `ALLOWED_DOMAINS` | Required, 1–100 comma-separated domains. Checked on every sign-in: the identity's email must be in one of them (Google: the Workspace `hd` claim too) |
| `TENANT` | `microsoft` only, required: a tenant ID, or `organizations` together with `TENANTS`. `common` and `consumers` are refused |
| `TENANTS` | `microsoft` with `TENANT=organizations` only: 1–100 tenant IDs |

`<ID>` is 1–32 lowercase letters, digits or dashes, written upper-case with
`_` for `-` in the variable names (`my-idp` → `IAMKIT_OPERATOR_SSO_MY_IDP_*`).
All settings are checked at start-up and a mistake stops it; the providers
themselves are only contacted at the first sign-in. Variables with the prefix
that match no listed provider are logged as ignored.

There is no just-in-time creation: invite the operator first
(`POST /management/v1/operators`). The first SSO sign-in links the identity
to the active operator with that email, if the provider says the email is
verified (an `oidc` or single-tenant Microsoft directory that sends no
`email_verified` is trusted within the allowed domains); later sign-ins match
the linked identity. An owner resets a link with
`DELETE /management/v1/operators/:id/identities` (for example after the
operator's account moved to another tenant).

With a provider configured, password sign-in defaults to `break_glass`:
only operators an owner granted emergency access
(`PUT /management/v1/operators/:id/password-access`) can still use their
password (others get 403 `SSO_REQUIRED`, only after their password matched). Set `IAMKIT_OPERATOR_PASSWORD_LOGIN=enabled` to keep passwords for
everyone, or `disabled` to refuse them (403 `PASSWORD_LOGIN_DISABLED`).
Failed sign-ins land on the console's `/login?sso_error=` with `expired`,
`not_authorized`, `provider_unavailable`, `cancelled` or `failed`; the
reason is in the server log.

## Compose-only variables

`IAMKIT_PORT` controls host publishing. The source-build template uses
`POSTGRES_PASSWORD`; the image template uses `IAMKIT_DB_PASSWORD`. Both compose
`DATABASE_URL` for you. Use a random hex password or URL-encode special characters.
A published host port defaults to all interfaces unless explicitly restricted.

## Fixed contracts (not environment settings)

- Password length: 12–72 bytes for operators and, by default, end users (an
  environment's [password policy](../guides/sign-in/password-policy.md) can raise the
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

See [CLI](cli.md), [webhook](email-webhooks.md) and [deployment](../operations/deployment.md).
