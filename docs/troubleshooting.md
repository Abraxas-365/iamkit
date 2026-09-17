# Troubleshooting

Common errors and their actual cause, keyed by the message you'll see in the
`{"error":{"code","message","type","http_status"}}` envelope (see
[Concepts → errors are classified](concepts.md#errors-are-classified-not-just-http-codes)).
Messages are deliberately generic for security-sensitive failures (e.g. invalid credentials) —
don't try to disambiguate those from the message text; the fixes below cover the realistic
causes.

## Setup / migrations

**`unmanaged database schema: use an empty database; automatic legacy adoption is forbidden`**
(`migrations/migrate.go:40`)
`migrate` found existing tables it didn't create. Point `DATABASE_URL` at a genuinely empty
database — IAMKit will never adopt an existing schema. If you're re-running locally with Compose,
`docker compose down -v` first (see [Configuration](configuration.md#database-not-environment-variables)).

**`applied migration checksum changed: <name>`** (`migrations/migrate.go:68`)
An already-applied migration file's contents no longer match what was recorded in
`iamkit_migrations`. Migrations are immutable once applied — never hand-edit a shipped
`NNN_*.sql` file; add a new numbered file instead. This usually means a stale build or a manual
DB edit.

**Bootstrap fails with a generic error / `--output` complaint**
`bootstrap`/`recover-owner` refuse to write over an existing file (`os.O_EXCL`) and require
`--output` explicitly so the credential is never only in shell history or logs
(`cmd/iamkit/main.go`). Point `--output` at a path that does not yet exist.

## Login / tokens

**`invalid credentials or access token`** on `POST /identity/v1/login`
(`internal/iam/authentication/authsvc/service.go:42,55`)
One of: wrong email/password, `environment_id`/`organization_id`/`application_id`/`resource_id`
isn't a valid UUID, the user has no password (federation/passwordless-only — use that user's
actual login method), or the user/organization/application/resource combination doesn't exist.
The message intentionally doesn't distinguish "wrong password" from "no such user" — see
[Concepts → every token is a 4-way boundary](concepts.md#every-token-is-a-4-way-boundary). Also
check `password` isn't over 72 bytes — bcrypt's limit, enforced on login; user creation also
enforces a 12-byte minimum.

**`{"active":false}` from `POST /identity/v1/introspect`**
The token is expired, revoked (logout/session revoke/grant removal), or — most commonly — your
`environment_id`/`audience` in the introspect body don't match what the token was actually
issued for. Introspection checks boundaries strictly; a token for one resource's audience will
never validate against another's, even in the same environment. See
[Getting started §8](getting-started.md#8-validate-the-token-like-a-resource-server-would).

**A previously-working permission disappeared from a fresh token**
Expected behavior, not a bug: shrinking a resource's permission catalog immediately strips that
permission from every grant/role/service-account referencing it — see
[Getting started §9](getting-started.md#9-see-a-permission-check-fail-on-purpose) and
[Concepts → permissions, roles and grants](concepts.md#permissions-roles-and-grants).

**`refresh token replay revoked session`** (`authsvc/service.go:112`)
A refresh token was used twice (e.g. two processes racing on the same stored token, or a stale
client retry). This isn't a bug to work around — replay detection intentionally kills the whole
session family for safety. The user needs to log in again.

**`invalid refresh token`**
Either the token was already rotated (use the *newest* refresh token you were issued, not one
from an earlier response) or the 24-hour session family has expired outright.

## Federation (Google/Microsoft/OIDC)

**`provider credential is not approved for this environment, issuer and client`**
(`internal/iam/federation/fedsvc/service.go:36`)
`POST /federation-connections` was called with an `{issuer, client_id}` that isn't in
`FEDERATION_CREDENTIAL_BINDINGS` for that exact `environment_id`. This is a hard allow-list, not
just documentation — add a matching entry and restart before creating the connection. See
[Configuration](configuration.md#optional-external-federation-google-microsoft-any-oidc-provider).

**`HTTPS issuer, client ID and IAMKIT_PROVIDER_ secret variable required`**
`secret_env` must match `^IAMKIT_PROVIDER_[A-Z0-9_]+$` exactly, and `issuer` must be a bare
HTTPS URL (no userinfo, query string, or fragment). Check for typos like a trailing `/` mismatch
against the binding.

**`external identity is not linked`** (`fedpg/repository.go`, surfaced as 401 from
`/identity/v1/federation/callback`)
The Google/Microsoft account authenticated successfully, but no
`POST /external-identities {connection_id,user_id,subject}` call has linked that provider
`subject` to an IAMKit user yet. This is not automatic by design — see
[Concepts → explicit linking over inference](concepts.md#explicit-linking-over-inference) and
[Recipes → Google login](recipes.md#recipe-let-a-products-users-sign-in-with-google) for the
provisioning step you're missing.

**`federation requires HTTPS issuer`**
Your deployment's `JWT_ISSUER`/base URL isn't HTTPS. Federation and OAuth browser-binding
cookies require HTTPS; this isn't relaxable for local convenience once federation is enabled.

## OAuth / OIDC server

**`prompt and max_age are not supported by the headless authorization interaction`**
(`oauthsvc/service.go:120`)
Intentional: IAMKit's `/oauth/authorize` rejects `prompt`/`max_age` rather than pretending to
honor a fresh-authentication request it can't actually fulfill (no hosted login UI). Your own
application's login screen is responsible for that UX, not the OAuth parameter.

**`login does not match client`** (`oauthsvc/service.go:140`)
The user Bearer token presented to `/oauth/authorize/complete` was issued for a different
application/resource than the OAuth client being approved. Re-authenticate with the correct
boundary first.

**`invalid authorization ticket or browser binding`**
The `authorization_ticket` from `/oauth/authorize` is stale, already consumed, or the request
came from a browser session without the matching binding cookie (e.g. a cross-origin retry, or
the cookie expired/was cleared). Restart the authorization flow from `/oauth/authorize`.

## SCIM

**401 on any `/scim/v2/...` call**
The `ik_scim_...` secret is wrong, expired (24-hour default — see
[Deployment](deployment.md#4-optional-subsystems--only-enable-what-you-need)), or revoked. Rotate
via `POST /provisioning-credentials` with the existing `connection_id`, then delete the old
credential — see [Recipes → SCIM](recipes.md#recipe-provision-users-automatically-from-your-identity-provider-scim).

**Manager reference rejected / cycle error on PATCH**
SCIM enterprise `manager.value` must reference a user provisioned by the *same* SCIM connection,
and manager chains cannot cycle. Cross-connection or self-referential manager values are
rejected outright, not silently ignored.

## Still stuck?

- Re-check the exact request shape against [API guide](api.md) — most `VALIDATION`-type errors
  are a missing/malformed field, not a deeper issue.
- Re-read [Concepts](concepts.md) if a rejection feels like it "should" work — several of these
  are intentional boundaries (explicit linking, no wildcard scope, exact permission catalogs),
  not bugs.
- Check [Security status](../SECURITY.md) for known gaps that are deployment work, not something
  the API can be configured around (rate limiting, audit retention, etc.).
