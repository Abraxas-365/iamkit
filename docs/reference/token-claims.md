# Token claims

Access tokens are signed RSA JWTs — except for OAuth clients set to
`access_token_format: opaque`, whose access tokens are random `ory_at_…` handles
that only `/oauth/introspect` and `/oauth/userinfo` resolve (introspection
returns the claims below). ID tokens are always JWTs. Consumers of JWTs must verify the expected issuer,
audience, expiry and RS256 algorithm, then application-specific boundaries.
Base claims include `iss`, `sub`, `aud`, `exp`, `iat`, and `jti` where issued.
Do not decode without verifying and treat that as authentication.

| Claim | Meaning |
| --- | --- |
| `environment_id` | Identity/data boundary |
| `application_id` | Requesting application |
| `resource_id` | Target protected resource |
| `permissions` | Exact permission strings |
| `purpose` | `application` or `machine` for API access; `api_key` only in [introspection of an API key](#api-key-validation) |
| `organization_id` | Tenant on user/application tokens; absent for machines |
| `sid` | User session identifier; absent for machines |
| `actor_id` | Operator attribution on impersonated tokens; absent otherwise |
| `act` | `{"sub": "<service account id>"}` ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) on tokens a service account got by [impersonation](../guides/organizations/impersonation.md#service-accounts-token-exchange) |
| `api_key` | `{id, name, owner:{type,id,organization_id}, resource_id, permissions, expires_at}`; only with `purpose` `api_key` |
| `oauth_client_id` | OAuth client binding when applicable; absent otherwise |
| `amr` | How the session authenticated: `pwd`, `email` or `fed`, plus `otp` + `mfa` (authenticator or email code), `sms` + `mfa` (text), `hwk` + `mfa` (security key) or `mfa` (recovery code) after a [second factor](../guides/sign-in/mfa.md); a [passkey](../guides/sign-in/mfa.md#passkeys) sign-in is `hwk`, `user`, `mfa`; a machine user [key](../guides/machines/machine-users.md#keys-jwt-bearer-login) sign-in is `swk`. Also in OIDC ID tokens |
| `scp` | OAuth scopes granted (OAuth access tokens only) |
| `auth_time` | When the session signed in (Unix seconds); unchanged by refreshes. Absent on machine and impersonation tokens; [exchanged](../guides/applications/oauth-oidc.md#calling-another-api-as-the-user-token-exchange) tokens keep the original |

Application-purpose tokens need subject, organization and session context.
Machine tokens must not be interpreted as organization users. OIDC ID tokens
identify the authentication event to a client; they are not business API tokens.
ID tokens carry `sid` (the session `/oauth/end_session` ends), `environment_id`
and `organization_id`; with the `profile` scope, ID tokens and UserInfo also carry
the profile attributes the [user schema](../guides/organizations/user-profiles.md) annotates
with `x-iamkit-claim` (under that name; absent when the user has no value).

`GET /.well-known/jwks.json` publishes verification material, never private keys.
Fetch only from the configured issuer, not an arbitrary token-supplied URL.
It lists the deployment key and every environment's `next`, `active` and
`retiring` keys; the token's `kid` header picks one. Environments
[rotate keys](../guides/applications/signing-keys.md) without re-login: cache the JWKS by
`kid` and refresh on an unknown `kid` (the SDK's `authclient.KeySet` does).
An environment key only verifies tokens of its own environment. Offline
validation cannot observe revocation before expiry.

`POST /identity/v1/introspect` checks current state and returns `active` with
claims when valid. Its expected environment/audience must come from trusted API
configuration; still compare application/resource/organization and permissions.
See [protected API](../start/protect-an-api.md). OAuth resource servers can use
RFC 7662 `POST /oauth/introspect` instead ([protocol reference](api/oauth-oidc.md)).

Opaque OAuth access tokens (`ory_at_…`) are not JWTs. The OAuth token endpoint
can accept one as the subject of a resource token exchange, but resource servers
resolve it through the confidential-client `/oauth/introspect` endpoint (or use
`/oauth/userinfo` for OpenID Connect); they must not send it to `/api/v1` or
`/identity/v1`.

## API key validation

An `ik_key_…` [API key](../guides/machines/api-keys.md) is not a JWT: it has no
signature to verify offline. Send it as the bearer of
`POST /identity/v1/introspect` with the `environment_id` and the `audience` of
the key's resource. An active key answers claims with `purpose` `api_key`:

| Claim | Meaning |
| --- | --- |
| `purpose` | `api_key` |
| `sub` | The user for user and machine keys; empty for organization keys |
| `environment_id`, `organization_id`, `resource_id` | The key's boundaries; `aud` is the resource's audience |
| `permissions` | The **effective** permissions, computed at this request (key list ∩ allowlist ∩ the owner's live reach) |
| `exp` | Unix seconds, or `0` when the key never expires |
| `api_key` | The key's `id`, `name`, `owner` (`type` `user`, `organization` or `machine`, `id`, `organization_id`), `resource_id`, `permissions` and `expires_at` (Unix seconds, `0` = never) |

There are no `sid`, `amr` or `auth_time`: no session exists. An unknown, revoked,
expired or disabled key, an inactive owner or an audience that is not the key's
resource is `{"active":false}`. A machine key exchanged at
`/identity/v1/token-exchange` yields an ordinary `machine`-style access token, not
these claims.

