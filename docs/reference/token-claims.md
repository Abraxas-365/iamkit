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
| `purpose` | `application` or `machine` for API access |
| `organization_id` | Tenant on user/application tokens; absent for machines |
| `sid` | User session identifier; absent for machines |
| `actor_id` | Operator attribution on impersonated tokens; absent otherwise |
| `act` | `{"sub": "<service account id>"}` ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) on tokens a service account got by [impersonation](../guides/organizations/impersonation.md#service-accounts-token-exchange) |
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
See [protected API](../start/protect-an-api.md). OAuth resource servers can
use RFC 7662 `POST /oauth/introspect` instead ([protocol reference](api/oauth-oidc.md)).
