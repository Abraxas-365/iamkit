# Token claims

Access tokens are signed RSA JWTs. Consumers must verify the expected issuer,
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
| `actor_id` | Operator attribution on impersonated tokens |
| `oauth_client_id` | OAuth client binding when applicable |

Application-purpose tokens need subject, organization and session context.
Machine tokens must not be interpreted as organization users. OIDC ID tokens
identify the authentication event to a client; they are not business API tokens.

`GET /.well-known/jwks.json` publishes verification material, never private keys.
Fetch only from the configured issuer, not an arbitrary token-supplied URL.
A single active signing key is configured; plan cache invalidation and re-login
when changing it. Offline validation cannot observe revocation before expiry.

`POST /identity/v1/introspect` checks current state and returns `active` with
claims when valid. Its expected environment/audience must come from trusted API
configuration; still compare application/resource/organization and permissions.
See [protected API](../guides/protect-an-api.md).
