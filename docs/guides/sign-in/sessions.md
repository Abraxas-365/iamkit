# Your users' sessions

Every sign-in opens a **session**: it is what refresh tokens, back-channel
logout and the `sid` claim hang on. IAMKit records where each session was opened
from and lets users see and end their own sessions: a "Where you're signed in"
page for your application, without any admin involved.

## Where a session was opened from

The request that creates a session leaves two facts on it:

- `ip_address`: the client address Fiber resolves (`c.IP()`). Behind a reverse
  proxy this is the proxy's address unless you list it in
  [`IAMKIT_TRUSTED_PROXIES`](../../reference/configuration.md): then the
  address comes from `X-Forwarded-For` (see
  [forwarded headers](../../operations/reverse-proxy.md#forwarded-headers)).
  The address is only as trustworthy as the proxy in front of IAMKit: with
  `IAMKIT_TRUSTED_PROXIES` set, whatever `X-Forwarded-For` says is taken, so the
  edge proxy must **overwrite** the header with the address it saw, not append
  to a value the client sent. Otherwise a client can put any address in the
  list of sessions.
- `user_agent`: the `User-Agent` header with control characters and Unicode
  bidirectional override characters removed, cut to 512 characters.

Both are `null` when unknown: sessions opened before this feature, and
sessions not created by an HTTP request. Token-exchange child sessions record
the exchange request's client. Impersonation sessions (an operator's or a
service account's) record neither, so the user does not see the impersonator's
address. Operators see the same two fields in the console
(**Users → user → Recent sessions**, columns *IP address* and *Device*) and in
`GET …/sessions`.

## List the caller's sessions

`GET /identity/v1/me/sessions?environment_id=ENV&audience=AUD`, authenticated
with the user's IAMKit access token (the same token as `GET /me`; service-account
tokens and API keys used directly get 403; the application token
a machine user gets by exchanging an API key or with a JWK key is an
ordinary session token and manages that machine user's own sessions). It returns the user's **live** sessions (not
revoked, not expired) across all their organizations and applications in the
environment, newest first, in the usual paginated envelope (`limit`, `offset`):

```json
{
  "items": [
    {
      "id": "6c1b…",
      "current": true,
      "organization": {"id": "…", "name": "Acme"},
      "application": {"id": "…", "name": "web"},
      "oauth_client_id": null,
      "created_at": "2025-03-01T10:00:00Z",
      "authenticated_at": "2025-03-01T10:00:00Z",
      "expires_at": "2025-03-08T10:00:00Z",
      "amr": ["pwd"],
      "ip_address": "203.0.113.7",
      "user_agent": "Mozilla/5.0 …",
      "impersonated": false
    }
  ],
  "page": {"total": 1, "limit": 20, "offset": 0}
}
```

`current` marks the session of the token that asked. `impersonated` marks
sessions an operator or service account opened on the user's behalf (see
[impersonation](../organizations/impersonation.md)). Sessions created by
[token exchange](../applications/oauth-oidc.md) (`parent_session_id`) are
**not listed**: they live and end with the session they came from, which stands
for them. Impersonated tokens may list.

## End sessions

| Call | Result |
|---|---|
| `DELETE /identity/v1/me/sessions/:id` | 204. 404 when the id is unknown or not the caller's (the two are indistinguishable). Ending the current session is allowed and signs the token out |
| `POST /identity/v1/me/sessions/revoke-others` | 200 `{"count": n}`: every other live session ended; the current one stays |

Impersonated tokens get **403** on both: a support user must not sign the real
user out. Both take `environment_id` and `audience` in the query (or, for the
POST, the JSON body) and share the rate limit of the other `/me` routes
(30 per minute).

Ending a session uses the same path as an operator revoking it: its refresh
tokens stop working, token-exchange children end with it, `session.revoked` is
emitted (with the user as actor) and [back-channel logout](../applications/oauth-oidc.md)
is queued for sessions opened through an OAuth client. Each call that ended a session is also audited
(`session.revoke_own`, or `session.revoke_others` with `data.count`, event
`user.sessions_revoked`); a revoke-others call that finds nothing to end writes
no audit row or event. Access tokens already issued stay valid until they
expire, as with any revocation; resource servers that must react at once
introspect.

## SDKs

- Go: `authclient.Client.ListSessions`, `RevokeSession`, `RevokeOtherSessions`
  (`sdk/authclient`).
- Any other language: call the three endpoints above; they are in the
  [OpenAPI document](../../reference/api/openapi.md) (`@iamkit/api` types).
