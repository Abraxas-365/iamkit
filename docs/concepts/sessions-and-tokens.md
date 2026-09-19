# Sessions and tokens

Password, OTP and linked-provider login produce an application-purpose access
JWT plus a refresh token. The JWT is scoped to one environment, organization,
application and resource. A second login creates a separate session for the same
local user, including when the provider differs.

Access tokens last 15 minutes. Refresh rotates the opaque token within a fixed
24-hour session window. Persist the replacement atomically; serialize refresh
requests across tabs/workers. Reusing an old refresh token is replay, not a safe
retry: it can revoke the family. After an ambiguous network failure, do not race
multiple retries with the old token; require sign-in if necessary.

Logout/revocation invalidates the stored session. Online introspection observes
current state; offline signature verification does not learn about logout,
suspension or grant removal before expiry. Select this trade-off deliberately.

Machine tokens carry no organization/session and have no user refresh flow. Renew
by exchanging the service credential while it remains valid. Impersonation tokens
carry attribution and do not grant a refresh session.

Password changes invalidate sessions/challenges through database enforcement.
Test reset and revocation with live introspection, not just decoding claims.

See [token claims](../reference/token-claims.md), [password login](../guides/password-login.md)
and [protected API](../guides/protect-an-api.md).
