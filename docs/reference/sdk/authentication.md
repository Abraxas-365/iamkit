# Authentication SDK

`authclient.New(baseURL, authclient.WithHTTPClient(httpClient))` calls identity
routes. Supply deadlines and never log token-pair values.

- `Login(ctx, PasswordLogin{LoginContext: boundary, Email: email, Password: password})`
- `Refresh(ctx, boundary, refreshToken)`; serialize and store replacements.
- `MachineToken(ctx, serviceSecret)`; no user refresh token.
- `InitiateChallenge(ctx, environment, email, purpose)` and
  `VerifyChallenge(ctx, ChallengeVerification{...})`.
- `StartFederation(ctx, FederationStart{...})`; browser-cookie handling is still
  your integration's responsibility, not a headless substitute for browser binding.
- `Profile`, `UpdateProfile`, `Organizations`, `Logout`, `AddMember`.
- `Introspect(ctx, token, issuer, audience, environment, application, resource)`
  validates current state plus configured boundaries.

`Validate(raw, rsaKey, issuer, audience, environment, application, resource)` is
explicitly offline. After either validation mode, check organization and required
permissions. See [protected API example](../../guides/protect-an-api.md).

OAuth helpers: `NewOAuth`, `NewPKCE`, `Exchange`, `Refresh`, `Revoke`. They do not
render login/consent or replace state/nonce validation. OAuth errors have a separate
`OAuthError` type. For query-bearing profile helpers, verify URL encoding for your
actual audience value; use `url.Values` in direct HTTP integrations.

The SDK does not provide a safe automatic retry policy for rotating credentials.
A timeout after a successful server rotation can make the predecessor unsafe to
reuse. Require reauthentication when the state cannot be reconciled safely.
