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
- `PreviewInvitation(ctx, token)` and `AcceptInvitation(ctx, InvitationAcceptance{...})`
  for your invitation page; accepting does not sign in (see
  [invitations](../api/identity.md#invitations)).
- `Profile`, `UpdateProfile`, `Organizations`, `Logout`, `AddMember`.
- MFA: `Login` and `VerifyChallenge` succeed **without tokens** when a second
  factor is needed — check `MFARequired` before using `AccessToken` (then
  `ExpiresIn` is the 5-minute pending-login lifetime). Call `EnrollMFA(ctx, pair.MFAToken)`
  first if `EnrollmentRequired`, then `VerifyMFA(ctx, pair.MFAToken, code)`.
  Self-service: `ListFactors`, `StartTOTP`, `ConfirmTOTP`, `RemoveTOTP`,
  `RegenerateRecoveryCodes` (all but `ListFactors` need a sign-in within 10
  minutes, else 403 `REAUTHENTICATION_REQUIRED`). `Claims.HasMFA()` checks the `amr` claim
  (see [MFA](../../guides/mfa.md)).
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
