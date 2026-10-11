# Authentication SDK

`authclient.New(baseURL, authclient.WithHTTPClient(httpClient))` calls identity
routes. Supply deadlines and never log token-pair values.

- `Login(ctx, PasswordLogin{LoginContext: boundary, Email: email, Password: password})`;
  set `Login` instead of `Email` to accept an email or a username.
- `Refresh(ctx, boundary, refreshToken)`; serialize and store replacements.
- `MachineToken(ctx, serviceSecret)`; no user refresh token.
- `ExchangeAPIKey(ctx, apiKey)` trades a machine user's `ik_key_` [API key](../../guides/machines/api-keys.md#machine-keys)
  for an access token (no refresh); user and organization keys cannot be
  exchanged, and `Validator` never accepts the raw `ik_key_` (see
  [validating API keys](#validating-api-keys)).
- `NewKeyLogin(url, machineUserID, keyID, key)` then `Token(ctx, KeyBoundary{...})`
  signs a machine user in with one of its [keys](../../guides/machines/machine-users.md#keys-jwt-bearer-login)
  (RFC 7523 JWT-bearer grant, fresh one-minute assertion per call, no refresh);
  `ParsePrivateKey(pem)` reads the private key IAMKit generated.
- `InitiateChallenge(ctx, environment, email, purpose)` (or `InitiateChallengeWith`
  with `ChallengeRequest.Login` for an email or username) and
  `VerifyChallenge(ctx, ChallengeVerification{...})`.
- Bot protection and risk signals: `Captcha(ctx, environment)` returns the
  `PublicCaptcha` (`Enabled`, `Provider`, `SiteKey`, `Headless`) to render;
  `PasswordLogin`, `ChallengeRequest`, `SignupRequest`, code-login and
  `DirectoryLogin` requests carry `CaptchaToken` (the widget's answer, tokens
  are single use) and `DeviceID` (a random 16–128 character id you keep per
  browser or install; without it `new_device` is not evaluated). Failures:
  `apierror.CodeCaptchaRequired` (`IsCaptchaRequired`, `Provider()`),
  `CodeSignInBlocked`, `CodeRiskChallenge`, `CodeChallengeUnavailable`; a
  [risk challenge](../../guides/sign-in/risk-signals.md#the-challenge) is a
  `TokenPair` with `MFAReason == authclient.MFAReasonRiskChallenge` and
  `Factors == ["email"]`: call `ChallengeMFA` with `"email"`, then `VerifyMFA`.
- `StartFederation(ctx, FederationStart{...})`; browser-cookie handling is still
  your integration's responsibility, not a headless substitute for browser binding.
- `PreviewInvitation(ctx, token)` and `AcceptInvitation(ctx, InvitationAcceptance{...})`
  for your invitation page; accepting does not sign in (see
  [invitations](../api/identity.md#invitations)).
- `Signup(ctx, SignupRequest{...})` then `CompleteSignup(ctx, environment,
  challengeID, code)` for your own sign-up page when the environment allows
  [sign-up](../../guides/sign-in/signup-and-onboarding.md#self-service-sign-up); the
  account signs in next (errors `apierror.CodeSignupDisabled`,
  `CodeAccountExists`).
- Self-service API keys (user keys, with the application access token of the
  person): `me := client.Me(accessToken, environmentID, audience)`, then
  `me.APIKeys(ctx, limit, offset)` (a `UserAPIKeys` page, `limit` 0 = the
  server default), `me.APIKeyOptions(ctx)`, `me.CreateAPIKey(ctx,
  NewUserAPIKey{ResourceID, Name, Permissions, ExpiresIn})` and
  `me.RevokeAPIKey(ctx, id)` over `/identity/v1/me/api-keys`. Creation needs a
  sign-in within 10 minutes (else 403 `REAUTHENTICATION_REQUIRED`), an enabled
  policy (403 `API_KEYS_DISABLED`) and room under the per-user limit (422
  `API_KEY_LIMIT_REACHED`); the answer's `Value` (`IssuedUserAPIKey`) is shown
  once. Impersonated tokens may only read.
- `Profile`, `UpdateProfile`, `Organizations`, `Logout`, `AddMember`.
- MFA: `Login` and `VerifyChallenge` succeed **without tokens** when a second
  factor is needed — check `MFARequired` before using `AccessToken` (then
  `ExpiresIn` is the 5-minute pending-login lifetime). Call `EnrollMFA(ctx, pair.MFAToken)`
  first if `EnrollmentRequired`, then `VerifyMFA(ctx, pair.MFAToken, code)`.
  For an email or SMS factor call `ChallengeMFA(ctx, pair.MFAToken, "email"|"sms")`
  first to send the code (masked `CodeSent.Destination`). For a security key
  (`"webauthn"` in `Factors`) call `AssertMFA(ctx, pair.MFAToken)`, pass
  `WebAuthnOptions.Options` to the browser, then
  `VerifyMFAWebAuthn(ctx, pair.MFAToken, session, credential)`.
  Passkeys: `BeginPasskeyLogin(ctx, environment)` then
  `PasskeyLogin(ctx, LoginContext{…}, session, credential)` (tokens directly,
  no second factor).
  Self-service: `ListFactors`, `StartTOTP`, `ConfirmTOTP`, `RemoveTOTP`,
  `StartEmailFactor`, `StartSMSFactor(…, phone)`, `ConfirmFactor(…, kind, code)`,
  `SendFactorCode(…, kind)`, `RemoveFactor(…, kind, code)`,
  `RegenerateRecoveryCodes`, and for security keys and passkeys
  `StartWebAuthn(…, name, passkey)`, `FinishWebAuthn(…, session, credential)`
  (→ `WebAuthnRegistration{Factor, RecoveryCodes}`), `ProveWebAuthn`,
  `RenameWebAuthn(…, factor, name)`, `RemoveWebAuthn(…, factor, WebAuthnProof{…})`
  (all but `ListFactors` need a sign-in within 10
  minutes, else 403 `REAUTHENTICATION_REQUIRED`). `Claims.HasMFA()` checks the `amr` claim
  (see [MFA](../../guides/sign-in/mfa.md)).
- `Introspect(ctx, token, issuer, audience, environment, application, resource)`
  validates current state plus configured boundaries.

`Validate(raw, rsaKey, issuer, audience, environment, application, resource)` is
explicitly offline. `ValidateWithKeySet(ctx, raw, keys, …same boundaries)` picks
the key by the token's `kid` from `NewKeySet(jwksURL, client)`, which caches
`/.well-known/jwks.json` (refresh every `MaxAge`, 10 minutes, and on an unknown
`kid` at most once per `MinRefresh`, 30 seconds), so tokens keep validating
across [signing-key rotations](../../guides/applications/signing-keys.md). After either validation mode, check organization and required
permissions. See [protected API example](../../start/protect-an-api.md).

OAuth helpers: `NewOAuth`, `NewPKCE`, `Exchange`, `Refresh`, `Revoke`,
`ClientCredentials` (service accounts: `NewOAuth(url, accountID, secret)`),
options `WithClientSecretPost` and `WithPrivateKeyJWT(key, kid, alg)` (signs a
fresh one-minute RFC 7523 assertion per request; introspection keeps Basic),
`UserInfo` (OIDC UserInfo), `Introspect` (RFC 7662, confidential clients) and
`EndSessionURL` (RP-initiated logout URL). Device authorization grant
(RFC 8628): `AuthorizeDevice(ctx, scopes...)` → `DeviceAuthorization{DeviceCode,
UserCode, VerificationURI, VerificationURIComplete, ExpiresIn, Interval}`,
`PollDevice(ctx, deviceCode)` (one poll; `*OAuthError` codes
`DeviceAuthorizationPending`, `DeviceSlowDown`, `DeviceAccessDenied`,
`DeviceExpired`) and `WaitDevice(ctx, authorization)` (polls at the interval,
+5 s per `slow_down`, until tokens, a final error or `ctx` ends);
`DeviceGrantType` is the grant URN. Token exchange (RFC 8693):
`ExchangeToken(ctx, subjectToken, audience, permissions...)` (a confidential
client with `TokenExchangeGrantType`: the user's token for another resource
of the application) and `Impersonate(ctx, user, organization, reason)` (a
service account allowed to impersonate), both → `ExchangedToken{AccessToken,
IssuedTokenType, TokenType, ExpiresIn}`; constants `AccessTokenType`,
`UserIDTokenType`. `Claims.Act` (`*Actor{Subject}`) is the RFC 8693 actor of
service-account impersonation; `Claims.Impersonated()` is true when
`ActorID` or `Act` is set.
`ValidateLogoutToken(ctx, raw, keys, issuer, clientID)` verifies the
`logout_token` IAMKit POSTs to a client's back-channel logout URL (signature,
`iss`, `aud`, `exp`, the logout event, `sid`, no `nonce`) and returns
`LogoutToken{Subject, SessionID, …}`; answer 400 on error, remember `jti` until
`exp` if you need replay protection. They do not
render login/consent or replace state/nonce validation. OAuth errors have a separate
`OAuthError` type. For query-bearing profile helpers, verify URL encoding for your
actual audience value; use `url.Values` in direct HTTP integrations.

The SDK does not provide a safe automatic retry policy for rotating credentials.
A timeout after a successful server rotation can make the predecessor unsafe to
reuse. Require reauthentication when the state cannot be reconciled safely.

## Validating API keys

Build the client with the environment and the audience of the resource your
service protects, then validate per request:

```go
client := authclient.New(iamkitURL, authclient.WithAudience(environmentID, "https://api.example.com"))
key, err := client.ValidateAPIKey(ctx, rawKey) // rawKey: the ik_key_… bearer
```

`ValidateAPIKey(ctx, apiKey)` checks an `ik_key_`
[API key](../../guides/machines/api-keys.md#validate-keys-in-your-backend)
online with `POST /identity/v1/introspect`, sending the environment and
audience from `WithAudience` (without them it fails with `VALIDATION`), and
returns an `authclient.APIKey`: `ID`, `Name`, `Owner` (`Type` `user`,
`organization` or `machine`; `ID` is the user, or the organization for an
organization key; `OrganizationID`), `OrganizationID`, `ResourceID`, the
**effective** `Permissions` (`HasPermission(p)`) and `ExpiresAt` (zero = never).
An unknown, revoked, expired or disabled key, a value that is not an API key,
or an audience other than the key's resource is a `401` `UNAUTHORIZED` error;
an unreachable IAMKit returns its own error, so never admit the request then.
`IsAPIKey(value)` tells the shape without a call. Keys have no offline form:
`Validate` and `ValidateWithKeySet` refuse `ik_key_` strings because they are
not JWTs. Scope your data by the owner's organization (and user, for user
keys). The [Fiber and net/http middleware](middleware.md#api-keys) accept keys
with the `AllowAPIKeys` option.
