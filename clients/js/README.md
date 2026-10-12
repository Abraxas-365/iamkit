# @iamkit/js

Browser sign-in flows for **custom sign-in UIs** on IAMKit, the same steps
the hosted pages run: describe an authorize ticket, sign in with a password,
an emailed code, a passkey, LDAP or single sign-on, answer the second factor,
sign up, accept invitations, then complete the OAuth authorization. Built on
the generated client [`@iamkit/api`](../typescript).

```ts
import { createSignIn, boundaryOf, IAMKitError, ErrorCodes } from "@iamkit/js";

const iam = createSignIn({ baseUrl: "https://id.example.com" });

// 1. The relying app sent the browser here with its authorize query.
//    (Or call iam.authorize(query) to start it from this UI.)
const ticket = new URLSearchParams(location.search).get("ticket")!;
const authz = await iam.authorization(ticket); // client, methods, branding, locale

// 2. Sign in.
const boundary = boundaryOf(authz, authz.organization_id ?? chosenOrganization);
let result = await iam.login(boundary, { login, password });
if (result.status === "mfa_required") {
  const tokens = await iam.mfa.verify(result.mfa.mfa_token, code);
  result = { status: "signed_in", tokens };
}

// 3. Complete: IAMKit answers the client's redirect URI with the code.
location.assign(await iam.complete(ticket, result.tokens.access_token));
```

## Requirements

- The OAuth client lists the UI's origin in `allowed_origins` (CORS on
  `/identity/v1/*` and `/oauth/*`), and is not a `hosted_login` client.
- Every request is sent with `credentials: "include"`: the authorize ticket
  is bound to the browser by IAMKit's `__Host-iamkit-authorization` cookie,
  so `authorize`, `authorization` and `complete` must run in the same
  browser.
- Passkeys and security keys: the UI's origin must be in
  `IAMKIT_WEBAUTHN_ORIGINS` (the RP ID is the issuer host, so the UI must be
  on that host or a subdomain of it).

## Flows

| Call | Route |
|------|-------|
| `authorize(query)` | `GET /oauth/authorize` → ticket (JSON) |
| `authorization(ticket)` | `GET /identity/v1/authorize/:ticket` |
| `discover(env, email)` | `POST /identity/v1/discover` (SSO routing) |
| `login(boundary, {login, password, newPassword?})` | `POST /identity/v1/login` |
| `sendCode` / `verifyCode` / `resetPassword` | `/identity/v1/challenges[/verify]` |
| `passkey(boundary, {mediation?})` | `/identity/v1/passkeys/login/*` |
| `mfa.verify` / `mfa.send` / `mfa.enroll` / `mfa.securityKey` | `/identity/v1/mfa/*` |
| `federation.start` / `federation.finish` | `/identity/v1/federation/start`, `/federation/result` (PKCE) |
| `federation.ldap` | `/identity/v1/federation/ldap/login` |
| `signup.start` / `signup.verify` | `/identity/v1/signup[/verify]` |
| `invitation.preview` / `invitation.accept` | `/identity/v1/invitations/*` |
| `organizations(accessToken, …)` | `GET /identity/v1/organizations` (see also `createAccount`) |
| `complete(ticket, accessToken, approve?)` | `POST /oauth/authorize/complete` (JSON) |
| `getCaptchaConfig(env)` | `GET /identity/v1/captcha/:environment` (public) |

Every sign-in step resolves a `SignInResult`: `{status: "signed_in", tokens}`
or `{status: "mfa_required", mfa}`. Failures throw `IAMKitError` with the
HTTP `status`, IAMKit's `code` (see `ErrorCodes`, e.g.
`PASSWORD_CHANGE_REQUIRED` → call `login` again with `newPassword`) and
public `details`.

## Account: self-service for a signed-in user

`createAccount` is the typed client of the user's own account over
`/identity/v1` (profile, phone, password, sessions, API keys, second factors,
passkeys, organizations). It stores nothing: `getAccessToken` is called before
every request, so hand it a function that refreshes when needed.

```ts
import { createAccount, isReauthenticationRequired, switchRefusal } from "@iamkit/js";

const account = createAccount({
  baseUrl: "https://id.example.com",
  environmentId: ENV_ID,
  audience: "https://api.example.com",   // the access token's audience
  getAccessToken: () => session.accessToken,
});

const me = await account.me();
try {
  await account.changePassword(current, next);      // other sessions end
} catch (e) {
  if (isReauthenticationRequired(e)) { /* ask the user to sign in again */ }
}
const tokens = await account.switchOrganization(refreshToken, otherOrganizationId);
```

| Call | Route |
|------|-------|
| `me()` / `updateMe({name?, avatarUrl?})` | `GET`/`PATCH /identity/v1/me` |
| `properties()` / `updateProperties(profile)` | `GET`/`PATCH /identity/v1/me/profile` (self-service profile properties) |
| `phone.start(phone)` / `phone.verify(phone, code)` / `phone.remove()` | `/identity/v1/me/phone[/verify]` |
| `changePassword(current, next)` | `POST /identity/v1/me/password` → `{sessions_revoked}` |
| `sessions.list({limit?, offset?})` / `sessions.revoke(id)` / `sessions.revokeOthers()` | `/identity/v1/me/sessions[/:id\|/revoke-others]` |
| `apiKeys.list(filter?)` / `options()` / `create(key)` / `revoke(id)` | `/identity/v1/me/api-keys[/options\|/:key]` (`create` returns `value` once) |
| `organizations()` | `GET /identity/v1/organizations` |
| `switchOrganization(refreshToken, organizationId, boundary?)` | `POST /identity/v1/refresh` with `switch_organization_id` → new `Tokens` |
| `mfa.factors()` | `GET /identity/v1/me/factors` → `{factors, recovery_codes_remaining}` |
| `mfa.totp.start/confirm/remove`, `mfa.email.start/confirm/send/remove`, `mfa.sms.start(phone)/confirm/send/remove` | `/identity/v1/me/factors/{totp,email,sms}[/confirm\|/challenge]` |
| `mfa.recoveryCodes(proof)` | `POST /identity/v1/me/factors/recovery-codes` |
| `passkeys.list()` / `add(name, {passkey})` / `rename(id, name)` / `remove(id, proof)` | `/identity/v1/me/factors/webauthn[/:id]` (`add` runs the browser ceremony; `begin`/`finish` are its two server calls) |
| `passkeys.prove()` / `passkeys.assert()` | `POST …/factors/webauthn/challenge`: a key assertion to use as `proof` |

`confirm` and `recoveryCodes` answer the recovery codes (shown once). `proof`
for removals is a code of any active factor or a recovery code, or (passkeys)
`{webauthnSession, credential}` from `passkeys.assert()`.

Errors are `IAMKitError` (`status`, `code`, `details`). Password, phone, API
key and factor changes need a recent sign-in: `REAUTHENTICATION_REQUIRED`
(`isReauthenticationRequired(e)`). `changePassword` also throws
`INVALID_CURRENT_PASSWORD`, `NO_PASSWORD` and `PASSWORD_POLICY`
(`details.rule`). A `switchOrganization` the target's sign-in rules refuse is
`REAUTHENTICATION_REQUIRED` too: `switchRefusal(e)` gives
`{organizationId, reason: "sso" | "mfa" | "method"}` — start a new
authorization with that organization. `switchOrganization` reads the current
boundary from the access token's claims (pass `boundary` for an opaque token).

Types: `Profile`, `Session`, `SessionPage`, `Factor`, `FactorSummary`,
`ApiKey`, `ApiKeyPage`, `ApiKeyOptions`, `IssuedApiKey`, `NewApiKey`,
`Organization`, `Page`, `PasswordChanged`, `Proof`, `Tokens`, `Boundary`.

## Bot protection and risk signals

Both are off until the operator configures them; nothing changes for UIs
that ignore them.

- **CAPTCHA.** When the environment's bot protection covers headless
  sign-in, `getCaptchaConfig(env)` (or `Authorization.captcha` on the ticket)
  gives the `provider` (`turnstile`, `hcaptcha`) and `site_key`. Solve the
  widget and pass its answer as `captchaToken` to `login`, `sendCode`,
  `signup.start` and `federation.ldap`. A missing or invalid token throws
  `CAPTCHA_REQUIRED` (`isCaptchaRequired(e)`, `captchaProvider(e)`): solve a
  fresh widget and retry (tokens are single use).
- **Device id.** Sign-in calls carry a `device_id`: 32 random hex characters
  created once in `localStorage` (`iamkit.device_id`). It enables the
  new-device detection and the user's device list; it is not a fingerprint.
  Pass `deviceId: "…"` to supply your own, `deviceId: false` to opt out (per
  call too), `deviceStorage` to keep it elsewhere. Nothing is sent where
  there is no storage (server rendering).
- **Risk challenge.** An unusual sign-in answers `mfa_required` with
  `mfa.reason === "risk_challenge"` and `factors: ["email"]`: call
  `mfa.send(token, "email")`, then `mfa.verify(token, code)` — the same as an
  email second factor.
- **Errors.** `SIGN_IN_BLOCKED` (`isSignInBlocked`) means a restriction or
  risk rule refused the sign-in: do not retry. `RISK_CHALLENGE` and
  `CHALLENGE_UNAVAILABLE` (no verified email to send the code to) have
  `isRiskChallenge` / `isChallengeUnavailable`.

Tokens are never stored. The only state kept is the federation PKCE
verifier, in `sessionStorage` (or the `storage` option) between
`federation.start` and `federation.finish` on the `returnTo` page.

## Development

```sh
cd ../typescript && npm ci && npm run build   # the generated client
npm ci && npm run typecheck && npm test && npm run build
```
