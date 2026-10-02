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
| `organizations(accessToken, …)` | `GET /identity/v1/organizations` |
| `complete(ticket, accessToken, approve?)` | `POST /oauth/authorize/complete` (JSON) |

Every sign-in step resolves a `SignInResult`: `{status: "signed_in", tokens}`
or `{status: "mfa_required", mfa}`. Failures throw `IAMKitError` with the
HTTP `status`, IAMKit's `code` (see `ErrorCodes`, e.g.
`PASSWORD_CHANGE_REQUIRED` → call `login` again with `newPassword`) and
public `details`.

Tokens are never stored. The only state kept is the federation PKCE
verifier, in `sessionStorage` (or the `storage` option) between
`federation.start` and `federation.finish` on the `returnTo` page.

## Development

```sh
cd ../typescript && npm ci && npm run build   # the generated client
npm ci && npm run typecheck && npm test && npm run build
```
