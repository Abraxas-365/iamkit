# Next.js custom sign-in example

A Next.js (App Router) application that signs users in with **its own UI**
instead of IAMKit's hosted pages. It uses [`@iamkit/react`](../../clients/react)
(`<SignInForm>`, `<AcceptInvitation>`) over [`@iamkit/js`](../../clients/js).
The application itself stays an ordinary OIDC client (code + PKCE).

```text
/ (server action)  → /sign-in?client_id=…&code_challenge=…   app's own page
/sign-in (browser) → GET  IAMKit /oauth/authorize            ticket + binding cookie
                   → POST IAMKit /identity/v1/…              password, code, MFA, sign-up…
                   → POST IAMKit /oauth/authorize/complete   → redirect_to
/callback (server) → POST IAMKit /oauth/token                code + verifier → ID token
```

No token is stored in the browser. The access token from the sign-in only
completes the authorization. The app's session is the verified ID token,
kept in an httpOnly cookie.

## Requirements on the IAMKit side

- A **public** OAuth client (`"public": true`) **without** `hosted_login`.
  Its redirect URI is `${APP_URL}/callback`, and `allowed_origins` contains
  `APP_URL`, so IAMKit answers CORS for the browser's calls.
- HTTPS everywhere. The issuer, redirect URIs and the `__Host-` binding
  cookie all require it (HTTP only on loopback for the issuer).
- The app and IAMKit should be **same-site** (e.g. `login.example.com` and
  `app.example.com`), because the binding cookie is `SameSite=Lax`. Browsers
  that block third-party cookies would otherwise drop it on the sign-in
  calls. `localhost` on different ports counts as same-site.
- For passkeys and security keys, add the app's origin to
  `IAMKIT_WEBAUTHN_ORIGINS`.

## Run

```bash
cd examples/nextjs-login
npm install
IAMKIT_ISSUER=https://iam.example.com \
IAMKIT_CLIENT_ID=<client uuid> \
APP_URL=https://app.example.com \
IAMKIT_ORGANIZATION_ID=<default organization uuid, optional> \
npm run build && npm start
```

| Variable | Meaning |
| --- | --- |
| `IAMKIT_ISSUER` | IAMKit's public URL, which is the browser's base URL and the ID token issuer |
| `IAMKIT_INTERNAL_URL` | Optional: where this server reaches IAMKit (token, JWKS); defaults to the issuer |
| `IAMKIT_CLIENT_ID` | The public OAuth client |
| `APP_URL` | This app's public URL |
| `IAMKIT_ORGANIZATION_ID` | Optional: the organization to sign in to when the authorize request names none and the email has no SSO organization |

Invitation emails can link to `${APP_URL}/invitation?token=…` instead of
the hosted invitation page.

## Parity journeys (Playwright)

`e2e/journeys.spec.ts` replays the hosted journeys of
`tests/e2e/hosted_test.go` and `custom_ui_test.go` through this UI in a
real browser: password sign-in with a single-use ticket, a wrong password,
an emailed code, a password reset, MFA enrollment with recovery codes,
sign-up with email verification, and invitation acceptance.

`e2e/run.sh` builds IAMKit from this checkout and starts a disposable stack:
Postgres in Docker, a TLS proxy, a mail webhook sink and this app. It seeds
the stack through the management API (`e2e/seed.mjs`), runs the journeys,
and removes everything on exit.

```bash
cd examples/nextjs-login
npm ci && npx playwright install chromium
bash e2e/run.sh
```

Needs Docker, Go, Node ≥ 20 and OpenSSL.
