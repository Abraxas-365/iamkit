# Passwords, reset and email verification

The password journeys your application drives through the identity API: sign in,
recover a forgotten password and verify an email address. Rules for what a
password must contain, lockout and expiry are in [password policy](password-policy.md);
which methods are offered is set in [sign-in methods](sign-in-methods.md).

## Password login

Prerequisites: active local user with a password, organization membership,
application-resource binding and effective resource grant. See
[first application](../../start/first-application.md). Your browser/BFF needs IDs, not
management credentials.

```js
const response = await fetch('/identity/v1/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...boundary, email, password }),
})
if (!response.ok) throw new Error('Sign-in failed')
const tokens = await response.json()
```

`boundary` contains `environment_id,organization_id,application_id,resource_id`.
The URL assumes same-origin proxying. Use the [browser helpers](../../examples/browser/auth.js)
for complete request handling. Keep tokens out of URLs/logs; a BFF should retain
refresh tokens server-side. Do not use browser local storage as an unexplained default.

For refresh, POST the same boundary plus `refresh_token` to `/identity/v1/refresh`.
Serialize requests and store the replacement atomically. Replay can revoke the
family. On logout, POST `{environment_id,audience}` with the access token to
`/identity/v1/logout`, then clear local tokens even if the network fails; distinguish
local signout from confirmed server revocation.

**Verify:** correct context succeeds; wrong password, absent membership or wrong
resource fails. Login does not automatically enforce `email_verified`; enforce
email-ownership onboarding policy deliberately. Show a generic sign-in error,
not whether an address exists. Provide [password reset](passwords.md#forgot-password) when
email delivery is configured.

With a [password policy](password-policy.md) that expires passwords, a correct
but expired password answers 403 `PASSWORD_CHANGE_REQUIRED`: ask for a new one
and repeat the request with `new_password` (400 `PASSWORD_POLICY` explains a
rejected one via `details.rule`). Locked accounts answer the same 401 as a wrong
password. When the environment or the organization turns password sign-in off
([sign-in methods](sign-in-methods.md)), login answers 403
`METHOD_NOT_ALLOWED` for every email, known or not.

## Forgot password

Your app provides the form. IAMKit uses the challenge API with
`purpose:"password_reset"`; [email delivery](../platform/email-delivery.md) must be configured.
The user must already have a password. This flow does not add a password to a
federation-only/passwordless account.

```http
POST /identity/v1/challenges
Content-Type: application/json

{"environment_id":"ENV_UUID","email":"alice@example.com","purpose":"password_reset"}
```

Show the generic 202 message, store the returned challenge ID and collect the
8-character code and a new password that follows the environment's
[password policy](password-policy.md) (default 12–72 bytes). Then:

```http
POST /identity/v1/challenges/verify
Content-Type: application/json

{"environment_id":"ENV_UUID","challenge_id":"CHALLENGE_UUID","code":"12345678","purpose":"password_reset","password":"new-unique-password"}
```

Use real IDs and the delivered code. Success is **204 with no token response**;
return the user to login. Full org/app/resource context is not required for reset.
Reset marks email verified, clears a [password lockout](password-policy.md#lockout),
restarts password expiry, and password changes invalidate sessions/challenges;
offline JWT consumers cannot observe revocation instantly. A password that breaks
the policy answers 400 `PASSWORD_POLICY` with `details.rule`; members of an
organization with [password requirements](password-policy.md#organization-requirements)
must meet those too. When the environment turns reset off
([sign-in methods](sign-in-methods.md)), both calls answer 403
`PASSWORD_RESET_DISABLED`.

Codes expire in five minutes, are single-use and allow five failures. Resending
supersedes the old same-purpose challenge. Never log codes or new passwords.

**Verify:** new password logs in; old password fails; replayed reset fails; old
session is rejected by online introspection. Use a disposable user for the test.

## Email verification

Use `purpose:"email_verification"` with the same two-step challenge API:

1. POST `/identity/v1/challenges` with `environment_id`, `email`, purpose.
2. POST `/identity/v1/challenges/verify` with the environment, returned
   `challenge_id`, delivered 8-character `code` and the same purpose.
3. Expect 204; read the user/profile to confirm `email_verified:true`.

The local user must exist and be active; verification is not public registration.
The challenge requires configured [mail delivery](../platform/email-delivery.md). Use generic
messages and test expiry/replay just like OTP. App/resource context and a password
are not needed to verify an email challenge.

**Policy matters:** recording `email_verified` does not automatically block all
password logins before verification. If your product requires verification before
access, keep onboarding grants withheld until your policy checks pass. Do not
assume the client UI hiding a button enforces this requirement.

OTP and password reset also mark the email verified on successful challenge
completion. Provider email claims are not a substitute for explicit local subject
linking. See [signup](signup-and-onboarding.md).
