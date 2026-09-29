# Multi-factor authentication (TOTP)

IAMKit supports authenticator-app second factors (TOTP, RFC 6238: 6 digits,
30-second steps, SHA-1, one step of clock skew) plus single-use recovery
codes. Users can enroll voluntarily; an organization can require it.

## Policy

Per organization, `PATCH /management/v1/environments/$ENV/organizations/$ORG`:

```json
{"mfa_required": true, "mfa_for_federated": false}
```

| Situation | Second factor asked? |
| --- | --- |
| User has a confirmed authenticator | Always, for password and email-code logins |
| Organization `mfa_required`, user not enrolled | Yes: the user enrolls during that login |
| SSO login | Only with `mfa_for_federated` (the identity provider is trusted by default, even for enrolled users) |
| Service accounts, refresh | Never (refresh keeps the original session's `amr`) |

The policy of the organization being signed in to applies, combined with the
environment's [sign-in methods](sign-in-methods.md) policy: its `mfa_required`
and `mfa_for_federated` apply to every organization (either one requiring it
is enough). The console shows the organization's switches on its overview
page and the environment's under **Sign-in → Sign-in methods**.

## Headless login

`POST /identity/v1/login` (and email-code `/challenges/verify` or the SSO
callback) answers with tokens, or, when a second factor is needed:

```json
{"mfa_required":true,"mfa_token":"ik_mfa_…","factors":["totp","recovery"],"enrollment_required":false,"expires_in":300}
```

No session exists yet. Continue with the same `mfa_token`:

- **Enrolled:** `POST /identity/v1/mfa/verify` `{mfa_token, code}` with the
  authenticator code or a recovery code → token pair.
- **`enrollment_required`:** `POST /identity/v1/mfa/enroll` `{mfa_token}` →
  `{secret, otpauth_uri}`. Show the URI as a QR code, then call
  `/mfa/verify` with the first code. The answer carries the token pair plus
  `recovery_codes` (shown once).

A pending login lasts 5 minutes and allows 5 wrong codes, then the user must
sign in again. Both endpoints are rate limited.

Wrong codes also count against the authenticator itself, across pending
logins, hosted pages and self-service calls: after 10 in a row it locks for
15 minutes (doubling on each further 10, up to 24 hours). While locked every
code, including the right one, gets 429 `MFA_LOCKED`; the lock is audited as
`mfa.locked`. A correct code resets the count. An operator reset clears it.

The trade-off: anyone who knows a user's password can trigger the lock
(recovery codes are refused too while it lasts), which blocks the real user
from signing in. Watch for `mfa.locked` in the audit log; an operator can
lift it with `DELETE /users/:id/factors`, after which the user enrolls again.
Unfinished enrollments expire after 15 minutes and can no longer be
confirmed.

## Self-service

With an application access token (`environment_id` and `audience` in the
body, or query for GET):

| Method/path | Body | Result |
| --- | --- | --- |
| `GET /identity/v1/me/factors` | query | `{factors:[{id,kind,confirmed_at,last_used_at,created_at}],recovery_codes_remaining}` |
| `POST /identity/v1/me/factors/totp` | — | 201 `{factor_id,secret,otpauth_uri}` (unconfirmed; replaces a previous unconfirmed one) |
| `POST /identity/v1/me/factors/totp/confirm` | `code` | `{recovery_codes}`; the factor is active |
| `DELETE /identity/v1/me/factors/totp` | `code` (TOTP or recovery) | 204; also removes recovery codes |
| `POST /identity/v1/me/factors/recovery-codes` | `code` | `{recovery_codes}`; old codes stop working |

Removing and regenerating require a current code; a wrong code gets 422
`INVALID_CODE`. Every changing call (enroll, confirm, remove, regenerate) also needs a session that signed in
within the last 10 minutes (the token's `auth_time`; refreshing does not
renew it) — otherwise 403 `REAUTHENTICATION_REQUIRED`: sign in again and
retry. Impersonated tokens get 403 on all of these.

Recovery codes look like `abcd-efgh-2345` (case and dashes are ignored). Each
works once; there are 10.

## Hosted login and OAuth

[Hosted login](hosted-login.md) adds a code page after the credential step and,
when the organization requires it, an enrollment page with a QR code and the
recovery codes. A user with several organizations is asked for the second
factor before choosing one if they are enrolled (password and email-code
sign-ins; after SSO it comes once the organization is known).

Wrong codes on a hosted sign-in share one budget of 5 per authorization,
even when sent in parallel or after entering the password again; then the
user starts over from the email page.

Access tokens and OIDC ID tokens carry `amr`: `pwd`, `email` or `fed`, plus
`otp` and `mfa` after a second factor (see [token claims](../reference/token-claims.md)).
Use `amr` containing `mfa` to require step-up in your API
(`authclient.Claims.HasMFA()` in the Go SDK).

## Operators

- `GET /management/v1/environments/$ENV/users/$USER/factors` lists factors
  (never secrets).
- `DELETE …/users/$USER/factors` resets them (lost device). The user enrolls
  again at the next sign-in if their organization requires it.
- Scoped API (`/api/v1/…/users/:id/factors`) exposes the same two operations.

Audit actions: `mfa.enrolled`, `mfa.removed`, `mfa.recovery_regenerated`,
`mfa.recovery_used`, `mfa.reset`, `mfa.locked`. Permanently deleting a user erases their
factors, recovery codes and pending logins.

Secrets are sealed with `IAMKIT_ENCRYPTION_KEY` (enrollment fails without
it, like sealed SSO secrets); recovery codes are stored hashed. **Set the key
before turning on `mfa_required`:** without it, members who have no
authenticator cannot enroll and so cannot sign in.
