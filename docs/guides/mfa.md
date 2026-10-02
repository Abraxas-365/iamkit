# Multi-factor authentication

IAMKit supports these second factors, plus single-use recovery codes:

| Kind | What the user proves | `amr` added |
| --- | --- | --- |
| `totp` | Authenticator app code (RFC 6238: 6 digits, 30-second steps, SHA-1, one step of clock skew) | `otp`, `mfa` |
| `email` | 6-digit code emailed to the account address | `otp`, `mfa` |
| `sms` | 6-digit code texted to a confirmed phone number | `sms`, `mfa` |
| `webauthn` | A security key or passkey (WebAuthn): the private key never leaves the device and signatures are bound to your domain, so it resists phishing | `hwk`, `mfa` |

Users can enroll voluntarily; an organization can require it. A **passkey**
is a WebAuthn credential that also signs the user in on its own, without a
password (see [Passkeys](#passkeys)).

## Allowed factors

The environment's [sign-in policy](sign-in-methods.md) lists the kinds users
may use in `allowed_factors` (default `["totp","webauthn"]`, so email and SMS
codes are off until you turn them on). An organization narrows it with its own
`allowed_factors` (default: every kind); a login accepts only kinds both
allow.

```bash
curl -X PUT $IAM/management/v1/environments/$ENV/sign-in-policy -H "X-API-Key: $KEY" \
  -d '{"allow_password":true,"allow_email_code":true,"allow_social":true,"allow_password_reset":true,"allowed_factors":["totp","email","sms"]}'
curl -X PATCH $IAM/management/v1/environments/$ENV/organizations/$ORG -H "X-API-Key: $KEY" \
  -d '{"allowed_factors":["totp","sms"]}'
```

Saving the sign-in policy without `allowed_factors` keeps the current list; an
empty list or an unknown kind is refused with 400. A factor the user already
has but that is no longer allowed is not offered at sign-in; when nothing
usable is left the user enrolls an allowed kind.

- **Email** codes go through the environment's [email delivery](email-delivery.md)
  with purpose `mfa` (template `mfa`, editable like the others). Your email
  webhook only ever receives purpose `mfa` once you allow the `email` factor.
  An email-code sign-in (`amr` `email`) never accepts the email factor as its
  second factor — same inbox.
- **SMS** needs an SMS provider for the environment (below). Users add a phone
  number from self-service; the first code confirms it (`users.phone`,
  `phone_verified`); users can also verify a phone without a factor
  ([phone numbers](user-profiles.md#phone-numbers)). Operators can set `phone`
  (`PATCH /users/:id`, the user page, `iam users update --phone`); a changed
  number is unverified and never changes an enrolled SMS factor.
- Codes last 5 minutes and are single use. One factor gets a new code at
  most every 30 seconds (429 `CODE_COOLDOWN`) and 10 per hour (429
  `CODE_LIMIT`). A failed delivery answers 502 and keeps the previous code.

## SMS provider

Per environment, `PUT /management/v1/environments/$ENV/sms`:

```json
{"provider":"twilio","account_sid":"AC…","auth_token":"…","from_number":"+15550001111"}
```

or with a Messaging Service (`messaging_service_sid` `MG…` instead of
`from_number`), or your own gateway:

```json
{"provider":"webhook","webhook_url":"https://sms.example.com/iamkit","webhook_token":"…"}
```

The Twilio auth token and webhook token are sealed with
`IAMKIT_ENCRYPTION_KEY` and never returned (`has_secret`). Omit them on a
later save to keep the stored one. A webhook receives
`POST {phone, purpose, code, body}` (`purpose` `mfa`, `phone_verification` or
`test`) with `Authorization: Bearer <token>` and a Standard Webhooks
signature (`webhook-id`, `webhook-timestamp`, `webhook-signature`, the token
as secret), like [email webhooks](email-delivery.md); answer 2xx. Twilio sends
`body`, translated to the environment's [language](hosted-login.md#language).

| Method/path | Result |
| --- | --- |
| `GET /sms` | The configuration (404 when none) |
| `PUT /sms` | Save it (audited `sms.update`) |
| `DELETE /sms` | Remove it (`sms.delete`); SMS codes then fail with 502 |
| `GET /sms/status` | `{configured, provider, last_attempt, last_failure}` (each attempt `{purpose, delivered, status?, reason?, latency_ms, at}`) |
| `POST /sms/test` | `{phone}` → sends a test text (`sms.test`, rate limited) |

Environment endpoints must be public addresses; set
`IAMKIT_ALLOW_PRIVATE_DELIVERY=true` only in development to reach a local
gateway. The same routes exist on the scoped API with `iam:delivery:read` /
`iam:delivery:write`.

From the CLI (secrets from stdin or environment variables, never flags):

```bash
IAMKIT_TWILIO_AUTH_TOKEN=... iam sms set --account-sid AC... --from +15550001111
printf %s "$TOKEN" | iam sms set --provider webhook --webhook-url https://sms.acme.io/iamkit --token-stdin
iam sms status
iam sms test +15551234567
iam sign-in-policy set --allowed-factors totp,webauthn,email,sms
iam organizations update ORG_ID --allowed-factors totp,sms
```

The console has the provider under **Sign-in → Notifications** (SMS card), the
allowed factors on **Sign-in → Sign-in methods** and on each organization's
overview. The Go SDK mirrors it: `iamclient.Environment.SMSConfig`,
`SetSMSConfig`, `DeleteSMSConfig`, `SMSStatus`, `TestSMS`,
`SetOrganizationFactors`, and `SignInPolicy.AllowedFactors`.

## Security keys and passkeys

The WebAuthn relying-party ID is the host of the issuer (`IAMKIT_ISSUER`),
and IAMKit accepts ceremonies from the issuer's origin: the hosted pages
work as they are. A custom sign-in UI on another origin (for example
`https://app.id.example.com` when the issuer is `https://id.example.com`) runs
them too if the browser accepts the issuer host as its relying-party ID (the
same host or a parent domain) and the origin is listed in
`IAMKIT_WEBAUTHN_ORIGINS` (comma-separated). An issuer on an IP address
disables security keys and passkeys (422 `FACTOR_NOT_ALLOWED`).

- Users register keys from self-service only (not while signing in), up to
  20 per user, each with a name (1–64 characters). The first factor of a
  user returns recovery codes.
- A registration with `passkey: true` asks the authenticator for a
  discoverable credential that verifies the user (PIN or biometrics); it is
  refused if the authenticator does not verify the user.
- Each assertion checks the origin, the challenge (single use, 5 minutes)
  and the signature counter. A counter that goes backwards means a cloned
  key: the sign-in is refused and audited `mfa.clone_detected`. Wrong
  assertions count toward the same lockout as wrong codes.
- The public key, counter, AAGUID, transports and backup flags are stored;
  IAMKit never sees a private key. Attestation is not required (`none`).

### Passkeys

A passkey signs in without email or password. The environment's
[sign-in policy](sign-in-methods.md) `allow_passkey` (default on) and the
organization's `allow_passkey` control it; `webauthn` must also be among the
allowed factors. The user proved possession *and* verified themself, so no
second factor follows and tokens carry `amr` `hwk`, `user`, `mfa`. Like a
password, a passkey is refused for an email an organization enforces SSO for
(unless the member may bypass it).

Headless, without knowing the user first:

```bash
curl -X POST $IAM/identity/v1/passkeys/login/begin -d '{"environment_id":"'$ENV'"}'
# → {"webauthn_session":"ik_wa_…","options":{…},"expires_at":"…"}
# navigator.credentials.get({publicKey: options}) in the browser, then:
curl -X POST $IAM/identity/v1/passkeys/login/finish \
  -d '{"environment_id":"'$ENV'","organization_id":"'$ORG'","application_id":"'$APP'","resource_id":"'$RES'","webauthn_session":"ik_wa_…","credential":{…}}'
```

`options` are the `PublicKeyCredentialRequestOptions` as JSON (base64url
binary fields); decode `challenge` and `allowCredentials[].id` before calling
the browser API, or use `PublicKeyCredential.parseRequestOptionsFromJSON`.
`credential` is the browser's `PublicKeyCredential.toJSON()`. A security key
registered without `passkey` cannot sign in this way (401).

Turn passkeys off for the environment or one organization with
`iam sign-in-policy set --allow-passkey=false` or
`iam organizations update ORG_ID --allow-passkey=false` (console: the
**Passkeys** switch under **Sign-in → Sign-in methods** and on the
organization's overview). The console lists each user's keys on their page
("Security key · name", "Passkey · name"); an operator reset removes them
like any factor.

## Policy

Per organization, `PATCH /management/v1/environments/$ENV/organizations/$ORG`:

```json
{"mfa_required": true, "mfa_for_federated": false}
```

| Situation | Second factor asked? |
| --- | --- |
| User has a confirmed, allowed factor | Always, for password and email-code logins |
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
  authenticator code or a recovery code → token pair. For a security key
  (`webauthn` in `factors`) call `POST /identity/v1/mfa/webauthn`
  `{mfa_token}` → `{webauthn_session, options, expires_at}`, run
  `navigator.credentials.get`, then `/mfa/verify`
  `{mfa_token, webauthn_session, credential}`. For an `email` or `sms`
  factor first call `POST /identity/v1/mfa/challenge` `{mfa_token, factor}` →
  202 `{factor, destination, expires_at}` (`destination` masked, e.g.
  `a•••@example.com`, `+1•••••••21`), then `/mfa/verify` with the received code.
- **`enrollment_required`:** `factors` lists what the login may add (`totp`,
  and `email` when allowed; SMS needs a phone number, so it is added from
  self-service). For an authenticator, `POST /identity/v1/mfa/enroll`
  `{mfa_token}` → `{secret, otpauth_uri}`: show the URI as a QR code, then call
  `/mfa/verify` with the first code. For email, `POST /mfa/challenge`
  `{mfa_token, factor:"email"}` and verify the emailed code. The answer carries
  the token pair plus `recovery_codes` (shown once).

A pending login lasts 5 minutes and allows 5 wrong codes, then the user must
sign in again. These endpoints are rate limited.

Wrong codes also count against the user, whichever factor they targeted,
across pending logins, hosted pages and self-service calls: after 10 in a row
every factor locks for
15 minutes (doubling on each further 10, up to 24 hours). While locked every
code, including the right one, gets 429 `MFA_LOCKED`; the lock is audited as
`mfa.locked`. A correct code resets the count. An operator reset clears it.
Switching to another factor does not reset the count.

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
| `GET /identity/v1/me/factors` | query | `{factors:[{id,kind,name?,phone?,confirmed_at,last_used_at,created_at}],recovery_codes_remaining,locked_until?}` |
| `POST /identity/v1/me/factors/totp` | — | 201 `{factor_id,secret,otpauth_uri}` (unconfirmed; replaces a previous unconfirmed one) |
| `POST /identity/v1/me/factors/email` | — | 202 `{factor,destination,expires_at}`: a code to the account address |
| `POST /identity/v1/me/factors/sms` | `phone` (E.164, spaces allowed) | 202 `{factor,destination,expires_at}`: a code to that number |
| `POST /identity/v1/me/factors/{kind}/confirm` | `code` | `{recovery_codes}`; the factor is active (for SMS the phone becomes the user's verified `phone`) |
| `POST /identity/v1/me/factors/{email,sms}/challenge` | — | 202: a code to the active factor, to prove possession before removing it |
| `DELETE /identity/v1/me/factors/{kind}` | `code` (any active factor or recovery) | 204; also removes recovery codes when no other factor remains |
| `POST /identity/v1/me/factors/recovery-codes` | `code` | `{recovery_codes}`; old codes stop working |
| `POST /identity/v1/me/factors/webauthn` | `name`, `passkey` | 201 `{webauthn_session,options,expires_at}`: pass `options` to `navigator.credentials.create` |
| `POST /identity/v1/me/factors/webauthn/confirm` | `webauthn_session`, `credential` | 201 `{factor,recovery_codes?}`; the key is active |
| `POST /identity/v1/me/factors/webauthn/challenge` | — | `{webauthn_session,options,expires_at}`: a key assertion that proves possession |
| `PATCH /identity/v1/me/factors/webauthn/{id}` | `name` | The renamed factor |
| `DELETE /identity/v1/me/factors/webauthn/{id}` | `code`, or `webauthn_session` + `credential` | 204; recovery codes go when no other factor remains |

Security keys and passkeys are listed with `kind` `webauthn`, their `name`
and `passkey: true` for passkeys. A key assertion (`webauthn_session` +
`credential`) also proves possession for `DELETE /me/factors/{kind}` and
`/me/factors/recovery-codes`.

Enrolling a kind the environment or organization does not allow gets 422
`FACTOR_NOT_ALLOWED`.

Removing and regenerating require a current code; a wrong code gets 422
`INVALID_CODE`. Every changing call (enroll, confirm, remove, regenerate) also needs a session that signed in
within the last 10 minutes (the token's `auth_time`; refreshing does not
renew it) — otherwise 403 `REAUTHENTICATION_REQUIRED`: sign in again and
retry. Impersonated tokens get 403 on all of these.

Recovery codes look like `abcd-efgh-2345` (case and dashes are ignored). Each
works once; there are 10.

## Hosted login and OAuth

[Hosted login](hosted-login.md) adds a code page after the credential step and,
when the organization requires it, an enrollment page with a QR code (and,
when the email factor is allowed, a button to use emailed codes instead) and
the recovery codes. Users with an email or SMS factor get a "send code" button
per factor on the code page, and users with a security key get a "Use a
security key" button (the page's only script, bound to its CSP nonce). A user with several organizations is asked for the second
factor before choosing one if they are enrolled (password and email-code
sign-ins; after SSO it comes once the organization is known).

Wrong codes on a hosted sign-in share one budget of 5 per authorization,
even when sent in parallel or after entering the password again; then the
user starts over from the email page.

Hosted clients can offer "Sign in with a passkey" and passkey autofill on
the email field (the client's sign-in option `passkey`, on by default for
new clients; clients configured before passkeys existed keep it off until
changed).

Access tokens and OIDC ID tokens carry `amr`: `pwd`, `email` or `fed`, plus
`otp` + `mfa` after an authenticator or email code, `sms` + `mfa` after a
text, `hwk` + `mfa` after a security key, `mfa` alone after a recovery code;
a passkey sign-in carries `hwk`, `user`, `mfa` (see [token claims](../reference/token-claims.md)).
Use `amr` containing `mfa` to require step-up in your API
(`authclient.Claims.HasMFA()` in the Go SDK).

## Operators

- `GET /management/v1/environments/$ENV/users/$USER/factors` lists factors
  (never secrets).
- `DELETE …/users/$USER/factors` resets them (lost device). The user enrolls
  again at the next sign-in if their organization requires it.
- Scoped API (`/api/v1/…/users/:id/factors`) exposes the same two operations.

Audit actions: `mfa.enrolled`, `mfa.removed`, `mfa.recovery_regenerated`,
`mfa.recovery_used`, `mfa.reset`, `mfa.locked`, `mfa.clone_detected`, and for the SMS provider
`sms.update`, `sms.delete`, `sms.test`. Permanently deleting a user erases their
factors, recovery codes and pending logins.

TOTP secrets and SMS provider credentials are sealed with `IAMKIT_ENCRYPTION_KEY` (enrollment fails without
it, like sealed SSO secrets); recovery codes and sent codes are stored hashed. **Set the key
before turning on `mfa_required`:** without it, members who have no
authenticator cannot enroll and so cannot sign in.
