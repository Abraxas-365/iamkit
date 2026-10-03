# Identity API

Base: `/identity/v1`. JSON bodies use `Content-Type: application/json`.
`boundary` below means UUID fields `environment_id`, `organization_id`,
`application_id`, `resource_id`. No management key is accepted as user login proof.

| Method/path | Input/authority | Success |
| --- | --- | --- |
| `POST /login` | boundary + `email` or `login` (email or [username](../../guides/user-profiles.md#usernames)), `password`; optional `new_password` to replace an expired one | 200 token pair, or an [MFA step](#multi-factor); 403 `PASSWORD_CHANGE_REQUIRED` when the [password policy](../../guides/password-policy.md) expired the password; 403 `FACTOR_NOT_ALLOWED` when the user must enroll a second factor but none the policies allow can be added at sign-in |
| `POST /mfa/verify` | `mfa_token`, `code` (TOTP, emailed/texted code, or recovery), or `webauthn_session` + `credential` (security key) | 200 token pair (+ `recovery_codes` after enrollment); rate limited |
| `POST /mfa/enroll` | `mfa_token` of a login with `enrollment_required` | 200 `{secret,otpauth_uri}`; rate limited |
| `POST /mfa/challenge` | `mfa_token`, `factor` (`email`\|`sms`) | 202 `{factor,destination,expires_at}`; 422 `FACTOR_NOT_ALLOWED`; 429 `CODE_COOLDOWN`/`CODE_LIMIT`; rate limited |
| `POST /mfa/webauthn` | `mfa_token` of a login with `webauthn` in `factors` | 200 `{webauthn_session,options,expires_at}` for `navigator.credentials.get`; rate limited |
| `POST /passkeys/login/begin` | `environment_id` | 200 `{webauthn_session,options,expires_at}`; 403 `METHOD_NOT_ALLOWED` when passkeys are off; rate limited |
| `POST /passkeys/login/finish` | boundary + `webauthn_session`, `credential` | 200 token pair (`amr` `hwk`,`user`,`mfa`; no second factor); 401 unknown or non-passkey credential, replay, cloned key; 403 `SSO_REQUIRED`/`METHOD_NOT_ALLOWED`; rate limited |
| `POST /refresh` | original boundary + `refresh_token` | 200 replacement token pair |
| `POST /machine-token` | Bearer `ik_svc_…`; no body needed | 200 access token, no user refresh |
| `POST /token-exchange` | Bearer `ik_pat_…` ([personal access token](../../guides/machine-users.md)); no body | 200 access token backed by the token's session, no refresh; 401 revoked/expired/inactive |
| `POST /challenges` | `environment_id`, `email` or `login` (email or [username](../../guides/user-profiles.md#usernames); the code goes to the account's email), `purpose`, optional `locale` (email language, e.g. `es`; used when IAMKit writes the email) | 202 challenge response |
| `POST /challenges/verify` | `environment_id`, `challenge_id`, `code`, `purpose`; full boundary for login; `password` for reset | Login: 200 pair; reset/verification: 204 |
| `POST /discover` | `environment_id`, `email` | 200 `{method:"sso"\|"password",organization_id?,connection_id?,required,provider?}`; by email domain only; `provider:"ldap"` means post the password to `/federation/ldap/login` instead of redirecting; rate limited |
| `POST /signup` | `environment_id`, `email`, `name`, `password?`, `locale?`, `accept_terms?` | 202 challenge response, the same for existing accounts; 400 `TERMS_REQUIRED` when the policy's `require_terms` is set and `accept_terms` is not true; 403 `SIGNUP_DISABLED`/`SSO_REQUIRED`; rate limited. See [sign-up](../../guides/signup-and-onboarding.md#self-service-sign-up) |
| `POST /signup/verify` | `environment_id`, `challenge_id`, `code` | 201 `{user_id,organization_id,email}`; no session; 409 `ACCOUNT_EXISTS`; rate limited |
| `GET /org-admin/:environment` | — | 200 `{client_id,environment_id,url}` of the [organization admin portal](../../guides/organization-administration.md#hosted-portal); 404 when it is off; `Cache-Control: no-store`; rate limited |
| `GET /authorize/:ticket` | the ticket's binding cookie (`__Host-iamkit-authorization`); `Accept-Language` | 200 the [ticket description](../../guides/custom-sign-in-ui.md#read-the-ticket) for a custom sign-in UI (`client_id`, boundary, `organization_id?`, `login_hint?`, `locale`, `languages`, `methods`, `connections`, `branding`, `texts`); 401 without the cookie or for an unknown/used ticket; 403 for a `hosted_login` client; `Cache-Control: no-store`; 60/min per IP |
| `POST /invitations/preview` | `token` | 200 [invitation preview](#invitations); 401 unknown, used, revoked or expired; rate limited |
| `POST /invitations/accept` | `token`, `name?`, `password?` | 200 `{user_id,organization_id,email,sso_required,created}`; no session; rate limited |
| `POST /federation/start` | boundary + `connection_id`; organization connections need their own `organization_id`; optional `return_to` + `code_challenge` (S256) for a [custom sign-in UI](../../guides/federation.md#returning-to-a-custom-sign-in-ui) | 200 `{authorization_url}` + binding cookie; 400 when `return_to` is not on an `allowed_origins` origin of an OAuth client of the application; 403 `METHOD_NOT_ALLOWED` for an environment connection when the sign-in policy or the organization turns off `allow_social` (checked again at the callback) |
| `GET /federation/callback` | `code`, `state` query + binding cookie | 200 token pair; with `return_to`: 303 there with `federation_result` (or `error`, `error_description`) |
| `POST /federation/result` | `federation_result`, `code_verifier` (30/min per IP) | Like `POST /login`; 401 for an unknown, expired, spent handle or a wrong verifier (which spends it) |
| `POST /federation/saml/acs` | form `SAMLResponse`, `RelayState` (the SAML assertion consumer service, HTTP-POST binding; 30/min per IP) | 303 to `/federation/callback?code=ik_saml_…&state=…`; 401 for an unknown/expired RelayState |
| `POST /federation/ldap/login` | boundary (with the connection's `organization_id`) + `connection_id`, `email`, `password` ([LDAP](../../guides/ldap.md); 10/min per IP) | Like `POST /login`: 200 token pair or an [MFA step](#multi-factor); 401 for a wrong password, an unknown or ambiguous user; 502 when the directory cannot be reached |
| `GET /federation/saml/:environment/:connection/metadata` | — (public, 60/min per IP) | 200 SP metadata XML (`application/samlmetadata+xml`); 404 for a non-SAML or inactive connection |
| `POST /introspect` | Bearer access token; `environment_id`, `audience` | 200 `{active:false}` or `{active:true,claims:{…}}` |
| `POST /logout` | Bearer user token; `environment_id`, `audience` | 204 |
| `GET /me` | Bearer user token; query `environment_id`, `audience` | 200 profile (`id,email,name,username,avatar_url,email_verified,phone,phone_verified,…`) |
| `PATCH /me` | Bearer user token; `environment_id`, `audience`, and `name` and/or `avatar_url` (https, `""` removes) | 204 |
| `POST /me/phone` | Bearer user token (human, not impersonated, signed in recently); `environment_id`, `audience`, `phone` (E.164, spaces allowed) | 202 `{destination,expires_at}`: a code texted to that number; 403 `REAUTHENTICATION_REQUIRED`, 429 `CODE_COOLDOWN`/`CODE_LIMIT`, 502 without an SMS provider |
| `POST /me/phone/verify` | Same token; `environment_id`, `audience`, `code` | 204: the number becomes the verified `phone`; 422 `INVALID_CODE` (five wrong codes discard it) |
| `DELETE /me/phone` | Same token; query `environment_id`, `audience` | 204: phone cleared |
| `GET /me/profile` | Bearer user token (not machine or impersonated); query `environment_id`, `audience` | 200 `{profile}`: the attributes the [user schema](../../guides/user-profiles.md#self-service) marks `x-iamkit-self` |
| `PATCH /me/profile` | Same token; `environment_id`, `audience`, `profile` (merge patch of `x-iamkit-self: write` attributes) | 200 `{profile}`; 403 for any other attribute or without a schema |
| `GET /organizations` | Bearer user token; query `environment_id`, `audience` | 200 organization array |
| `POST /memberships` | Bearer user token; `environment_id`, `audience`, `user_id` | 201; requires `iam:members:write` |
| `GET /me/factors` | Bearer user token; query `environment_id`, `audience` | 200 `{factors,recovery_codes_remaining}` |
| `POST /me/factors/totp` | Bearer user token; `environment_id`, `audience` | 201 `{factor_id,secret,otpauth_uri}` |
| `POST /me/factors/email` | Bearer user token; `environment_id`, `audience` | 202 `{factor,destination,expires_at}` |
| `POST /me/factors/sms` | Bearer user token; `environment_id`, `audience`, `phone` | 202 `{factor,destination,expires_at}` |
| `POST /me/factors/{totp,email,sms}/confirm` | Bearer user token; `environment_id`, `audience`, `code` | 200 `{recovery_codes}` |
| `POST /me/factors/{email,sms}/challenge` | Bearer user token; `environment_id`, `audience` | 202 `{factor,destination,expires_at}` |
| `DELETE /me/factors/{totp,email,sms}` | Bearer user token; `environment_id`, `audience`, `code` | 204 |
| `POST /me/factors/recovery-codes` | Bearer user token; `environment_id`, `audience`, `code` (or a key assertion) | 200 `{recovery_codes}` |
| `POST /me/factors/webauthn` | Bearer user token; `environment_id`, `audience`, `name`, `passkey?` | 201 `{webauthn_session,options,expires_at}` for `navigator.credentials.create` |
| `POST /me/factors/webauthn/confirm` | Bearer user token; `environment_id`, `audience`, `webauthn_session`, `credential` | 201 `{factor,recovery_codes?}` |
| `POST /me/factors/webauthn/challenge` | Bearer user token; `environment_id`, `audience` | 200 `{webauthn_session,options,expires_at}` (possession proof) |
| `PATCH /me/factors/webauthn/:id` | Bearer user token; `environment_id`, `audience`, `name` | 200 factor |
| `DELETE /me/factors/webauthn/:id` | Bearer user token; `environment_id`, `audience`, `code` or `webauthn_session` + `credential` | 204 |

The membership endpoint uses the authenticated user's organization context; it
is not a sign-up. Impersonated tokens cannot update self-service profiles.
Encode query values using `URLSearchParams`/`url.Values`, especially audiences.

Token pair:

```json
{"access_token":"SECRET_JWT","refresh_token":"SECRET_REFRESH","token_type":"Bearer","expires_in":900}
```

Challenge response:

```json
{"challenge_id":"UUID","message":"If eligible, a code will be sent.","expires_in":300}
```

Purpose is exactly `login`, `password_reset` or `email_verification`. Unknown or
ineligible users get a generic challenge result to avoid exposing registration
state; 202 does not prove delivery. Login requires OTP enabled, reset requires an
existing password. Codes are 8 characters, expire in 5 minutes and allow 5 failed
attempts. Delivery must be configured before issuing challenges.

Profile endpoints require application-purpose access and current valid state.
Logout revokes the session; offline JWT consumers still need expiry or online
checking. Refresh rotates the token: never reuse the predecessor after success.

Federation is browser-cookie-bound over HTTPS. The callback returns JSON tokens,
not a hosted application redirect. See [federation](../../guides/federation.md).
Errors follow [the JSON contract](../errors-and-pagination.md), except protocol
families documented separately.

Source: `internal/server/server.go`,
`internal/iam/authentication/adapters/authhttp/{handler,tokens}.go`.

## Multi-factor

Password login, email-code login and the SSO callback return, instead of a
token pair, `{mfa_required:true,mfa_token:"ik_mfa_…",factors,enrollment_required,expires_in}`
when the user has a usable factor or the organization requires one. No
session exists until `/mfa/verify` succeeds (5 minutes, 5 wrong codes).
Email and SMS factors need `/mfa/challenge` first to send the code; security
keys need `/mfa/webauthn` for the assertion options. WebAuthn `options` are
the standard `PublicKeyCredential{Creation,Request}Options` as JSON
(base64url binary fields, no `publicKey` wrapper); `credential` is the
browser's `PublicKeyCredential.toJSON()`. Passkeys sign in without a prior
step (`/passkeys/login/*`). See [security keys and passkeys](../../guides/mfa.md#security-keys-and-passkeys).
Self-service factor endpoints refuse impersonated tokens (403). See the
[MFA guide](../../guides/mfa.md).

## Invitations

Invitation tokens (`ik_inv_…`) travel in the JSON body, never in the URL, so
they stay out of request logs. Your invitation page reads `token` from its own
query string and posts it.

Preview returns `{organization_id,organization_name,email,expires_at,status,password_required,sso_required}`
with the email masked (`b***@example.com`). An invalid, used, revoked or expired
token returns the same 401, so tokens cannot be probed.

Accept rules:

- **New account:** `password` (following the environment's
  [password policy](../../guides/password-policy.md); 400 `PASSWORD_POLICY`
  otherwise) is required, unless the
  organization enforces SSO for the email's verified domain; then it is
  rejected (400) and the person signs in through SSO, which links by email.
- **Existing account:** `password` is rejected (400); accepting never changes
  credentials. An inactive account returns 422; an inactive membership is
  reactivated.
- The email is marked verified (the invitee proved control of the mailbox),
  the membership, invited roles and still-existing operator-managed groups are
  added in one transaction, and the token is consumed. Roles or groups deleted
  since the invitation are skipped.
- Accept does not sign the person in; call `/login` (or start SSO when
  `sso_required`) afterwards. Inactive organizations return 422.
