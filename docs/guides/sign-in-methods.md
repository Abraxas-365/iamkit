# Sign-in methods

Each environment decides which ways users can sign in. Without a saved policy
everything is allowed and no second factor is required — IAMKit's behaviour
before policies existed.

Manage it in the console (**Sign-in → Sign-in methods**), with the
[management API](../reference/api/management.md) (`GET|PUT|DELETE
/environments/:environment/sign-in-policy`), the CLI
(`iam sign-in-policy get|set|delete`) or the Go SDK (`iamclient`
`SignInPolicy`, `SetSignInPolicy`, `DeleteSignInPolicy`).

| Field | Effect when `false` |
| --- | --- |
| `allow_password` | Password sign-in refused (headless and hosted) |
| `allow_password_reset` | "Forgot password" hidden and refused; needs `allow_password` |
| `allow_email_code` | Email-code sign-in refused |
| `allow_social` | [Environment connections](social-login.md) (Google, Microsoft…) refused |
| `allow_passkey` | [Passkey](mfa.md#passkeys) sign-in refused (it also needs `webauthn` in `allowed_factors`); omitted on `PUT` keeps the current value |

| Field | Effect when `true` |
| --- | --- |
| `mfa_required` | A [second factor](mfa.md) in every organization, on top of the organization's own `mfa_required` |
| `mfa_for_federated` | The same after social and SSO sign-ins |
| `allow_signup` | [Self-service sign-up](signup-and-onboarding.md#self-service-sign-up) into `signup_organization_id` (required) and optionally `signup_group_id` |
| `require_terms` | Sign-up needs `accept_terms` and records `terms_accepted_at` on the user ([terms](signup-and-onboarding.md#terms-acceptance)); omitted on `PUT` keeps the current value |

`allowed_factors` lists the [second-factor kinds](mfa.md#allowed-factors)
users may enroll and sign in with (`totp`, `email`, `sms`, `webauthn`; default
`["totp","webauthn"]`). Organizations narrow it with their own
`allowed_factors`.

`PUT` replaces the whole policy (audited `sign_in_policy.update`), except
that an omitted `allowed_factors` keeps its current value; `DELETE`
restores the default (`sign_in_policy.delete`). `GET` returns `custom: false`
for the default. Turning every method off is valid: only organization SSO
connections remain.

## Three layers

The effective methods are the intersection of three layers; each can only
narrow the one above:

1. **Environment** — this policy.
2. **Organization** — `allow_password`, `allow_email_code`, `allow_social`,
   `allow_passkey` on
   the organization (`PATCH /organizations/:id`, console organization page,
   `iam organizations update --allow-password=false`, SDK
   `SetOrganizationMethods`). An organization cannot turn on a method the
   environment turns off.
3. **Application** — the hosted pages' per-client [sign-in
   options](hosted-login.md) hide methods for one application.

Organization single sign-on is not governed by these switches; it follows its
connection's enforcement.

## Refusals

A refused method answers 403 `METHOD_NOT_ALLOWED`; a refused reset 403
`PASSWORD_RESET_DISABLED`. Both are checked **before** the account is looked
up, so the answer is the same for known and unknown emails and no failed
attempt is counted.

Users can belong to several organizations. When a sign-in names no
organization (the hosted chooser), organizations that refuse the method are
left out of the choice; when none allows it the sign-in is refused. The chosen
organization is checked again when the session is issued.

## Unknown accounts

IAMKit never reveals whether an account exists: wrong passwords, unknown
emails and locked accounts answer the same 401, and challenges (codes, resets)
and sign-ups answer 202 either way. There is no switch to reveal it.

Source: `internal/iam/authentication/signin.go`, `authsvc/signin.go`,
`adapters/authhttp/signin.go`.
