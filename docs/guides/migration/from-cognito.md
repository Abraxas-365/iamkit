# Migrate from Amazon Cognito

Cognito does not let you export password hashes, so users are imported
**without passwords**. General behaviour is in
[importing users](importing-users.md).

## Export

```sh
aws cognito-idp list-users --user-pool-id POOL_ID --output json > cognito.json
```

| Cognito | IAMKit |
| --- | --- |
| `Users[].Username` (or the `sub` attribute) | `external_id` |
| attribute `email`, `email_verified` | `email`, `email_verified` |
| attribute `name` | `name` |

## Import

```sh
iam users import cognito.json --from cognito --home-organization ORG_UUID --dry-run
iam users import cognito.json --from cognito --home-organization ORG_UUID \
  --skip-existing --errors failed.jsonl
```

Every IAMKit user needs an email, so Cognito users without an `email` attribute
cannot be imported. Social and SAML identities and MFA are not migrated: for providers,
create a [federation connection](../enterprise/federation.md) with `link_email`
so the first provider sign-in joins the imported user.

## Getting users back in

Imported users have no password. Choose one of:

- **Email codes.** Turn on `otp_enabled` for the users and let them sign in with a
  one-time code ([email OTP](../sign-in/email-otp.md); email delivery must be
  configured). The converter maps only the fields in the table above: set
  `otp_enabled` afterwards with `PATCH …/users/:id`, or build the rows yourself and
  import them with `--from iamkit` including `"otp_enabled": true`.
- **Password reset.** Send users through [forgot password](../sign-in/passwords.md#forgot-password)
  (the flow needs an existing password, so it does not give a passwordless user
  their first one; use email codes for that).
- **Forced change.** `iam users require-password-change` applies to users who have a
  password ([password policy](../sign-in/password-policy.md#requiring-a-change-for-one-user));
  passwordless users answer 422.

## Lazy migration is not provided

IAMKit does not verify the password against Cognito at the user's first sign-in
and copy it over, so there is no way to carry Cognito passwords across without
asking the users for something once: an email code or a new password. Plan the
announcement and the cut-over accordingly.
