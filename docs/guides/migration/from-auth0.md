# Migrate from Auth0

Import Auth0 users with their bcrypt passwords. General behaviour, limits and
safety are in [importing users](importing-users.md).

## What moves and what does not

| Auth0 | IAMKit |
| --- | --- |
| `user_id` | `external_id` |
| `email`, `email_verified`, `username` | same fields |
| `name`, else `given_name` + `family_name`, else `nickname` | `name` |
| `passwordHash` (bcrypt) | `password_hash` |
| `custom_password_hash` (`algorithm`, `hash.value`) | `password_hash` when the value is already an argon2 or pbkdf2 string in the PHC format; see the [formats](importing-users.md#password-hash-formats) |
| `user_metadata`, `app_metadata` | metadata keys `auth0_user_metadata` and `auth0_app_metadata`, only with `--metadata` |

**Not migrated:** MFA factors (users enroll again,
[MFA](../sign-in/mfa.md)), social identities, sessions and refresh tokens (users
sign in once more), Auth0 roles and organizations. Create those in IAMKit first
and point the import at them with `--home-organization`.

## Export

1. **Users.** Use Auth0's bulk user export (the *User Import / Export* extension or
   the Management API `POST /api/v2/jobs/users-exports`) and download the result
   as **JSON Lines** (one user per line).
2. **Password hashes.** Auth0 does not include hashes in that export. Open a
   support ticket asking for the password hash export of the tenant; Auth0 sends
   a JSON Lines file with `passwordHash` per user. Merge the two files by
   `email` or `user_id` into one JSONL (for example with `jq`) so that each line
   has both the profile and `passwordHash`. Tenants without the hash file can
   still import and use [email codes](../sign-in/email-otp.md) or a reset.

## Import

```sh
iam users import auth0-users.jsonl --from auth0 --home-organization ORG_UUID --dry-run
iam users import auth0-users.jsonl --from auth0 --home-organization ORG_UUID \
  --skip-existing --errors failed.jsonl
```

Add `--metadata` to keep Auth0's metadata under the two `auth0_*` keys (metadata
limits apply: [user profiles](../organizations/user-profiles.md#metadata)).
Users imported from Auth0's bcrypt keep their hash until they sign in; bcrypt
hashes of cost 12 or above stay as they are, lower ones are rehashed.

## Social users

Users who signed in with Google, GitHub and other providers have no password.
Import them as passwordless users and set up a
[federation connection](../enterprise/federation.md) for the provider. With
`link_email` on, the first provider sign-in is linked to the imported user whose
email the provider verified ([linking members by email](../enterprise/federation.md#linking-members-by-email),
[social login](../enterprise/social-login.md#first-sign-in-sign-up-and-email-linking)),
so they keep their account, `external_id` and memberships. The provider must
verify the email, otherwise the sign-in is refused.

## Cut-over

Run the import ahead of time, repeat it with `--skip-existing` just before you
switch the application's sign-in to IAMKit to catch new users, then verify as
described in [importing users](importing-users.md#verify).
