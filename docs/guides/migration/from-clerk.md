# Migrate from Clerk

Import Clerk users from the dashboard's CSV export. General behaviour is in
[importing users](importing-users.md).

## Export

In the Clerk dashboard, open **Users** and export all users as CSV. The export
needs the `password_digest` and `password_hasher` columns; users without a digest
import without a password.

| Clerk column | IAMKit |
| --- | --- |
| `id` | `external_id` |
| `first_name`, `last_name` | `name` |
| `username` | `username` |
| `primary_email_address` | `email` |
| `password_digest`, `password_hasher` | `password_hash` |

The `password_hasher` column says how the digest was made. The CLI converts these
values, matching the [accepted formats](importing-users.md#password-hash-formats):
`bcrypt`, `argon2id`, `argon2i` and `pbkdf2_sha256` (Django style). A row whose
hasher is not supported (for example md5 or sha1 variants) is **skipped with the
reason** instead of importing a hash IAMKit cannot verify.

## Import

```sh
iam users import clerk-users.csv --from clerk --home-organization ORG_UUID --dry-run
iam users import clerk-users.csv --from clerk --home-organization ORG_UUID \
  --skip-existing --errors failed.jsonl
```

Pass `--passwordless-unsupported` to import users whose hasher is unsupported
without a password instead of skipping them (check the
[CLI reference](../../reference/cli.md) for the exact behaviour). They can then use
[email codes](../sign-in/email-otp.md) or a
[password reset](../sign-in/passwords.md#forgot-password).

Social identities and MFA are not migrated: create a
[federation connection](../enterprise/federation.md) with `link_email` for each
provider ([social login](../enterprise/social-login.md#first-sign-in-sign-up-and-email-linking))
and let users enroll [MFA](../sign-in/mfa.md) again. Clerk sessions are not
carried over.
