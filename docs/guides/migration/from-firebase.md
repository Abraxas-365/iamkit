# Migrate from Firebase Authentication

Import Firebase users with their scrypt passwords. General behaviour is in
[importing users](importing-users.md).

## Export

1. Export the users with the Firebase CLI:

   ```sh
   firebase auth:export users.json --format=json --project PROJECT_ID
   ```

   The file holds `users[]` with `localId`, `email`, `emailVerified`,
   `displayName`, `passwordHash` and `salt`.
2. Read the project's **password hash parameters** in the Firebase console
   (Authentication › Users › menu › *Password hash parameters*): `base64_signer_key`,
   `base64_salt_separator`, `rounds` and `mem_cost`.

| Firebase | IAMKit |
| --- | --- |
| `localId` | `external_id` |
| `email`, `emailVerified`, `displayName` | `email`, `email_verified`, `name` |
| `passwordHash`, `salt` + the console parameters | `password_hash` as `$firebase-scrypt$…` |

Users without `passwordHash` (social or phone sign-in) import without a password.
Their provider identities are not migrated: use a
[federation connection](../enterprise/federation.md) with `link_email`
([social login](../enterprise/social-login.md#first-sign-in-sign-up-and-email-linking))
so they keep their account.

## Import

```sh
export IAMKIT_FIREBASE_HASH_KEY="$FIREBASE_SIGNER_KEY" # kept out of argv
iam users import users.json --from firebase \
  --salt-separator "$FIREBASE_SALT_SEPARATOR" \
  --rounds 8 --mem-cost 14 \
  --home-organization ORG_UUID --dry-run
```

The signer key (`--hash-key`, or the `IAMKIT_FIREBASE_HASH_KEY` environment
variable, which keeps it out of `ps` and shell history), `--salt-separator`,
`--rounds` and `--mem-cost` are required for this
source; the key and the separator are the console's base64 values. The CLI builds
`$firebase-scrypt$m=<mem_cost>,r=<rounds>$<salt>$<hash>$<salt_separator>$<signer_key>`
for each user ([formats](importing-users.md#password-hash-formats)): `mem_cost`
must be 1–15, `rounds` 1–16, and the work (128 · rounds · 2^mem_cost bytes) at most
64 MiB, or the rows are refused. Remove `--dry-run` to import; add
`--skip-existing --errors failed.jsonl` for re-runs.

## Protect the signer key

The signer key is part of **every imported hash** until the user's next
successful password sign-in replaces it with bcrypt. Anyone who reads the
database rows or the import payload and holds a user's hash can test passwords
offline using the key they find inside it. So:

- keep the export, the key and your shell history private (read the key from a
  secret store instead of typing it);
- delete the export file after the import;
- encourage users to sign in soon, or require a new password
  (`iam users require-password-change`) for accounts you do not expect to return.

Firebase ID tokens and refresh tokens are not accepted by IAMKit: users sign in
again after the switch.
