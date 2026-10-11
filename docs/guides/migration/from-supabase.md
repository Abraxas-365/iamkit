# Migrate from Supabase Auth

Supabase stores bcrypt hashes in `auth.users.encrypted_password`, which IAMKit
verifies as they are. You export them with SQL into the IAMKit row format and import
that file. General behaviour is in [importing users](importing-users.md).

## Export

| Supabase (`auth.users`) | IAMKit |
| --- | --- |
| `id` | `external_id` |
| `email` | `email` |
| `encrypted_password` (bcrypt) | `password_hash` |
| `email_confirmed_at` (not null) | `email_verified` |
| `raw_user_meta_data` | `metadata` and `name` |

Run this with `psql` against the database (a read-only role is enough). It writes
one JSON object per line:

```sh
psql "$SUPABASE_DB_URL" -At -c "COPY (
  SELECT json_build_object(
    'external_id', id::text,
    'email', email,
    'name', coalesce(nullif(raw_user_meta_data->>'full_name', ''),
                     nullif(raw_user_meta_data->>'name', ''),
                     split_part(email, '@', 1)),
    'email_verified', email_confirmed_at IS NOT NULL,
    'password_hash', nullif(encrypted_password, ''),
    'metadata', jsonb_build_object('supabase_user_metadata', raw_user_meta_data)
  )
  FROM auth.users
  WHERE email IS NOT NULL AND deleted_at IS NULL
) TO STDOUT WITH (FORMAT csv, QUOTE E'\\x01', DELIMITER E'\\x02')" > supabase-users.jsonl
```

The CSV format with control characters as quote and delimiter keeps `COPY` from
escaping backslashes and quotes, so every line stays valid JSON.
`nullif(encrypted_password, '')` leaves the hash null for users without a password
(social or magic-link). Metadata keys must match `^[a-zA-Z0-9_.-]{1,64}$` and the
[metadata limits](../organizations/user-profiles.md#metadata) apply: drop `metadata`
from the query if `raw_user_meta_data` is large.

Add `'home_organization_id', 'ORG_UUID'` to the object, or pass
`--home-organization` below.

## Import

```sh
iam users import supabase-users.jsonl --from iamkit --home-organization ORG_UUID --dry-run
iam users import supabase-users.jsonl --from iamkit --home-organization ORG_UUID \
  --skip-existing --errors failed.jsonl
```

Supabase bcrypt hashes are usually cost 10: users sign in with their password and
the hash is replaced by cost 12 at that sign-in. Passwords longer than 72 bytes
cannot sign in ([notes](importing-users.md#password-hash-formats)).

Users who signed in with OAuth providers have no password: set up a
[federation connection](../enterprise/federation.md) with `link_email`
([social login](../enterprise/social-login.md#first-sign-in-sign-up-and-email-linking))
so the first provider sign-in joins the imported user. Supabase's MFA factors and
sessions are not migrated.
