# CLI reference

The container entrypoint is `iamkit`. The CLI connects to `DATABASE_URL` before
handling commands; a reachable configured database is required even for command
parsing. Errors go to stderr and exit nonzero.

| Command | Effect |
| --- | --- |
| `iamkit` | Apply embedded migrations, optionally auto-bootstrap, start HTTP server |
| `iamkit migrate` | Apply migrations and exit |
| `iamkit bootstrap --email EMAIL --workspace NAME --output PATH` | Initialize workspace/owner and write credential JSON |
| `iamkit recover-owner --email EMAIL --workspace UUID --output PATH` | Recover owner authority for an existing workspace |

The command line is checked before any connection to the database: `--email`,
`--workspace` and `--output` are all required, the email must be valid, and
`recover-owner` needs a workspace UUID. A mistake exits 1 naming the flag; an
unknown flag prints the usage and exits 2; `--help` exits 0 without a database.

`--workspace` is a **name** for bootstrap and a **UUID** for recovery. `--output`
is mandatory and must not exist; its parent directory must be writable. Files
are exclusively created with mode 0600 and contain `management_key`. Credentials
expire in 24h. Protect the file and verify it through `GET /management/v1/me` with
`X-API-Key`. Never use a publicly mounted directory or overwrite an old file.

Recovery requires an existing active owner and revokes their workspace management
keys and console sessions, then clears their password. Warn affected automation
consumers and re-establish the password for console login. Other operators'
credentials are unaffected.

The explicit CLI does not set an operator password and ignores
`IAMKIT_BOOTSTRAP_PASSWORD` (it warns when that variable is set); set it through management
`POST /password` after authenticating. Automatic bootstrap instead optionally
uses `IAMKIT_BOOTSTRAP_PASSWORD` as a temporary password (replaced at the
first console sign-in) and currently logs its management key. Omit
automatic bootstrap when credential logging is unacceptable. A
`IAMKIT_BOOTSTRAP_PASSWORD` outside 12-72 characters stops start-up before the
workspace is created.

Normal shutdown handles SIGINT/SIGTERM and allows 10 seconds for HTTP shutdown.
Do not use process restarts as migration rollback. See
[database operations](../operations/database-and-migrations.md) and
[incident response](../operations/incident-response.md).

## `iam users import`

`iam` is the management CLI (separate from the `iamkit` server entrypoint above;
configure it with `iam configure`, `IAMKIT_URL`/`IAMKIT_KEY`/`IAMKIT_ENVIRONMENT`
or `--url`/`--key`/`--environment`). `iam users import FILE` moves users from
another system into the environment through `POST …/users/import` without
asking anyone to reset a password. `FILE` can be `-` for stdin. See the
migration guide [Importing users](../guides/migration/importing-users.md) for end-to-end walkthroughs.

Password hashes in a supported format (bcrypt, argon2i/argon2id, pbkdf2 in PHC,
passlib or Django form, Firebase scrypt) are stored as they are and verified at
sign-in; IAMKit replaces them with its own bcrypt at the user's next successful
password sign-in. Users without a hash are created without a password.

| Flag | Effect |
| --- | --- |
| `--from SOURCE` | `iamkit` (default), `auth0`, `firebase`, `clerk`, `cognito` |
| `--home-organization ID` | Set `home_organization_id` on every user |
| `--dry-run` | Convert and validate locally (email, name, recognised hash prefix), print the counts, make no API calls |
| `--skip-existing` | Rows the server answers with `CONFLICT` (email, username or external ID already taken) count as skipped, not failed |
| `--errors FILE` | Write failed and skipped rows as JSON Lines `{row, external_id, email, code, message}` |
| `--metadata` | `auth0`: keep `user_metadata`/`app_metadata` as metadata keys `auth0_user_metadata`/`auth0_app_metadata` |
| `--passwordless-unsupported` | `auth0`/`clerk`: import users whose hash format is not supported without a password instead of skipping them |
| `--hash-key`, `--salt-separator`, `--rounds`, `--mem-cost` | `firebase`: the project's scrypt parameters (Firebase console › Authentication › Users › Password hash parameters); required when any user has a password. The signer key can come from `IAMKIT_FIREBASE_HASH_KEY` instead, keeping it out of argv |

Sources:

| `--from` | Input | Mapping |
| --- | --- | --- |
| `iamkit` | JSON array or JSON Lines of the create shape: `email`, `name`, `username`, `external_id`, `password_hash`, `email_verified`, `metadata`, `home_organization_id`, `otp_enabled`, `avatar_url` | Passed through; unknown fields are refused |
| `auth0` | Bulk export, JSON Lines | `user_id` → `external_id`; name from `name`, else `given_name` + `family_name`, else `nickname`, else the email local part; `passwordHash` or `custom_password_hash.hash.value` when already in a supported format; users without an email are skipped |
| `firebase` | `firebase auth:export users.json --format=json` | `localId` → `external_id`, `displayName` → name; `passwordHash` and `salt` become `$firebase-scrypt$m=<mem-cost>,r=<rounds>$<salt>$<hash>$<salt-separator>$<hash-key>` (URL-safe or unpadded base64 is normalised); users without `passwordHash` import without a password |
| `clerk` | CSV export; headers are matched case-insensitively, extra columns ignored | `id`, `first_name` + `last_name`, `username`, `primary_email_address`; `password_digest` for `password_hasher` `bcrypt`, `argon2id`, `argon2i` and `pbkdf2_sha256` (Django format); other hashers are skipped |
| `cognito` | `aws cognito-idp list-users` JSON (several pages may be concatenated) | `sub` (else `Username`) → `external_id`, `email`, `email_verified`, `name` or `given_name` + `family_name`; no passwords |

```sh
iam users import users.jsonl
iam users import auth0-export.jsonl --from auth0 --metadata --skip-existing --errors failed.jsonl
IAMKIT_FIREBASE_HASH_KEY="$FB_SIGNER_KEY" iam users import users.json --from firebase \
  --salt-separator "$FB_SALT_SEPARATOR" --rounds 8 --mem-cost 14
iam users import clerk.csv --from clerk --home-organization ORG_ID --dry-run
aws cognito-idp list-users --user-pool-id POOL > cognito.json
iam users import cognito.json --from cognito
```

Users are sent in requests of at most 100 rows and 60 KiB. `429` and `503`
answers are retried up to 5 times, waiting `Retry-After` seconds or else 1, 2,
4 and 8 seconds. Rows are independent: one failing never stops the others. The
`row` in `--errors` is the position in the input: the line number for JSON
Lines and CSV (the header is line 1), and the 1-based index for JSON arrays
and the Firebase and Cognito lists. The last line printed is
`created N, skipped N, failed N`; the exit code is 1 when any row failed.
Skipped rows (no email, unsupported hash, existing with `--skip-existing`) do
not change the exit code. Password hashes are never printed or written to the
errors file.

## Bot protection and risk signals

Per-environment [CAPTCHA](../guides/sign-in/bot-protection.md) and
[risk signals](../guides/sign-in/risk-signals.md), with the management key the
CLI is configured with. The CAPTCHA secret never goes in an argument: it is read
from stdin (`--secret-stdin`) or `IAMKIT_CAPTCHA_SECRET`; omitted, the stored
secret is kept (required the first time).

```sh
IAMKIT_CAPTCHA_SECRET="$SECRET" iam captcha set --provider turnstile --site-key "$SITE_KEY"
printf %s "$SECRET" | iam captcha set --provider hcaptcha --site-key "$SITE_KEY" --secret-stdin --headless=false
iam captcha get               # never shows the secret
iam captcha test              # checks the secret with the provider (5 a minute)
iam captcha delete

iam risk status               # GeoIP source, captcha and risk_signals flags
iam risk policy get
iam risk policy set --ip-velocity block --new-device challenge --user-failures-per-hour 5
iam risk policy delete        # every detection off again
iam risk restrictions add --kind ip --value 203.0.113.0/24 --action deny
iam risk restrictions add --kind email_domain --value acme.com --action allow --note "staff"
iam risk restrictions list --kind country
iam risk restrictions remove RESTRICTION_ID
iam risk attempts list --outcome blocked --limit 20
iam risk attempts get ATTEMPT_ID
iam users devices USER_ID
```

`iam captcha set` takes `--provider` (`turnstile` or `hcaptcha`), `--site-key`,
`--hosted` and `--headless` (both default true) and a repeatable `--hostname`.
`iam risk policy set` changes only the flags you pass: one flag per detection
(`--ip-velocity`, `--user-brute-force`, `--impossible-travel`, `--new-device`,
`--stale-account`, each taking that detection's actions), the thresholds
`--ip-failures-per-hour`, `--ip-distinct-logins-per-hour`,
`--user-failures-per-hour`, `--stale-after-days` and `--travel-speed-kmh`,
`--notify-user` and `--block-if-unverifiable`. `iam risk restrictions add` needs
`--kind`, `--value` and `--action` (`allow` or `deny`) and takes `--note`.
`iam risk attempts list` filters with `--user`, `--ip`, `--outcome`,
`--detection`, `--country` and pages with `--limit` and `--before`; add
`-o json` to any of them for raw JSON.

## API keys

[API keys](../guides/machines/api-keys.md) of every owner kind, with the
management key the CLI is configured with. The value of a new key is printed
once, as `ik_key_…`.

```sh
iam api-keys policy get
iam api-keys policy set --user-keys --organization-keys --max-ttl-days 365 --max-per-user 10 --max-per-organization 50
iam resources api-key-permissions set RESOURCE_ID --user invoices:read --organization invoices:read,invoices:write
iam resources api-key-permissions get RESOURCE_ID

iam api-keys create --organization ORG_ID --resource RESOURCE_ID --name "warehouse sync" \
  --permission invoices:read --expires-in 2160h      # organization key; --expires-in never or omitted = no expiry
iam api-keys list --owner-type organization --organization ORG_ID --resource RESOURCE_ID
iam api-keys get KEY_ID
iam api-keys revoke KEY_ID

iam machine-users api-keys create USER_ID --org ORG_ID --app APP_ID \
  --resource RESOURCE_ID --name "nightly export" --expires-in 720h
iam machine-users api-keys list USER_ID                # --limit, --offset, --search
iam machine-users api-keys revoke USER_ID KEY_ID
```

`iam api-keys list` filters with `--owner-type` (`user`, `organization`,
`machine`), `--organization`, `--user`, `--resource`, `--state` (`active`,
`revoked`, `expired`) and `--search` (name), and pages with `--limit` and
`--offset`. `--expires-in` takes `1h`–`8760h` or `never`;
omitted means `never`, unless the policy sets a maximum. `iam api-keys create`
makes organization keys; user keys are made by their owners in your application
and machine keys with `iam machine-users api-keys create` (`--permission`
omitted = everything the machine user holds). `iam api-keys policy set` changes
only the flags you pass: `--user-keys=false`, `--organization-keys=false`,
`--max-ttl-days N` or `--no-max-ttl`, `--max-per-user N` and
`--max-per-organization N`. `iam resources api-key-permissions set` replaces the
list of each of `--user` and `--organization` you pass (empty clears) and keeps
the other. `--permission`, `--user` and `--organization` repeat or take commas.
