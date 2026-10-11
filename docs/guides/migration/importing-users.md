# Importing users with their passwords

Move users from another identity provider, or from your own user table, into
IAMKit **without forcing a password reset**. Imported password hashes are
verified as they are, and replaced with IAMKit's own bcrypt hash at the user's
next successful password sign-in. Sources that cannot export hashes (Amazon
Cognito) import without passwords.

Per-source steps: [Auth0](from-auth0.md), [Firebase](from-firebase.md),
[Clerk](from-clerk.md), [Amazon Cognito](from-cognito.md) and
[Supabase](from-supabase.md). This page is what they share.

## When to use it

- You are replacing a hosted provider or a home-grown `users` table and want
  people to keep signing in with the password they have.
- You have a one-off or repeated bulk load of 100 users or more. For a handful
  of users, `POST …/users` is enough.

Importing creates **users only**. It adds no membership, role or grant: set
`home_organization_id` on each row (which also adds the membership), or pass
`--home-organization` to the CLI, then give access as usual (see
[first application](../../start/first-application.md)).

## Password hash formats

`password_hash` is one self-describing string; there is no separate type field.
IAMKit accepts these formats, with caps that are checked **at import and again at
every sign-in**. The caps keep the work of one sign-in to a few times that of a
bcrypt at cost 12, and memory-hard verifications (argon2, scrypt) run a few at
a time, so a crafted row cannot pin CPU or memory:

| Format | String | Accepted parameters | Replaced at sign-in |
| --- | --- | --- | --- |
| bcrypt | `$2a$`, `$2b$` or `$2y$` + cost + 53 characters | cost 4–13 | cost other than 12, or not `$2a$`/`$2b$` |
| argon2 | `$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>` (also `$argon2i$`), PHC base64 (standard alphabet, padding optional) | `m` ≤ 65536, `t` ≤ 10, `p` ≤ 8, `m`·`t` ≤ 262144, salt ≥ 8 bytes, hash 16–64 bytes, `v=19` only | always |
| pbkdf2 (PHC) | `$pbkdf2-sha1$i=<n>$<salt>$<hash>`, `$pbkdf2-sha256$…`, `$pbkdf2-sha512$…`, PHC base64 | `i` 1000–2,000,000, salt ≥ 8 bytes, hash 16 bytes up to the digest size (20, 32 or 64) | always |
| pbkdf2 (passlib) | `$pbkdf2-sha256$<n>$<ab64 salt>$<ab64 hash>` (also sha1/sha512; ab64 = base64 with `.` for `+`, no padding) | same as PHC | always |
| pbkdf2 (Django) | `pbkdf2_sha256$<n>$<salt text>$<base64 hash>` (also `pbkdf2_sha1`) | same; the salt is text without `$`, at least 8 characters | always |
| Firebase scrypt | `$firebase-scrypt$m=<mem_cost>,r=<rounds>$<salt>$<hash>$<salt_separator>$<signer_key>`, all standard base64 (padding optional) | `mem_cost` 1–15 (N = 2^m), `r` 1–16, 128·`r`·N ≤ 64 MiB | always |

Whitespace or line breaks anywhere in the string make it malformed.

Example strings (shortened, not real hashes):

```text
$2b$10$N9qo8uLOickgx2ZMRZoMye...
$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA
$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA
pbkdf2_sha256$600000$saltsalt$aGFzaGhhc2hoYXNoaGFzaA==
$firebase-scrypt$m=14,r=8$c2FsdA==$aGFzaA==$c2VwYXJhdG9y$c2lnbmVy
```

Anything else is refused with 400 `password_hash format is not supported`: md5,
sha1, unsalted sha\*, ssha, plain scrypt and bcrypt-sha256. A recognised format
with parameters above the caps answers 400 `password_hash parameters exceed the
allowed cost`, and a broken string 400 `password_hash is malformed`. For those
users, import without a password and use [email codes](../sign-in/email-otp.md)
or a reset.

Passwords longer than **72 bytes** cannot sign in: IAMKit's bcrypt only
considers 72 bytes (the same limit as for new passwords, see
[password policy](../sign-in/password-policy.md)). A user whose source allowed
longer passwords has to [reset](../sign-in/passwords.md#forgot-password) theirs.

The Firebase format embeds the project's **signer key** in every imported hash
until it is replaced by the rehash (below). Those hashes are only as strong as
that key, and anyone holding the import file and the stored rows can try
passwords offline. Treat the file and the database as secrets, and delete the
file when the import is done. See [Firebase](from-firebase.md).

## What happens at sign-in (rehash)

On the next **successful** password sign-in, a hash in any format other than
bcrypt, or a bcrypt hash with cost below 12, is replaced by a bcrypt hash of cost
12. This happens in the headless `POST /identity/v1/login` and on the hosted
pages. It is invisible to the user:

- other sessions stay open and the password expiry is not reset;
- no event is written (no `user.password_changed`), and the hash never appears in
  the change history;
- [MFA](../sign-in/mfa.md) is still required after it;
- a wrong password never rehashes; a bcrypt hash of cost 12 is not rewritten; a
  sign-in that is about to set a new password (expired or required change) does
  not rehash first;
- if the rehash fails, the sign-in still succeeds and the old hash stays for the
  next attempt.

Users who never sign in keep their imported hash. When a source's hashes are
weaker than you accept, ask the user to sign in, or require a new password with
`iam users require-password-change` (see
[password policy](../sign-in/password-policy.md#requiring-a-change-for-one-user)).

## Import API

Two routes, same body and response:

| Route | Authentication |
| --- | --- |
| `POST /management/v1/environments/:environment/users/import` | [Management](../../reference/api/management.md) key or operator |
| `POST /api/v1/environments/:environment/users/import` | Bearer token with `iam:users:write` and `iam:users:import` ([scoped IAM](../../reference/api/scoped-iam.md)), for example a service account |

```http
POST /management/v1/environments/ENV_UUID/users/import
X-API-Key: ik_mgmt_…
Content-Type: application/json

{"users":[
  {"name":"Ada Lovelace","email":"ada@example.com","email_verified":true,
   "external_id":"legacy-1001","home_organization_id":"ORG_UUID",
   "password_hash":"$2b$12$...","metadata":{"plan":"pro"}},
  {"name":"Grace Hopper","email":"grace@example.com","external_id":"legacy-1002"}
]}
```

Each row is a [user create](../../reference/api/users-and-organizations.md#users):
`name`, `email`, `username`, `external_id`, `home_organization_id`,
`otp_enabled`, `avatar_url` and these fields, which regular `POST …/users`
accepts too:

| Field | Meaning |
| --- | --- |
| `password_hash` | A hash in one of the [formats above](#password-hash-formats), stored as given (trimmed, at most 1024 characters). Exclusive with `password`; machine users cannot have one |
| `email_verified` | The email is already verified. Default `false`; machine users cannot set it |
| `metadata` | A JSON object, [limits as usual](../organizations/user-profiles.md#metadata) |

The [password policy](../sign-in/password-policy.md) and the breached-password
check do **not** apply to an imported hash: a hash cannot be inspected. Organization
administrators cannot set `password_hash` or `email_verified`; those fields are
operator-only.

The body holds 1 to 100 rows (an empty list or 101 rows is 400) and the server
accepts at most 64 KiB per request. The answer is 200 even when rows fail:

```json
{
  "results": [
    {"index": 0, "id": "USER_UUID"},
    {"index": 1, "error": {"code": "CONFLICT", "message": "email is taken"}}
  ],
  "created": 1,
  "failed": 1
}
```

Rows are independent: each has its own transaction, its own `users_max`
[quota](../platform/usage-limits.md) check and its own `request:user.create`
[action](../platform/actions.md), so one failure never rolls back the others and
a quota reached halfway fails the rows after it. A
duplicate email, username or external ID is that row's `CONFLICT`. Actions never
see `password_hash` (nor `password`). Failed rows are safe to resend after fixing
them. Results never echo a hash.

Each created user records `user.created` with `data.origin` `import` in the
[event log](../../reference/events.md). On `/api/v1` the call counts as one request
against `requests_per_minute`.

## CLI

`iam users import` converts the export of each source, batches it and calls the
import route. Connection settings are the same as for the other `iam` commands;
the full list of flags is in the [CLI reference](../../reference/cli.md).

```sh
iam users import users.jsonl --from iamkit --home-organization ORG_UUID
iam users import - --from auth0 < export.jsonl      # "-" reads standard input
```

| Flag | Effect |
| --- | --- |
| `--from iamkit\|auth0\|firebase\|clerk\|cognito` | Format of the file; `iamkit` (default) is a JSON array or JSON Lines of the rows above |
| `--hash-key`, `--salt-separator`, `--rounds`, `--mem-cost` | Firebase's password hash parameters ([Firebase](from-firebase.md)) |
| `--metadata` | Keep Auth0's `user_metadata` and `app_metadata` ([Auth0](from-auth0.md)) |
| `--passwordless-unsupported` | Clerk: see [Clerk](from-clerk.md) |
| `--dry-run` | Convert and check locally (the hash prefix is recognised, an email is present) and print the counts; makes no request |
| `--skip-existing` | Count `CONFLICT` rows as skipped instead of failed |
| `--errors FILE` | Write failed rows as JSON Lines `{index, external_id, email, code, message}` |
| `--home-organization ID` | Set `home_organization_id` on every row |

The CLI sends at most 100 rows and 60 KiB per request. On 429 or 503 it waits for
`Retry-After`, else backs off exponentially, and gives up after 5 tries. It prints
a summary such as `created 950, skipped 40, failed 10` and exits non-zero when any
row failed. It never prints a password hash. Do a `--dry-run` first.

## Safe re-runs

Set `external_id` on every row (the CLI maps it from the source's user ID) and
re-run with `--skip-existing`: rows already imported answer `CONFLICT` and are
counted as skipped, so an interrupted import or a second pass for late sign-ups
picks up where it stopped. This also covers a batch whose answer was lost: after
a timeout or network error the CLI reports the batch as failed (`REQUEST_FAILED`),
though the server may have created some of its rows, so re-run with
`--skip-existing`. Without an `external_id`, only email and username
detect a repeat. Fix the rows in the `--errors` file and import that file with
`--from iamkit`.

## Security notes

- **`email_verified` is trusted.** Rows you import with `email_verified: true`
  count as verified for [domain join](../organizations/domain-join.md): anyone
  whose email is on an organization's verified domain joins it at sign-in. Import
  `true` only where the source really verified the address, and keep
  `domain_join_group_id` low-privilege.
- Hash caps (above) bound the work one sign-in can cost. A password check never
  answers sooner than a bcrypt at cost 12, so response time does not tell an
  unknown account, a refused hash or a cheaper imported hash apart; refused
  hashes never match.
- Imported hashes are never logged, never in events, change history or action
  payloads, and never returned by the API.
- The import key is powerful: it can create users with chosen verified emails. Use
  a short-lived operator key or a service account holding only `iam:users:write`
  and `iam:users:import`. On `/api/v1`, `iam:users:import` is also what
  `password_hash` and `email_verified` on `POST /users` need, so give it to no
  other service account.
- Import files contain hashes and personal data. Keep them off shared disks and
  delete them afterwards.

## Verify

1. `--dry-run` reports the counts you expect.
2. After the import, compare: `GET …/users?home_organization_id=ORG_UUID` has the
   same total, and `GET …/events?type=user.created` shows `data.origin: "import"`
   for the created users.
3. Sign in as a few imported users with their old password (a disposable test
   account from the source works): it succeeds, and a wrong password fails. Check
   that the second sign-in still works: the stored hash is now bcrypt cost 12.
4. Check one user with `email_verified` and one with `metadata`.
5. Confirm sign-in works for the application: memberships and
   [grants](../../start/first-application.md) are in place.

## Rollback

Imported users can be removed again, one at a time:

- find them: `GET …/users?external_id=legacy-1001` returns one user by exact
  `external_id`, and the [event log](../../reference/events.md) lists them with
  `GET …/events?type=user.created` (filter `data.origin` = `import` and the time
  window of your run; each event's subject is the user ID);
- `DELETE …/users/:id/permanent` erases the user and everything that references
  them, and cannot be undone. `DELETE …/users/:id` only suspends. See
  [users and organizations](../../reference/api/users-and-organizations.md#users).

There is no bulk delete. Script the permanent delete over the list you collected,
and take a [backup](../../operations/backup-and-restore.md) before the import so
a bad run can be restored as a whole.
