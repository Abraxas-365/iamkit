# User metadata and profile schemas

Users carry two JSON objects besides their built-in fields:

| Object | Who writes it | Checked against | Reaches tokens |
| --- | --- | --- | --- |
| `metadata` | Operators and API clients | Size limits only | No (organization metadata: yes, see below) |
| `profile` | Operators, API clients and — for annotated attributes — the user | The environment's user schema, when one is saved | Annotated attributes, with the `profile` scope |

Organizations have `metadata` too, with the same limits; it is included in
tokens for that organization.

## Metadata

Metadata is free-form operator data: CRM IDs, plan tiers, notes. Limits:
at most 64 keys, keys match `^[a-zA-Z0-9_.-]{1,64}$`, each value at most
4 KiB and the whole object at most 32 KiB (JSON-encoded). A write that breaks
a limit is 400.

Change one key at a time, so concurrent writers do not overwrite each other
(each change is audited `user.metadata_set` / `user.metadata_deleted`, or
`organization.metadata_*`):

```sh
curl -X PUT  "$BASE/environments/$ENV/users/$USER/metadata/crm.id" -d '"0012345"'
curl         "$BASE/environments/$ENV/users/$USER/metadata/crm.id"     # 200 "0012345"
curl -X DELETE "$BASE/environments/$ENV/users/$USER/metadata/crm.id"   # 204; 404 when absent
```

The body of `PUT` is the raw JSON value (a string, number, object…).
`PATCH /users/:id` with `metadata` still replaces the whole object, under
the same limits.

## Profile attributes and the user schema

The profile is a JSON object of structured attributes (department, employee
number, preferred language…). Without a schema any object is accepted. Save a
[JSON Schema](https://json-schema.org/draft/2020-12) (draft 2020-12; the only
draft accepted) per environment to check every profile write:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["department"],
  "properties": {
    "department": { "type": "string", "enum": ["sales", "engineering"], "x-iamkit-claim": "department", "x-iamkit-self": "read" },
    "nickname":   { "type": "string", "maxLength": 40, "x-iamkit-self": "write" },
    "employee_no": { "type": "integer" }
  }
}
```

- The schema's top level must be `type: object`; it is compiled when saved
  and invalid schemas are 400. `$ref` may only point inside the schema —
  IAMKit never fetches remote schemas. Formats (`email`, `date`, `uri`…) are
  asserted.
- Saving answers `non_conforming`: how many existing profiles do not match.
  They are never rewritten; each must conform on its next change.
- Every save bumps `version` and is audited `user.schema_updated`; deleting
  the schema (`user.schema_deleted`) stops checking and releasing claims.

Top-level properties may carry two annotations:

| Annotation | Values | Effect |
| --- | --- | --- |
| `x-iamkit-self` | `read`, `write` | The user sees (`read`) or also changes (`write`) the attribute through `/identity/v1/me/profile`. Unannotated attributes stay operator-only |
| `x-iamkit-claim` | a claim name | The attribute is released under that name in OIDC ID tokens and UserInfo when the `profile` scope was granted. Names are unique and cannot reuse a standard or IAMKit claim (`sub`, `email`, `permissions`, `organization_id`…) |

Operators change attributes with `PATCH /users/:id/profile`, a
[JSON merge patch](https://www.rfc-editor.org/rfc/rfc7396): listed keys are set,
`null` removes a key, the rest is kept. The merged profile (at most 32 KiB) is
checked against the schema and the answer is the full profile. Changes are
audited `user.profile_updated`.

## Self-service

A signed-in user reads and edits their own annotated attributes with an
application token (not a machine or impersonated one):

```sh
curl "$BASE/identity/v1/me/profile?environment_id=$ENV&audience=$AUD" -H "Authorization: Bearer $TOKEN"
# {"profile":{"department":"sales","nickname":"Al"}}
curl -X PATCH "$BASE/identity/v1/me/profile" -H "Authorization: Bearer $TOKEN" \
  -d '{"environment_id":"'$ENV'","audience":"'$AUD'","profile":{"nickname":"Ally"}}'
```

The PATCH may only name `x-iamkit-self: write` attributes (others are 403);
the merged profile must still satisfy the whole schema. Without a schema the
self-service profile is empty and every change is refused.

## Avatars

`avatar_url` is a built-in field holding an `https://` link to the user's
picture (at most 2048 characters, no embedded credentials). IAMKit stores the
link, never the image, so host pictures on a CDN or your own storage.

- Operators set it on `POST`/`PATCH …/users` (`""` removes it).
- Users change their own through `PATCH /identity/v1/me` with `avatar_url`.
- Social and enterprise sign-ins fill it from the provider's `picture` claim
  when the account has none; with `update_profile` it follows the provider.
- It is released as the OIDC `picture` claim with the `profile` scope, and the
  hosted organization chooser shows it next to the account being signed in.

```sh
iam users update $USER --avatar-url https://cdn.example.com/u/ada.png
```

## Usernames

A user may have a `username` besides their email: 3 to 64 lowercase letters,
digits, `.`, `_` or `-`, starting with a letter or digit, unique in the
environment (409 `username is taken`). It never contains `@`, so whatever
someone types to sign in is an email exactly when it has one. Input is
lowercased and trimmed; `""` removes it and frees it for someone else.

- Operators set it on `POST`/`PATCH …/users`; user lists search it with
  `?search=`. Users read theirs on `GET /identity/v1/me` but cannot change it.
- `POST /identity/v1/login` and `POST /identity/v1/challenges` accept `login`
  (an email or a username) in place of `email`. A challenge for a username is
  sent to the account's email; an unknown username answers exactly like an
  unknown email (202 with a challenge id, nothing sent).
- The hosted page asks for "Email or username". A username goes straight to
  the password page — known or not, so the page reveals nothing — because it
  has no domain to route to single sign-on by.
- Single sign-on enforcement still applies to the account's email domain.
  For a username it is checked once the password matched, so `SSO_REQUIRED`
  never reveals that a username exists; wrong passwords answer the uniform 401.
- It is released as the OIDC `preferred_username` claim with the `profile`
  scope. Federation linking, invitations and SCIM `userName` stay email-based.

```sh
iam users create --name Ada --email ada@example.com --username ada
iam users update $USER --username ""   # remove it
```

## Phone numbers

`phone` is a built-in field holding an E.164 number (`+` and 7–15 digits;
spaces, dashes, dots and parentheses are stripped on input) and
`phone_verified` says whether someone proved they receive texts at it. It is
not a sign-in identifier.

- Users verify a number themselves, with an SMS provider configured for the
  environment (see [SMS provider](mfa.md#sms-provider)) and a sign-in within
  the last few minutes (403 `REAUTHENTICATION_REQUIRED` otherwise):
  `POST /identity/v1/me/phone {phone}` texts a 6-digit code (purpose
  `phone_verification`, 5 minutes, one every 30 seconds and 10 an hour —
  429 `CODE_COOLDOWN`/`CODE_LIMIT`), then `POST /identity/v1/me/phone/verify
  {code}` makes it their verified `phone` (audited `user.phone_verified`). The
  current number stays until the code is entered; five wrong codes discard it
  (422 `INVALID_CODE`). `DELETE /identity/v1/me/phone` clears it
  (`user.phone_removed`).
- Confirming an SMS second factor also sets the verified phone.
- Operators set `phone` on `PATCH …/users/:id` (a changed number is
  unverified) and may mark it verified with `phone_verified: true`, which needs
  a number and is audited `user.phone_verified_set`.
- The OIDC `phone` scope releases `phone_number` and `phone_number_verified`
  (ID token and UserInfo); `profile` alone does not.
- SCIM maps `phoneNumbers[type eq "mobile"]` only for connections issued with
  `map_phone` (see [SCIM](scim-provisioning.md#phone-numbers)).

```sh
iam users update $USER --phone "+1 415 555 0100"
iam users update $USER --phone-verified true
```

The Go SDK's `authclient` has `StartPhoneVerification`, `VerifyPhone` and
`RemovePhone`.

## Console, CLI and SDK

The console's user page lists metadata keys (add, edit, delete one at a time)
and profile attributes; **Users & access › User schema** edits the schema and
shows each property's type and annotations.

```sh
iam users metadata set $USER plan '"gold"'   # VALUE is JSON, else a plain string
iam users metadata get $USER plan
iam users profile $USER --data '{"department":"sales"}'
iam user-schema set --file schema.json
iam orgs metadata set $ORG region eu
```

The Go SDKs (`iamclient` and `apiclient`) have `UserMetadata`,
`SetUserMetadata`, `DeleteUserMetadata`, the `Organization*` equivalents,
`UpdateUserProfile`, `UserSchema`, `SaveUserSchema` and `DeleteUserSchema`.
Scoped API clients need `iam:users:read`/`iam:users:write` (organization
metadata: `iam:orgs:*`).
