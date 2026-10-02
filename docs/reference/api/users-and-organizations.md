# Users and organizations API

All paths use `/management/v1/environments/:environment` and management
[authentication](management.md). IDs are UUIDs. Writes require owner/admin.
Requests are JSON; creation responses `{id}` identify newly created entities.
Lists of users, organizations and members use the
[pagination envelope](../errors-and-pagination.md).

## Users

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /users` | `name`, `email`; optional `password`, `otp_enabled`, `avatar_url`, `username`, `home_organization_id` (also adds the membership). `kind: "machine"` creates a [machine user](../../guides/machine-users.md): `name` and optional `avatar_url`/`home_organization_id` only | 201 `{id}`; 409 `email is taken` or `username is taken` |
| `GET /users` | List parameters (`search` matches name, email and username); optional `state`, `home_organization_id`, `kind` (`human`\|`machine`) | 200 page of users (each with `kind`) |
| `GET /users/:id` | User ID | 200 user |
| `PATCH /users/:id` | Optional `name`, `active`, `otp_enabled`, `metadata`, `phone` (E.164, `""` clears; a changed number is unverified), `phone_verified` (explicit, audited `user.phone_verified_set`; `true` needs a number, else 400), `avatar_url` (`""` removes), `username` (`""` removes), `home_organization_id` (an organization the user belongs to; `""` clears) | 204; 409 `username is taken` |
| `DELETE /users/:id` | User ID | 204; suspend, not erase (same as `POST …/deactivate`) |
| `POST /users/:id/deactivate` | User ID | 204; suspends the user (`active=false`): sessions end, nothing signs in; audited `user.deactivated` |
| `POST /users/:id/reactivate` | User ID | 204; lifts a suspension; audited `user.reactivated` |
| `DELETE /users/:id/permanent` | User ID | 204; permanently erases the user and every session, membership, group membership, grant, role assignment, position assignment, external identity, provisioned identity, second factor, recovery code and identity challenge referencing them. Irreversible. |
| `GET /users/:id/factors` | User ID | 200 `{factors:[{id,kind,confirmed_at,last_used_at,created_at}],recovery_codes_remaining}`; never secrets |
| `DELETE /users/:id/factors` | User ID | 204; removes every [second factor](../../guides/mfa.md) and recovery code (lost device) and clears a lockout; audited `mfa.reset`. 404 when the user has none |
| `GET /users/:id/access-tokens` | Machine user ID; list parameters (`search` matches the name) | 200 page of `{id,name,organization_id,organization_name,application_id,application_name,resource_id,resource_name,expires_at,last_used_at,revoked_at,created_at}`; never secrets |
| `POST /users/:id/access-tokens` | `name`, `organization_id` (one the machine user belongs to), `application_id`, `resource_id` (linked to it); optional `expires_in` (`1h`–`8760h` or `never`, default `24h`) | 201 the token plus `token` (`ik_pat_…`, shown once); 404 unknown user; 422 for a human user; 400 without an active membership in the organization or with an unlinked resource; audited `user.access_token_created` |
| `DELETE /users/:id/access-tokens/:token` | User ID, token ID | 204, also when already revoked; sessions exchanged from it end; audited `user.access_token_revoked` |
| `GET /users/:id/keys` | Machine user ID; list parameters | 200 page of `{id,user_id,public_key,expires_at,last_used_at,created_at}` ([keys](../../guides/machine-users.md#keys-jwt-bearer-login)) |
| `POST /users/:id/keys` | Empty body (IAMKit generates an RSA pair), or `public_key` (public RSA ≥ 2048-bit or EC P-256/384/521 JWK); optional `expires_in` (`1h`–`8760h` or `never`, default `8760h`) | 201 the key, plus `private_key` (PKCS #8 PEM, shown once) for a generated pair; 400 private or malformed key; 422 for a human user or a user with 10 keys; audited `user.key_added` |
| `DELETE /users/:id/keys/:key` | User ID, key ID | 204; sessions opened with it end; 404 unknown key; audited `user.key_removed` |
| `POST /users/:id/unlock` | User ID | 204; clears the wrong-password count and [password lockout](../../guides/password-policy.md); audited `user.unlocked` |
| `GET /users/:id/metadata/:key` | User ID, key | 200 the raw JSON value; 404 when the key is absent |
| `PUT /users/:id/metadata/:key` | Raw JSON value as the body | 204; audited `user.metadata_set` |
| `DELETE /users/:id/metadata/:key` | User ID, key | 204; 404 when absent; audited `user.metadata_deleted` |
| `PATCH /users/:id/profile` | [JSON merge patch](https://www.rfc-editor.org/rfc/rfc7396) of profile attributes (`null` removes) | 200 `{profile}`; the result must match the [user schema](../../guides/user-profiles.md#profile-attributes-and-the-user-schema); audited `user.profile_updated` |
| `GET /user-schema` | — | 200 `{schema,version,updated_at}`; 404 when none is saved |
| `PUT /user-schema` | `schema` (JSON Schema 2020-12, top-level `type: object`, local `$ref` only, ≤ 64 KiB) | 200 `{schema,version,updated_at,non_conforming}`; audited `user.schema_updated` |
| `DELETE /user-schema` | — | 204; audited `user.schema_deleted` |

List items contain only `id,email,name,username,home_organization_id,avatar_url,active,state,last_signed_in_at`. Use `GET /users/:id` for
`email_verified,otp_enabled,phone,phone_verified,metadata,profile` and the password lockout state
(`failed_logins`, `locked_until` — null when not locked) and `terms_accepted_at` (when a
[sign-up](../../guides/signup-and-onboarding.md#terms-acceptance) accepted the terms) as well; missing list fields are not evidence
that those settings are false. Neither response exposes password hashes.
Non-empty passwords must follow the environment's
[password policy](../../guides/password-policy.md) (default 12–72 bytes; 400
`PASSWORD_POLICY` with `details.rule`). Name cannot be
blank. `avatar_url` is an `https://` URL of at most 2048 characters without
credentials ([avatars](../../guides/user-profiles.md#avatars)). `username` is optional: 3–64 lowercase letters, digits, `.`, `_`, `-` (never `@`), unique in the environment; it is lowercased (`""` when none; [usernames](../../guides/user-profiles.md#usernames)). Email is normalized by the service. Metadata is a JSON object, not an encoded JSON
string: at most 64 keys matching `^[a-zA-Z0-9_.-]{1,64}$`, 4 KiB per value,
32 KiB in total — `PATCH` replaces it whole, the `/metadata/:key` routes change
one key (see [metadata and profiles](../../guides/user-profiles.md)). Password is not a user PATCH field; use the challenge reset workflow.
`home_organization_id` names the organization that owns the record: its
[administrators](../../guides/organization-administration.md) may edit the
user (null when none).

### User states

`state` is derived on every read, never stored; `active` stays the only
switch that blocks sign-in. The first matching state wins:

| State | Meaning |
| --- | --- |
| `suspended` | `active=false` — an operator or API client deactivated the user |
| `locked` | the [password policy](../../guides/password-policy.md) locked password sign-in (`locked_until` in the future) |
| `initial` | never signed in (`last_signed_in_at` is null): created, invited or provisioned and not used yet |
| `inactive` | signed in before but has no active membership in an active organization (removed, deprovisioned by SCIM, or the organization deactivated), so no sign-in can succeed |
| `active` | can sign in |

`last_signed_in_at` is set when a sign-in creates a session (password, email
code, passkey, federation, hosted and OAuth logins); impersonation and token
exchange do not change it. `GET /users?state=initial` lists users in one state;
another value is 400.

A user without a password can use linked federation, or OTP if enabled. Creation
does not establish membership or access. Email verification does not automatically
follow creation. Suspend rather than assuming deletion removes historical data;
use the `/permanent` endpoint only when the user's data must actually be erased
(e.g. a GDPR erasure request) — it deletes audit-relevant relationships, not
just the account.

## Organizations and memberships

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /organizations` | `name` | 201 `{id}` |
| `GET /organizations` | List parameters; optional `user_id` (only organizations the user belongs to) | 200 page of `{id,name,active}` |
| `GET /organizations/:id` | Organization ID | 200 organization |
| `GET,PUT,DELETE /organizations/:id/metadata/:key` | Like the user metadata routes (same limits) | 200 value / 204; audited `organization.metadata_set` / `organization.metadata_deleted` |
| `PATCH /organizations/:id` | Update fields: `name`, `metadata`, `mfa_required`, `mfa_for_federated`, `allowed_factors` ([MFA policy](../../guides/mfa.md#policy)), `allow_password`, `allow_email_code`, `allow_social`, `allow_passkey` ([sign-in methods](../../guides/sign-in-methods.md#three-layers)) | 204 |
| `POST /memberships` | `organization_id`, `user_id` | 201 |
| `GET /organizations/:organization/members` | Organization ID | 200 page |
| `PATCH /organizations/:organization/members/:user` | `sso_bypass` | 204; 400 for an empty patch |
| `DELETE /organizations/:organization/members/:user` | Organization/user IDs | 204 |

Members include `sso_bypass`: when true, the member may keep using password or
email-code login where the organization enforces SSO (break-glass; see
[federation](../../guides/federation.md#enforcement)).

Membership does not grant operator authority or API permissions. Removing one
organization's membership must not be used as a substitute for suspending a user
across the environment. Tenant data queries must match the token organization.

## Organization structure

Prefix these paths with `/organizations/:organization`:

| Method/path | Input or result |
| --- | --- |
| `GET /org-units`, `/positions`, `/position-assignments` | Structure collections (JSON read models) |
| `GET /org-units/:id` | Unit detail |
| `GET /org-units/:id/ancestors`, `/org-units/:id/descendants` | Hierarchy traversal |
| `GET /org-units/:id/delete-impact` | Inspect affected structure before deletion |
| `GET /tree`, `/org-chart` | Organization read models |
| `POST /org-units`, `PUT /org-units/:id` | `name`, `kind`, nullable `parent_id` |
| `DELETE /org-units/:id` | Remove unit |
| `PUT /members/:user/profile` | Nullable `org_unit_id`, `manager_id` |
| `POST /positions`, `PUT /positions/:id` | `name`, `code` |
| `DELETE /positions/:id` | Remove position |
| `POST /position-assignments` | `position_id`, `user_id`, nullable `org_unit_id` |
| `DELETE /position-assignments/:id` | Remove assignment |

Structure creates return 201 `{id}`; updates/deletes return 204. Referenced members
and units must belong to the organization. Parent/manager relationships cannot
introduce cycles. Structure collections are not the generic page contract. Job
titles and reporting relationships are descriptive, not authorization grants.

## Groups

Groups collect organization members so roles can be assigned once to many
people. Prefix these paths with `/organizations/:organization`:

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /groups` | `name`, optional `description` | 201 `{id}` |
| `GET /groups` | List parameters; optional `user_id`, `connection_id`, `source` (`manual` or `directory`) filters | 200 page |
| `GET /groups/:group` | — | 200 group |
| `PATCH /groups/:group` | Optional `name`, `description` | 204 |
| `DELETE /groups/:group` | — | 204; also removes its members and role bindings |
| `GET /groups/:group/members` | List parameters | 200 page `{user_id,user_name,user_email,active,added_at}` |
| `POST /groups/:group/members` | `add` and/or `remove` user ID arrays (≤ 1000 total) | 204 |
| `GET /members/:user/groups` | List parameters | 200 page of the member's groups |

A group is `{id,name,description,connection_id,external_id?,member_count,created_at,updated_at}`.
Names are unique per organization, case-insensitive (409). Every added user must
be an active member of the organization (400); adding an existing member or
removing a non-member is a no-op. Removing a member from the organization, SCIM
deprovisioning and permanent user deletion also remove the user from its groups.
Groups do not nest.

Groups with a non-null `connection_id` are owned by a SCIM directory (see
[SCIM Groups](scim.md#group-resource)): PATCH, DELETE and member changes return
422; the directory manages them. Operators still decide which roles they carry.
Bind roles with `POST /group-role-assignments` (see
[authorization](applications-and-authorization.md#group-roles)).

## Domains

An organization claims the DNS domains it owns and proves control with a TXT
record. Prefix these paths with `/organizations/:organization`:

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /domains` | `domain` | 201 domain (unverified, with the record to publish) |
| `GET /domains` | List parameters (`search` matches the domain) | 200 page |
| `GET /domains/:domain` | — | 200 domain |
| `POST /domains/:domain/verify` | — | 200 domain; 422 when the record is missing, 502 when DNS fails |
| `POST /domains/:domain/force-verify` | — | 200 domain, verified without DNS (method `manual`) |
| `DELETE /domains/:domain` | — | 204; releases the claim; 422 if it is the last verified domain while SSO is enforced |

A domain is `{id,organization_id,domain,verified,verified_at,verified_by,verification_method,verification:{type,name,value},created_at}`.
Input is normalized: lowercased, trailing dot removed, internationalized names
converted to punycode (`bücher.example` → `xn--bcher-kva.example`). Wildcards,
bare public suffixes (`com`, `co.uk`), single labels and names over 253
characters are rejected (400). Subdomains are separate claims.

A domain belongs to at most one organization per environment, verified or not
(409). To verify, publish a TXT record named `verification.name`
(`_iamkit-challenge.<domain>`) with value `verification.value`
(`iamkit-verification=<token>`), then call `verify`; the check runs only when
requested and is never repeated, so removing the record later does not
unverify. Verifying an already verified domain returns it unchanged.
Force-verify is for ownership confirmed out of band; both paths are audited
with their method. Viewers can read domains but not change them.

Verified domains restrict SCIM adoption when a connection uses
`adopt_scope: "verified_domains"` (see [SCIM](scim.md#existing-users)), and
route email discovery, just-in-time provisioning and SSO enforcement for the
organization's federation connections (see [federation](../../guides/federation.md#organization-sso)).

## Invitations

Invite a person by email into an organization. Prefix these paths with
`/organizations/:organization`:

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /invitations` | `email`, `role_ids?`, `group_ids?` | 201 issued invitation (token shown once) |
| `GET /invitations` | List parameters; `search` matches the email; `status` = `pending`\|`accepted`\|`revoked`\|`expired` | 200 page |
| `GET /invitations/:invitation` | — | 200 invitation |
| `POST /invitations/:invitation/resend` | — | 200 issued invitation with a new token and expiry; 422 once accepted or revoked |
| `DELETE /invitations/:invitation` | — | 204; idempotent; 422 once accepted |

An invitation is `{id,organization_id,email,role_ids,group_ids,inviter,expires_at,accepted_at,accepted_user_id?,revoked_at,created_at,status}`.
`status` is derived, never stored. Create and resend also return `token`,
`link` (only when the environment's delivery config has an `invitation_url`)
and `delivery`: `sent`, `failed` (the webhook rejected it; the invitation is
still valid, share the token yourself) or `skipped` (no webhook configured).
Only a SHA-256 hash of the token is stored; it cannot be shown again.

Rules: email is normalized (trimmed, lowercased); up to 50 roles and 50 groups.
Roles must exist in the environment and groups must be operator-managed groups
of the organization (directory groups are rejected), otherwise 422. Inviting an
active member returns 409; so does a second pending invitation for the same
email (resend or revoke the first). Expired pending invitations are revoked
automatically when the email is invited again. Inactive organizations cannot
invite (422). Invitations expire after 7 days; resend restarts the clock and
invalidates the previous token. Viewers can read invitations but not change them.

The invitee accepts through the public [identity API](identity.md#invitations).
Erasing a user permanently also deletes invitations addressed to or accepted by
them.

**Verify (invitations):** invite a test address, confirm the webhook received the
token, preview and accept it, then accept again (401) and read the invitation
back as `accepted`.

**Verify (domains):** add a domain, call `verify` before publishing the record (422), publish
it, verify again (200, `verification_method: "dns"`), then try to claim it from
another organization (409).

**Verify:** create a user and membership, read both back, then attempt login before
creating a resource grant: it must fail. Complete the
[first application](../../start/first-application.md) workflow for permitted access.

Source: `user/adapters/userhttp/handler.go`, `user/user.go`,
`organization/adapters/orghttp/{handler,structure,groups,domains}.go`, `organization/adapters/orgdns`, `invitation/adapters/invhttp` and domain types under
`internal/iam/`.
