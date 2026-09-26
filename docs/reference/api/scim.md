# SCIM API

Base `/scim/v2` (RFC 7643/7644). All routes, including discovery, require the
provisioning credential as `Authorization: Bearer ik_scim_…` (what directories
such as Entra ID, Okta and OneLogin send) or `X-API-Key: ik_scim_…`. If both
headers are present they must carry the same secret. Principal scope comes from
the provisioning connection; callers do not select arbitrary
environment/organization IDs per request. Responses use
`Content-Type: application/scim+json`.

| Method/path | Result |
| --- | --- |
| `GET /ServiceProviderConfig` | Supported features; auth scheme `oauthbearertoken` |
| `GET /ResourceTypes`, `GET /ResourceTypes/:id` | `User` and `Group` resource metadata |
| `GET /Schemas`, `GET /Schemas/:id` | Schema metadata matching stored attributes |
| `GET /Users` | SCIM ListResponse |
| `POST /Users` | 201 user, `Location` header |
| `GET /Users/:id` | 200 user |
| `PUT /Users/:id`, `PATCH /Users/:id` | 200 updated user |
| `DELETE /Users/:id` | 204; deprovisions (see below), never erases the user |
| `GET /Groups`, `GET /Groups/:id` | SCIM ListResponse / 200 group |
| `POST /Groups` | 201 group, `Location` header |
| `PUT /Groups/:id` | 200 group (name and member set replaced) |
| `PATCH /Groups/:id` | 204 |
| `DELETE /Groups/:id` | 204; deletes the group, its members and role bindings |

## User resource

Every response (POST, GET, PUT, PATCH, list) has the same shape: `schemas`, `id`,
`externalId` (when the directory supplied one), `userName`, `displayName`,
`name.formatted`, `active`, `emails[]` (primary `{value,type:"work",primary:true}`
followed by aliases), `meta{resourceType,created,lastModified,location}` and,
when set, the enterprise extension `manager.value`.

Inbound, `userName` falls back to the primary `emails[].value`; `displayName`
falls back to `name.formatted`, then `name.givenName + name.familyName`.
`active` accepts JSON booleans and the strings `"True"`/`"False"`. The enterprise
`manager` accepts `{"value":"SCIM_USER_UUID"}` or a bare `"SCIM_USER_UUID"`; it
must reference a live user of the same connection and cannot form a cycle.

### Identity and anchors

- The resource `id` is the IAMKit user id and never changes.
- `externalId` is the directory anchor (e.g. Entra `objectId`). Once set by the
  directory it is immutable (400 `mutability`). If omitted on create, IAMKit
  anchors the identity internally (not returned); the directory may later set
  `externalId` once, by PUT/PATCH or by a `POST` with the same `userName` (which
  returns the existing user). Migration 002 also re-keys stored anchors equal to
  the user's email this way, since earlier releases used the email as fallback:
  a directory that genuinely sent the email as `externalId` re-claims it on its
  next create, or an operator restores it with `POST /provisioned-identities`.
- `userName` is the user's primary email and login. It can be renamed (PUT or
  PATCH); the new address starts unverified. Only users the directory created
  can be renamed: adopted or operator-linked users (who may have their own
  password or federated login), and users that also belong to another
  organization or provisioning connection, return 400 `mutability`. Another user's address returns 409 `uniqueness`.
- Other `emails[]` values are stored as aliases of this connection: returned
  and searchable with `emails.value eq`, but not login identifiers, not unique
  and invisible to other directories. PUT replaces the connection's alias set.

### DELETE and re-creation

`DELETE` deprovisions: the membership is deactivated, the user's roles, grants,
group memberships and positions in the organization are removed, reports pointing to the user
lose their manager, and the resource returns 404 to GET/PUT/PATCH/DELETE and is
hidden from lists. The user itself (password, other organizations) is kept. A
later `POST` with the same `externalId` (or the same `userName` when no
`externalId` was ever sent) reactivates the same user id without access and
returns 201. A reused address with a different `externalId` is treated as a
different person: 409 until an operator links it with
`POST /provisioned-identities`.

### Existing users

By default, `POST` of an email that already belongs to a user returns 409
`uniqueness`; link them explicitly with `POST /provisioned-identities`. A
connection issued with `"adopt_existing_members": true` instead links an existing
member of its organization with that primary email (password and grants are
kept). Users outside the organization are never adopted. With
`"adopt_scope": "verified_domains"` only members whose email is on one of the
organization's [verified domains](users-and-organizations.md#domains) are
adopted; others get 409 as if adoption were off.

```json
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","displayName":"Alice","externalId":"directory-alice","active":true}
```

## Group resource

SCIM groups are organization groups owned by the provisioning connection. A
directory sees and changes only its own groups; operator-created groups and
other directories' groups return 404. Operators see directory groups in the
management API as read-only (name and members return 422) and decide which
roles they carry with `POST /group-role-assignments`; members receive those
roles in their tokens.

Responses: `schemas`, `id`, `externalId` (when set), `displayName`,
`members[]` (`{value, display, type:"User", $ref}`) and
`meta{resourceType,created,lastModified,location}`. `displayName` is required,
unique per connection (case-insensitive, 409 `uniqueness`). `members[].value`
must be the id of a live user this connection provisioned (400 `invalidValue`).
Deprovisioning a user (`DELETE /Users/:id`) removes it from every group.
`excludedAttributes=members`, or an `attributes` list without `members`, omits
members from GET and list responses.

```json
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","externalId":"grp-eng","members":[{"value":"SCIM_USER_UUID"}]}
```

PATCH supports `displayName`, `externalId` and `members` with the forms Entra
ID and Okta send: `add` `members` (list of `{value}`), `remove`
`members[value eq "id"]`, `remove` `members` with a value list (those members)
or without one (all members), `replace` `members` (full set), and a path-less
`replace` object with `displayName`/`members`. Operations are applied in order;
unknown attributes are ignored. Group filters: `displayName` (case-insensitive),
`externalId` (case-exact) and `id`.

## User PATCH

Operations `add`, `replace` and `remove` (case-insensitive), with a `path` or a
path-less object value. Stored attributes: `active`, `displayName`,
`name.formatted`, `userName`, `externalId` (see anchors), enterprise `manager` /
`manager.value` (`remove` clears it), and `emails`: `add` merges, `replace`
resets, `remove` clears the aliases; `emails[value eq "x"]` and
`emails[type eq "t"].value` target one alias, and `emails[primary eq true].value`
renames. Read-only (`id`, `meta`, `schemas`) and unstored attributes
(`name.givenName`, `title`, `department`, `phoneNumbers`, …) are accepted and
ignored, so a directory's full attribute mapping does not fail the sync. Other
operations return 400 `invalidSyntax`. A PATCH racing another update of the same
user is re-applied on the latest state; persistent contention returns 409.

## Listing and filters

`startIndex` defaults to 1 (values below 1 are treated as 1); `count` defaults
to 100, is capped at 100, negative values are treated as 0. Filters support a
single `ATTRIBUTE eq "VALUE"` with case-insensitive attribute and operator, for
`userName` (primary email), `emails.value` (primary or alias), `externalId`
(case-exact) and `id`. Other expressions
return 400 `invalidFilter`. URL-encode filters. Results use
`Resources,totalResults,startIndex,itemsPerPage,schemas`, not `items/page`.

## Errors

SCIM Error schema with string `status`, `detail` and, for 400/409, a `scimType`
(`invalidSyntax`, `invalidFilter`, `invalidPath`, `invalidValue`, `mutability`,
`uniqueness`). Bulk, sort, password change and ETags are not supported.

Source: `internal/iam/provisioning/adapters/provhttp/{handler,patch,schema,groups}.go`,
`provsvc/{service,groups}.go`. See [connection setup](../../guides/scim-provisioning.md).
