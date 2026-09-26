# Users and organizations API

All paths use `/management/v1/environments/:environment` and management
[authentication](management.md). IDs are UUIDs. Writes require owner/admin.
Requests are JSON; creation responses `{id}` identify newly created entities.
Lists of users, organizations and members use the
[pagination envelope](../errors-and-pagination.md).

## Users

| Method/path | Input | Success |
| --- | --- | --- |
| `POST /users` | `name`, `email`; optional `password`, `otp_enabled` | 201 `{id}` |
| `GET /users` | List parameters | 200 page of users |
| `GET /users/:id` | User ID | 200 user |
| `PATCH /users/:id` | Optional `name`, `active`, `otp_enabled`, `metadata` | 204 |
| `DELETE /users/:id` | User ID | 204; suspend, not erase |
| `DELETE /users/:id/permanent` | User ID | 204; permanently erases the user and every session, membership, group membership, grant, role assignment, position assignment, external identity, provisioned identity, and identity challenge referencing them. Irreversible. |

List items contain only `id,email,name,active`. Use `GET /users/:id` for
`email_verified,otp_enabled,metadata` as well; missing list fields are not evidence
that those settings are false. Neither response exposes password hashes.
Non-empty passwords must be 12–72 bytes. Name cannot be
blank. Email is normalized by the service. Metadata is JSON, not an encoded JSON
string. Password is not a user PATCH field; use the challenge reset workflow.

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
| `GET /organizations` | List parameters | 200 page |
| `GET /organizations/:id` | Organization ID | 200 organization |
| `PATCH /organizations/:id` | Update fields: `name`, `metadata` | 204 |
| `POST /memberships` | `organization_id`, `user_id` | 201 |
| `GET /organizations/:organization/members` | Organization ID | 200 page |
| `DELETE /organizations/:organization/members/:user` | Organization/user IDs | 204 |

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
| `GET /groups` | List parameters; optional `user_id`, `connection_id` filters | 200 page |
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

**Verify:** create a user and membership, read both back, then attempt login before
creating a resource grant: it must fail. Complete the
[first application](../../start/first-application.md) workflow for permitted access.

Source: `user/adapters/userhttp/handler.go`, `user/user.go`,
`organization/adapters/orghttp/{handler,structure,groups}.go` and domain types under
`internal/iam/`.
