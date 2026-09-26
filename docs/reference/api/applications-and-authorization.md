# Applications and authorization API

Prefix: `/management/v1/environments/:environment`. Send `X-API-Key` and JSON.
Owner/admin writes; viewers read. Entity lists use the
[page contract](../errors-and-pagination.md).

| Method/path | Body | Success |
| --- | --- | --- |
| `POST /applications` | `name`, `redirect_uris` array | 201 `{id}` |
| `GET /applications` | — | 200 page |
| `GET /applications/:id` | — | 200 application |
| `PATCH /applications/:id` | Optional `name`, `redirect_uris`, `active` | 204 |
| `DELETE /applications/:id` | — | 204; deactivate |
| `POST /resources` | `name`, `prefix`, `audience`, `permissions` array | 201 `{id}` |
| `GET /resources` | — | 200 page |
| `GET /resources/:id` | — | 200 resource |
| `PUT /resources/:id` | `name`, `permissions` | 204 |
| `POST /application-resources` | `application_id`, `resource_id` | 201 |
| `DELETE /application-resources/:application/:resource` | — | 204 |
| `GET /applications/:application/resources` | — | 200 page |
| `POST /roles` | `name`, `resource_id`, `permissions` | 201 `{id}` |
| `GET /roles` | — | 200 page |
| `GET /roles/:id` | — | 200 role |
| `PUT /roles/:id` | `name`, `resource_id`, `permissions` | 204 |
| `DELETE /roles/:id` | — | 204 |
| `POST /role-assignments` | `organization_id`, `user_id`, `role_id` | 204 |
| `GET /role-assignments` | Filters below | 200 page |
| `DELETE /role-assignments/:role/:organization/:user` | — | 204 |
| `POST /group-role-assignments` | `organization_id`, `group_id`, `role_id` | 204; 409 if already bound |
| `GET /group-role-assignments` | `organization_id`, `group_id`, `role_id`, `resource_id`, list parameters | 200 page |
| `DELETE /group-role-assignments/:role/:organization/:group` | — | 204 |
| `GET /effective-roles` | Required `organization_id`, `user_id` | 200 `{items}` (not paginated) |
| `PUT /grants` | `organization_id`, `user_id`, `resource_id`, `permissions` | 200 `{id}` |
| `GET /grants` | — | 200 page |
| `GET /grants/:id` | — | 200 grant |
| `DELETE /grants/:id` | — | 204 |

`GET /role-assignments` supports `role_id`, `organization_id`, `user_id`,
`resource_id`, `search`, `limit`, `offset`. Filtering and pagination are performed
in the database; total counts filtered matches. Search covers role, organization,
user name/email and resource name. Do not assume these filters exist on other lists.

## Group roles

A role bound to a group applies to every member of that group in the group's
organization. Group-derived roles are computed at token issue, not copied into
`role_assignments`: leaving the group removes them at the next token without
touching the user's direct assignments, and a role held both directly and
through a group survives losing either one. The group must belong to
`organization_id` (404 otherwise). Directory (SCIM) groups can be bound like
any other group.

`GET /effective-roles?organization_id=…&user_id=…` explains a member's roles:
one item per reason the role is held.

```json
{"items":[
  {"role_id":"…","role_name":"reader","resource_id":"…","resource_name":"Invoices API","source":"group","group_id":"…","group_name":"Finance"},
  {"role_id":"…","role_name":"admin","resource_id":"…","resource_name":"Invoices API","source":"direct"}
]}
```

Direct grants (`PUT /grants`) are not included; inspect them separately.
Tokens do not carry a `groups` claim; they carry the resulting permissions.

## Catalog rules

A resource defines an immutable audience and prefix. Permissions must belong to
its exact catalog and namespace, for example `invoices:read`. There is no wildcard
administrator permission. A role belongs to a resource; it cannot grant another
resource's permissions. Catalog changes must remain consistent with existing
assignments/grants. Application-resource linking is required before login can
request that resource. Bindings do not themselves grant a user access.

Example grant body:

```json
{"organization_id":"ORG_UUID","user_id":"USER_UUID","resource_id":"RESOURCE_UUID","permissions":["invoices:read"]}
```

Replace identifiers with real IDs from creation responses. A PUT grant replaces
that direct grant's permissions; role-derived permissions may still provide access.
To remove access, inspect direct grants, direct role assignments and group roles
(`GET /effective-roles` lists the role paths). Recheck through
online introspection; an offline JWT verifier sees the issued snapshot until expiry.

**Verify:** request `invoices:write` when only `invoices:read` is cataloged and expect
validation failure. Test another organization's token against the protected API
and expect denial even when it has the same permission string.

Source: `internal/iam/application/adapters/apphttp/handler.go`,
`authorization/adapters/authzhttp/{handler,grants,groups}.go`, authorization domain types.
