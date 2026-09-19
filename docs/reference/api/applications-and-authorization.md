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
| `PUT /grants` | `organization_id`, `user_id`, `resource_id`, `permissions` | 200 `{id}` |
| `GET /grants` | — | 200 page |
| `GET /grants/:id` | — | 200 grant |
| `DELETE /grants/:id` | — | 204 |

`GET /role-assignments` supports `role_id`, `organization_id`, `user_id`,
`resource_id`, `search`, `limit`, `offset`. Filtering and pagination are performed
in the database; total counts filtered matches. Search covers role, organization,
user name/email and resource name. Do not assume these filters exist on other lists.

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
To remove access, inspect both direct and role-derived grants. Recheck through
online introspection; an offline JWT verifier sees the issued snapshot until expiry.

**Verify:** request `invoices:write` when only `invoices:read` is cataloged and expect
validation failure. Test another organization's token against the protected API
and expect denial even when it has the same permission string.

Source: `internal/iam/application/adapters/apphttp/handler.go`,
`authorization/adapters/authzhttp/{handler,grants}.go`, authorization domain types.
