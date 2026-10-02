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
| `PUT /resources/:id` | `name`, `permissions` | 204; permissions removed from the catalog are removed from roles, grants and service accounts too; 422 for the IAM resource (its catalog is built in) |
| `PUT /resources/:id/access` | `owner_organization_id` (null = the environment), `require_grant` | 204; 422 for the IAM resource; organizations losing access have their sessions for the resource ended |
| `PUT /resource-grants` | `resource_id`, `organization_id`, `role_ids` (null = every role) | 200 grant; replaces the roles of an existing grant; 422 for the owner organization or the IAM resource; 400 for a role of another resource |
| `GET /resource-grants` | Optional `resource_id`, `organization_id`, list parameters | 200 page of `{id,resource_id,resource_name,organization_id,organization_name,role_ids,created_at,updated_at}` |
| `GET /resource-grants/:id` | — | 200 grant |
| `DELETE /resource-grants/:id` | — | 204 |
| `POST /application-resources` | `application_id`, `resource_id` | 201 |
| `DELETE /application-resources/:application/:resource` | — | 204; 409 while sessions, OAuth clients, service accounts or SAML applications use the pair |
| `GET /applications/:application/resources` | — | 200 page |
| `POST /roles` | `name`, `resource_id`, `permissions` | 201 `{id}` |
| `GET /roles` | — | 200 page |
| `GET /roles/:id` | — | 200 role |
| `PUT /roles/:id` | `name`, `resource_id`, `permissions` | 204 |
| `DELETE /roles/:id` | — | 204 |
| `POST /role-assignments` | `organization_id`, `user_id`, `role_id` | 204; 409 if already held or the user is not a member |
| `GET /role-assignments` | Filters below | 200 page |
| `DELETE /role-assignments/:role/:organization/:user` | — | 204 |
| `POST /group-role-assignments` | `organization_id`, `group_id`, `role_id` | 204; 409 if already bound |
| `GET /group-role-assignments` | `organization_id`, `group_id`, `role_id`, `resource_id`, list parameters | 200 page |
| `DELETE /group-role-assignments/:role/:organization/:group` | — | 204 |
| `GET /effective-roles` | Required `user_id`; optional `organization_id` | 200 `{items}` (not paginated) |
| `PUT /grants` | `organization_id`, `user_id`, `resource_id`, `permissions` | 200 `{id}` |
| `GET /grants` | — | 200 page |
| `GET /grants/:id` | — | 200 grant |
| `DELETE /grants/:id` | — | 204 |
| `GET /saml/identity-provider` | — | 200 `{entity_id,sso_url,metadata_url,certificate}` ([SAML applications](../../guides/saml-apps.md)) |
| `POST /saml/service-providers` | `name`, `application_id`, `resource_id` (linked), `entity_id`, `acs_urls` (1–10 HTTPS), optional `name_id_format` (`email` default \| `persistent`), `attributes` (name → `email`\|`name`\|`user_id`\|`organization_id`\|`permissions`, ≤ 32) | 201 service provider; 409 for a taken entity ID or an unlinked resource; audited `saml_service_provider.create` |
| `GET /saml/service-providers` | Optional `application_id`, `search` (name, entity ID), list parameters | 200 page of `{id,environment_id,name,application_id,application_name,resource_id,resource_name,entity_id,acs_urls,name_id_format,attributes,created_at}` |
| `GET /saml/service-providers/:id` | — | 200 service provider |
| `PATCH /saml/service-providers/:id` | Any of `name`, `acs_urls`, `name_id_format`, `attributes` (replaces the map) | 200 service provider; audited `saml_service_provider.update` |
| `DELETE /saml/service-providers/:id` | — | 204; pending sign-ins fail; audited `saml_service_provider.delete` |

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
one item per reason the role is held. Omit `organization_id` to get the user's
roles in every organization at once; each item names its `organization_id`.

```json
{"items":[
  {"organization_id":"…","role_id":"…","role_name":"reader","resource_id":"…","resource_name":"Invoices API","source":"group","granted":true,"group_id":"…","group_name":"Finance"},
  {"organization_id":"…","role_id":"…","role_name":"admin","resource_id":"…","resource_name":"Invoices API","source":"direct","granted":false}
]}
```

`granted` is false when the resource requires a grant (`require_grant`) that
the organization lacks for this role: the role stays assigned but adds no
permissions to tokens until the owner grants it.

Direct grants (`PUT /grants`) are not included; inspect them separately.
Tokens do not carry a `groups` claim; they carry the resulting permissions.

## Resource grants

Resources carry `owner_organization_id` and `require_grant`. With
`require_grant` false (the default) any organization may hold the resource's
roles and permissions. With it true, tokens, roles and direct grants for the
resource count only in the owner organization and in organizations holding a
resource grant — and, in the latter, only the granted roles (`role_ids`,
`null` = all). Owner organizations' administrators manage grants of their
resources themselves ([organization administration](../../guides/organization-administration.md#resource-grants-vendor-organizations)).
Resource grant routes need `iam:roles:read`/`iam:roles:write` on `/api/v1`;
`PUT /resources/:id/access` needs `iam:resources:write`.

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
`authorization/adapters/authzhttp/{handler,grants,groups,resource_grants}.go`, authorization domain types.
