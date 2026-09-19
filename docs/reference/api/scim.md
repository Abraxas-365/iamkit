# SCIM API

Base `/scim/v2`. All routes, including discovery, require
`X-API-Key: ik_scim_…`. Principal scope comes from the provisioning connection;
callers do not select arbitrary environment/organization IDs per request.

| Method/path | Result |
| --- | --- |
| `GET /ServiceProviderConfig` | Supported features/authentication scheme |
| `GET /ResourceTypes`, `GET /ResourceTypes/:id` | User resource metadata |
| `GET /Schemas`, `GET /Schemas/:id` | Supported schema metadata |
| `GET /Users` | SCIM ListResponse |
| `POST /Users` | 201 user, Location header |
| `GET /Users/:id` | 200 user |
| `PUT /Users/:id`, `PATCH /Users/:id` | Updated user |
| `DELETE /Users/:id` | 204; deprovisioning semantics, not universal identity erasure |

Create/replace fields include `schemas`, `userName`, `displayName`, `externalId`,
`active`, email/name fallback fields and enterprise manager. Core schema:
`urn:ietf:params:scim:schemas:core:2.0:User`. Enterprise extension:
`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, with
`manager: {value: "SCIM_USER_UUID"}`.

```json
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","displayName":"Alice","externalId":"directory-alice","active":true}
```

List parameters: `startIndex` defaults to 1 and must be ≥1; `count` defaults to
100 and must be 0–100. Filters support `userName eq "VALUE"` or
`externalId eq "VALUE"`, not arbitrary SCIM expressions. URL-encode filters.
Results use `Resources,totalResults,startIndex,itemsPerPage,schemas`, not `items/page`.

Discovery advertises PATCH but not bulk, sort, password change or ETags. PATCH is
a supported subset; inspect the advertised schemas and handler before mapping
vendor-specific operations. Errors use the SCIM Error schema with string `status`
and `detail`; no management error wrapper.

Source: `internal/iam/provisioning/adapters/provhttp/{handler,schema}.go`,
`provsvc/service.go`. See [connection setup](../../guides/scim-provisioning.md).
