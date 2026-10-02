# @iamkit/api

Typed TypeScript client for every documented IAMKit route — the management
API, the scoped API, the identity API, SCIM and the OAuth endpoints. Types
are generated with [openapi-typescript](https://openapi-ts.dev) from
`api/openapi.json`; requests go through
[openapi-fetch](https://openapi-ts.dev/openapi-fetch/) (a thin `fetch`
wrapper, no runtime schema code).

```ts
import { createIAMKitClient, isApiError, type Schema } from "@iamkit/api";

const iam = createIAMKitClient({ baseUrl: "https://iam.example.com", managementKey: process.env.IAMKIT_KEY });

const { data, error } = await iam.GET("/management/v1/environments/{environment}/users", {
  params: { path: { environment }, query: { limit: 50 } },
});
if (error) throw new Error(isApiError(error) ? error.error.message : "request failed");
const users: Schema<"PaginatedUser"> = data;
```

- `managementKey` is sent as `X-API-Key` (`/management/v1`).
- `token` (a string or a function called for every request) is sent as a
  bearer token: access tokens for `/api/v1` and `/identity/v1`, `ik_pat_`
  tokens of machine users, SCIM credentials.
- Failures resolve with `error` (IAMKit's `{"error": {code, message, …}}`
  envelope, or the OAuth/SCIM error shapes on those endpoints); network
  errors reject.

Go programs use the hand-written SDKs in `sdk/` instead.

## Development

```sh
make openapi      # regenerate api/openapi.json and src/schema.d.ts
make api-client   # npm ci, generate, test, build
```

The schema is generated from the server's routes and handler source
(`cmd/openapi`); `go test ./cmd/openapi` fails when it is stale, and the e2e
suite validates every request and response it makes against it.
