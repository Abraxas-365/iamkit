# OpenAPI document and TypeScript client

IAMKit publishes an OpenAPI 3.1 description of its HTTP API at
`GET /openapi.json` (public, like OIDC discovery). It covers
`/management/v1`, `/api/v1`, `/identity/v1`, `/scim/v2`, `/oauth/*`,
`/.well-known/*` and `/health`; the hosted pages (`/hosted`, `/org-admin`), the
SAML identity provider (`/saml`) and the console are browser surfaces and are
not described.

```sh
curl -s https://iam.example.com/openapi.json | jq '.paths | keys | length'
```

The same file is in the repository at `api/openapi.json`. To browse it, point
any OpenAPI viewer at it, for example:

```sh
npx @redocly/cli preview-docs api/openapi.json
# or
docker run -p 8081:8080 -e SWAGGER_JSON=/spec/openapi.json -v "$PWD/api:/spec" swaggerapi/swagger-ui
```

## How it stays correct

The document is generated, not maintained by hand: `make openapi` runs
`cmd/openapi`, which assembles the server exactly as it runs, lists its routes
and reads each handler's source with `go/types` — path parameters, the
`BodyParser` target, `Query` names, every `JSON`/`SendStatus`/`Redirect`
answer with its status, and the Go types they serialize (following
`encoding/json` tags). Then:

- `go test ./cmd/openapi` fails when the committed file differs from what the
  code produces;
- the e2e suite validates **every request and response it makes** against the
  document (kin-openapi), so a response that does not match its schema, or a
  route the document lacks, fails the suite. The run prints how many
  documented operations it exercised (`IAMKIT_OPENAPI_COVERAGE=1` lists the
  rest).

What the document deliberately leaves loose:

- **Request bodies list every accepted field but mark none required** — the
  server checks required fields and answers 400 naming the field (see
  [errors](../errors-and-pagination.md)).
- **Errors**: every `/management/v1`, `/api/v1` and `/identity/v1` operation
  documents `4XX`/`5XX` with the `{"error": {...}}` envelope (`Error`
  schema). OAuth endpoints use RFC 6749 `{"error": "..."}` bodies and SCIM
  uses RFC 7644 error resources.
- A few answers are produced outside IAMKit's own code (fosite's token and
  introspection bodies, streamed exports); those are documented without a
  body schema.

Operation ids are derived from method and path
(`getManagementEnvironmentsbyEnvironmentApplications`) and change only when the
route does.

## TypeScript client

`clients/typescript` is the `@iamkit/api` package: types generated with
`openapi-typescript`, requests through `openapi-fetch`.

```ts
import { createIAMKitClient } from "@iamkit/api";

const iam = createIAMKitClient({ baseUrl: "https://iam.example.com", managementKey: process.env.IAMKIT_KEY });
const { data, error } = await iam.POST("/management/v1/environments/{environment}/users", {
  params: { path: { environment } },
  body: { email: "ada@example.com", name: "Ada" },
});
```

`managementKey` is sent as `X-API-Key`; `token` (string or function) as a
bearer token for `/api/v1`, `/identity/v1` and SCIM. See
[the package README](../../../clients/typescript/README.md).

Go services keep using the hand-written SDKs in `sdk/`
([Go SDK reference](../sdk/go.md)). gRPC/Connect APIs are not planned.
