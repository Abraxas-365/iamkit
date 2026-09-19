# Go SDK

The SDK is a separate module at `github.com/Abraxas-365/iamkit/sdk`. Pin a verified
SDK release/pseudo-version compatible with your backend; do not assume the root
module's version imports it. In this checkout the runnable example uses a local
`replace` to `../../../sdk` and can be built without a published SDK release.

| Package | Purpose |
| --- | --- |
| `iamclient` | Workspace management via X-API-Key |
| `apiclient` | Permission-scoped `/api/v1` via JWT |
| `authclient` | Identity login/challenges/token checks and OAuth helpers |
| `authclient/fiberauth` | Fiber v2 authorization middleware |
| `scimclient` | Scoped SCIM user operations |
| `apierror` | Structured ordinary API errors |

Pass a context with a deadline and an HTTP client with a timeout. The shared
transport refuses credential-carrying redirects, caps decoded response bodies at
1 MiB and decodes ordinary error envelopes. It does not automatically retry writes
or refresh tokens. Handle 204 without decoding a body.

**Current compatibility note:** typed management/scoped list helpers still decode
into slices while several backend lists return `{items,page}`. Use a matching
response DTO through a supported low-level call/direct HTTP until the typed
method matches the server. Do not ignore decode errors or assume unit mock tests
prove live response compatibility. `iamclient.Do` rejects query strings in its
path; filtered/paginated requests may require direct HTTP with URL encoding.

See [management](management.md), [authentication](authentication.md),
[Fiber](fiber.md), [SCIM](scim.md) and the
[compilable API example](../../examples/go-api/main.go).

Build/test the SDK independently: `cd sdk && go test ./... && go vet ./...`.
