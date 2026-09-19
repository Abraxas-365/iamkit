# Protect an API

Authenticating a user and authorizing an invoice request are different checks.
Validate issuer, signature/online trust, audience, environment, application,
resource, token purpose, organization and exact permissions. Never accept an ID
token as an API access token or choose expected boundaries from untrusted claims.

## Run the Go example

Complete [first application](../start/first-application.md). The example uses the
local Go SDK module and online introspection, binding expected values from trusted
configuration. Go 1.26.6 is required by this checkout.

```sh
export IAMKIT_URL=http://localhost:8080 JWT_ISSUER=http://localhost:8080
export ENVIRONMENT_ID=$(jq -r .environment_id .dev-secrets/invoicecloud.json)
export APPLICATION_ID=$(jq -r .application_id .dev-secrets/invoicecloud.json)
export RESOURCE_ID=$(jq -r .resource_id .dev-secrets/invoicecloud.json)
export AUDIENCE=$(jq -r .audience .dev-secrets/invoicecloud.json)
cd docs/examples/go-api
go mod tidy
go run .
```

From another terminal at the repository root:

```sh
TOKEN=$(jq -r .access_token .dev-secrets/invoicecloud.json)
ORG=$(jq -r .organization_id .dev-secrets/invoicecloud.json)
OTHER=$(jq -r .other_organization_id .dev-secrets/invoicecloud.json)
curl --fail "http://127.0.0.1:8090/organizations/$ORG/invoices" -H "Authorization: Bearer $TOKEN"
curl -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8090/organizations/$OTHER/invoices" -H "Authorization: Bearer $TOKEN"
```

Expected: first request 200 with an empty invoice collection, second request 403.
A missing/expired token produces 401. This API deliberately has no invoice storage;
real database queries must also constrain `organization_id` to the validated tenant.

## Online versus offline

Online introspection checks current session, account and grant state; if IAMKit is
unreachable, fail closed. Do not silently fall back to decoding JWT payloads.
Offline validation uses the issuer's trusted JWKS/RSA key and validates RS256,
expiry and expected boundaries. It avoids a network request per API call but
cannot observe revocation until expiry. Define key-cache refresh and failure policy.

The SDK's `authclient.Validate` checks environment/app/resource and purpose, but
**you still must compare organization IDs**. Fiber users can compose
`Authenticate`, `RequirePermissions("invoices:read")` and
`RequireOrganization(trustedOrganizationID)` from `authclient/fiberauth`.
Any other Go HTTP stack (stdlib `net/http`, chi, gorilla/mux, or gin/echo via
their standard-middleware adapters) can compose the same three checks from
`authclient/httpauth` — see [net/http middleware](../reference/sdk/http.md).
Do not hardcode a tenant from a request parameter without comparing it to
claims.

Impersonated tokens include `actor_id`; restrict sensitive actions if your policy
requires. Machine tokens have no organization or user session: give them separate
routes/policies rather than pretending they are tenant-user tokens.

Source: [example](../examples/go-api/main.go), `sdk/authclient/validator.go`,
`sdk/authclient/fiberauth/middleware.go` and `sdk/authclient/httpauth/middleware.go`.
