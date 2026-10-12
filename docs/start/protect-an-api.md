# Protect an API

Use IAMKit's trusted token checks to protect a tenant-scoped invoice endpoint.
This example accepts Alice's Acme request and rejects the same token for another
organization.

## Before you begin

Complete [your first application](first-application.md). You need Go 1.26.6,
jq, and the `.dev-secrets/invoicecloud.json` output from that example. The local
Go SDK example uses online introspection and binds expected values from trusted
configuration.

<a id="run-the-go-example"></a>

## 1. Run the Go example

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

## 2. Call the protected endpoint

Keep `go run .` running. From another terminal at the repository root:

```sh
TOKEN=$(jq -r .access_token .dev-secrets/invoicecloud.json)
ORG=$(jq -r .organization_id .dev-secrets/invoicecloud.json)
OTHER=$(jq -r .other_organization_id .dev-secrets/invoicecloud.json)
curl --fail "http://127.0.0.1:8090/organizations/$ORG/invoices" -H "Authorization: Bearer $TOKEN"
curl -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8090/organizations/$OTHER/invoices" -H "Authorization: Bearer $TOKEN"
```

**Check:** the first request returns 200 with an empty invoice collection; the
second prints 403. A missing or expired token produces 401. This API deliberately
has no invoice storage; real database queries must also constrain
`organization_id` to the validated tenant.

<a id="online-versus-offline"></a>

## 3. Choose your validation strategy

Authenticating a user and authorizing an invoice request are separate checks:
validate issuer, signature or online trust, audience, environment, application,
resource, token purpose, organization, and exact permissions. Never accept an ID
token as an API access token or choose expected boundaries from untrusted claims.

### Online introspection

Online introspection checks current session, account, and grant state; if IAMKit
is unreachable, fail closed. Do not silently fall back to decoding JWT payloads.

### Offline validation
Offline validation uses the issuer's trusted JWKS (`authclient.NewKeySet` +
`ValidateWithKeySet` follow [key rotations](../guides/applications/signing-keys.md)) and validates RS256,
expiry and expected boundaries. It avoids a network request per API call but
cannot observe revocation until expiry. Define key-cache refresh and failure policy.

The SDK's `authclient.Validate` checks environment/app/resource and purpose, but
**you still must compare organization IDs**. Fiber users can compose
`Authenticate`, `RequirePermissions("invoices:read")` and
`RequireOrganization(trustedOrganizationID)` from `authclient/fiberauth`.
Any other Go HTTP stack (stdlib `net/http`, chi, gorilla/mux, or gin/echo via
their standard-middleware adapters) can compose the same three checks from
`authclient/httpauth` — see [net/http middleware](../reference/sdk/middleware.md#nethttp).
Do not hardcode a tenant from a request parameter without comparing it to
claims.

Impersonated tokens include `actor_id`; restrict sensitive actions if your policy
requires. Machine tokens have no organization or user session: give them separate
routes/policies rather than pretending they are tenant-user tokens.

## Next steps

Continue with [application integration](../guides/applications/application-integration.md)
to choose hosted or custom sign-in. For other runtimes, use the
[SDK guide](../reference/sdk/index.md); for troubleshooting token failures, see
[errors and pagination](../reference/errors-and-pagination.md).

Source: [example](../examples/go-api/main.go), `sdk/authclient/validator.go`,
`sdk/authclient/fiberauth/middleware.go` and `sdk/authclient/httpauth/middleware.go`.
