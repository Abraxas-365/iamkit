# Fiber middleware

Package `authclient/fiberauth` targets Fiber v2. Supply a trusted validator:
`func(context.Context, string) (*authclient.Claims, error)`. It can call online
`Client.Introspect` or offline `authclient.Validate` with expected configuration.

Middleware order:

```go
app.Get("/invoices",
    fiberauth.Authenticate(validate),
    fiberauth.RequireOrganization(configuredTenantID),
    fiberauth.RequirePermissions("invoices:read"),
    handler,
)
```

This is a wiring fragment, not a standalone program. Use
`fiberauth.Claims(c)` in handlers and scope data queries to the validated tenant.
For dynamic organization routes, compare the requested organization to the claims
rather than treating the URL itself as authority. `RequirePermissions` requires
all specified exact strings; it does not imply tenant checks.

Missing/invalid tokens produce 401, mismatched organization or missing permission
403. Machine tokens do not pass user-organization middleware. Test these rejection
cases as well as success; see the framework-neutral
[Go example](../../examples/go-api/main.go).
