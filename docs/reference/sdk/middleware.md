# Go middleware (Fiber and net/http)

Two packages protect Go APIs with the same shape: `Authenticate`,
`RequireOrganization` and `RequirePermissions`, and the same JSON error format.
Use `authclient/fiberauth` for Fiber v2 and `authclient/httpauth` for everything
built on `net/http`. Each takes a trusted validator; see the [Go SDK](go.md) and the
[Protect an API](../../start/protect-an-api.md) guide.

## Fiber

Supply a trusted validator:
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

## net/http

Package `authclient/httpauth` is framework-neutral: it only depends on
`net/http`, so it works with the standard library router, chi, gorilla/mux,
or anything else built on `http.Handler` (gin and echo can wrap standard
middleware via their own adapters, e.g. `gin.WrapH`/`echo.WrapMiddleware`).
Use `authclient/fiberauth` instead if the API is built on Fiber v2 — both
packages expose the same `Authenticate`/`RequirePermissions`/
`RequireOrganization` shape and the same JSON error format, so switching
frameworks does not change how you reason about auth.

Supply a trusted validator: `func(context.Context, string) (*authclient.Claims, error)`.
It can call online `Client.Introspect` or offline `authclient.Validate` with
expected configuration.

### Handler wrapping

```go
mux := http.NewServeMux()
mux.Handle("/invoices", httpauth.Authenticate(validate,
    httpauth.RequireOrganization(
        httpauth.RequirePermissions(invoicesHandler, "invoices:read"),
        configuredTenantID,
    ),
))
```

### Middleware chains (chi, gorilla/mux, or any `func(http.Handler) http.Handler` router)

```go
r.Use(httpauth.Middleware(validate))
r.With(
    httpauth.RequireOrganizationMiddleware(configuredTenantID),
    httpauth.RequirePermissionsMiddleware("invoices:read"),
).Get("/invoices", invoicesHandler)
```

Use `httpauth.Claims(r)` in handlers and scope data queries to the validated
tenant. For dynamic organization routes, compare the requested organization
to the claims rather than treating the URL itself as authority.
`RequirePermissions`/`RequirePermissionsMiddleware` require every listed
permission; they do not imply tenant checks — pair them with
`RequireOrganization`/`RequireOrganizationMiddleware`.

Missing/invalid tokens produce 401, mismatched organization or missing
permission 403. Machine tokens have no organization or session; do not run
them through `RequireOrganization`. Test these rejection cases as well as
success; see `sdk/authclient/httpauth/middleware_test.go` and the
framework-neutral [Go example](../../examples/go-api/main.go), which shows
the same enforcement written directly against `net/http` without depending
on this package at all.

### gin and echo

There is no separate `ginauth`/`echoauth` package — both frameworks ship
official adapters for standard `net/http` middleware, so `httpauth` composes
with them directly instead of duplicating the auth logic:

```go
// gin
r.GET("/invoices", gin.WrapH(httpauth.Authenticate(validate,
    httpauth.RequireOrganization(
        httpauth.RequirePermissions(invoicesHandler, "invoices:read"),
        configuredTenantID,
    ),
)))

// echo
e.Use(echo.WrapMiddleware(httpauth.Middleware(validate)))
e.Use(echo.WrapMiddleware(httpauth.RequireOrganizationMiddleware(configuredTenantID)))
e.GET("/invoices", echo.WrapHandler(http.HandlerFunc(invoicesHandler)),
    echo.WrapMiddleware(httpauth.RequirePermissionsMiddleware("invoices:read")))
```

Read claims with `httpauth.Claims(c.Request())` (gin) or
`httpauth.Claims(c.Request())` (echo) inside the wrapped handler.

## API keys

By default both packages reject `ik_key_` bearers, which are not JWTs. Pass the
`AllowAPIKeys` option to accept them next to access tokens: the middleware then
validates a key online on every request through
[`POST /identity/v1/introspect`](../api/identity.md). The validator is
`func(context.Context, string) (authclient.APIKey, error)` (`fiberauth.APIKeyValidator`
/ `httpauth.APIKeyValidator`); pass the `ValidateAPIKey` method of a client built
with [`authclient.WithAudience`](authentication.md#validating-api-keys):

```go
client := authclient.New(iamkitURL, authclient.WithAudience(environmentID, audience))

// Fiber
app.Use(fiberauth.Authenticate(validate, fiberauth.AllowAPIKeys(client.ValidateAPIKey)))

// net/http
mux.Handle("/invoices", httpauth.Authenticate(validate,
    httpauth.RequirePermissions(invoicesHandler, "invoices:read"),
    httpauth.AllowAPIKeys(client.ValidateAPIKey)))
// or, router-level: httpauth.Middleware(validate, httpauth.AllowAPIKeys(client.ValidateAPIKey))
```

For an API key `Claims` is nil: read the request's `Principal`
(`fiberauth.Principal(c)`, `httpauth.Principal(r)`), whose `APIKey` or `Claims`
is set, with the accessors `OrganizationID()`, `Permissions()`,
`HasPermission(p)`, `Owner()` (nil for tokens) and `OrganizationBound(id)`.
`fiberauth.APIKey(c)` / `httpauth.APIKey(r)` return the validated
`*authclient.APIKey` (`Owner`, `Permissions`, `ExpiresAt`, …) or nil.
`RequirePermissions` and `RequireOrganization` accept both principals, with the
key's **effective** permissions, so they work unchanged. Organization keys carry
an organization but no user and no session: pair `RequireOrganization` with your
own check on the owner. The key must have been made for the audience you
configure. A missing validator, a failed validation or a key without an ID is
`401`. See
[API keys](../../guides/machines/api-keys.md#validate-keys-in-your-backend).

