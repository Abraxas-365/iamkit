# net/http middleware

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

## Handler wrapping

```go
mux := http.NewServeMux()
mux.Handle("/invoices", httpauth.Authenticate(validate,
    httpauth.RequireOrganization(
        httpauth.RequirePermissions(invoicesHandler, "invoices:read"),
        configuredTenantID,
    ),
))
```

## Middleware chains (chi, gorilla/mux, or any `func(http.Handler) http.Handler` router)

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

## gin and echo

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
