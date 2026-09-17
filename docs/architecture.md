# Architecture

How IAMKit's Go code is organized, and which rules are machine-enforced versus convention. For
the *runtime* mental model (environments, resources, tokens), see [Concepts](concepts.md) — this
document is about the codebase, for contributors and anyone auditing the implementation.

## Layout

```text
cmd/iamkit/           Server, migration, bootstrap and recovery commands
internal/bootstrap/   Composition root: concrete adapters and configuration
internal/identity/    Shared domain boundaries and validation
internal/iam/         Domain modules, use cases and named adapters (see below)
internal/server/      HTTP route composition and shared error handling
internal/errx/        Classified backend error type, used everywhere inside internal/
internal/architecture/ Machine-enforced dependency-direction tests (see below)
migrations/           Embedded, checksummed, ordered database migrations
sdk/                  Separate Go module: iamclient, authclient (+fiberauth), scimclient, apierror
tests/e2e/            Disposable-database security/functional journeys
```

## Module structure

Each domain under `internal/iam/` follows the same shape — domain types and ports at the top
level, a use-case package, and infrastructure adapters grouped (not packaged) under `adapters/`:

```text
internal/iam/user/
  user.go, ports.go       Domain types and repository/password ports (interfaces)
  usersvc/                Use cases and validation — implements the ports, no infra imports
  adapters/userpg/        PostgreSQL implementation of the repository port
  adapters/userhttp/      Fiber request/response mapping onto the use-case package
```

| Module | Domain/use-case/adapter prefix |
| :--- | :--- |
| `user` | `usersvc`, `userpg`, `userhttp` |
| `organization` | `orgsvc`, `orgpg`, `orghttp` |
| `authentication` | `authsvc`, `authpg`, `authhttp`, `authbcrypt`, `authjwt`, `authmail`, `authsecret` |
| `authorization` | `authzsvc`, `authzpg`, `authzhttp` |
| `federation` | `fedsvc`, `fedpg`, `fedhttp`, `fedoidc` |
| `oauth` | `oauthsvc`, `oauthpg`, `oauthhttp`, `oauthfosite` |
| `provisioning` (SCIM) | `provsvc`, `provpg`, `provhttp` |
| `application` | `appsvc`, `apppg`, `apphttp` |
| `serviceaccount` | `sacctsvc`, `sacctpg`, `saccthttp` |
| `impersonation` | `impsvc`, `imppg`, `imphttp` |
| `management` | `mgmtsvc`, `mgmtpg`, `mgmthttp`, `mgmtsecret` |

`adapters/` is a grouping directory only — it never itself contains a `.go` file
(`TestAdaptersDirectoryIsNotPackage` in `internal/architecture/architecture_test.go` enforces
this at build/test time, not just by convention).

## Dependency direction is machine-enforced

`internal/architecture/architecture_test.go` runs as part of `make test` and statically parses
imports across `internal/iam/`:

- **`TestDomainDependencyDirection`** fails the build if any domain/use-case package (i.e.
  anything under `internal/iam/*` that is *not* inside `adapters/` or a `*module/` package)
  imports: Fiber, `database/sql`, `sqlx`, `lib/pq`, Fosite, `golang.org/x/crypto/bcrypt`,
  `net/http`, or anything under `internal/server`/`internal/bootstrap`. Domain code stays
  infrastructure-agnostic — always test it without a database or HTTP server.
- **`TestModuleAssemblyOnlyUsedByCompositionRoot`** fails the build if any package outside
  `internal/bootstrap/` imports a `*module` assembly package. Wiring concrete adapters together
  happens in exactly one place.
- **`TestAdaptersDirectoryIsNotPackage`** fails the build if `adapters/` itself ever becomes an
  importable Go package rather than a pure grouping directory.

If you add a new module, follow the existing shape — these tests will catch accidental
architectural drift automatically, not just at review time.

## Error handling

Backend code uses `internal/errx` exclusively — a classified error type (`Type`: `INTERNAL`,
`VALIDATION`, `AUTHORIZATION`, `NOT_FOUND`, `CONFLICT`, `BUSINESS`, `EXTERNAL`) that
`internal/server/errors.go` renders into the public envelope
(`{"error":{"code","message","type","http_status"}}`), stripping causes/details for 5xx
responses so internal specifics never leak to clients. The independently-published `sdk/`
module has its own parallel `sdk/apierror` type instead of depending on `internal/errx` — the
SDK must build and be usable without importing anything under `internal/`.

## Composition root

`internal/bootstrap/container.go` is the one place concrete adapters (Postgres, bcrypt, JWT
signer, email webhook, OIDC provider) get wired into the domain use-case packages and handed to
`internal/server` for route registration. `cmd/iamkit/main.go` is a thin CLI wrapper around
`internal/bootstrap` for `migrate`/`bootstrap`/`recover-owner`/serve.

## Modules and versioning

Two independent Go modules: `github.com/Abraxas-365/iamkit` (the server) and
`github.com/Abraxas-365/iamkit/sdk` (the client library). Pin/update them separately. SDK/API
contracts are not guaranteed stable across releases yet — see `README.md#provenance--license`.

## Where to go next

- [Concepts](concepts.md) — the runtime model this code implements.
- [API guide](api.md) — the HTTP surface `internal/server` exposes.
- [SDK reference](sdk.md) — the client surface `sdk/` exposes.
