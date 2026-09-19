# AGENTS.md — IAMKit Architecture & Coding Guidelines

This document is the single source of truth for architectural decisions.
Every rule here reflects code that compiles and ships today. Do not add
aspirational patterns — update this file when the code changes.

---

## Project Structure

```
cmd/iamkit/              CLI entry point
internal/
  bootstrap/             Composition root — only place concrete types are wired
  config/                Constants (TTLs, limits)
  errx/                  Typed application errors (the only error system)
  httpx/                 Shared HTTP utilities (pagination)
  identity/              Typed IDs, domain primitives, validation helpers
  logx/                  Structured logging
  ptrx/                  Pointer helpers
  console/               Embedded SPA assets
  server/                Fiber server, route registration, error middleware
    apiauth/             JWT authentication middleware for /api/v1/*
  iam/
    <module>/            Domain package (structs + interfaces)
      adapters/
        <mod>http/       Fiber HTTP handlers
        <mod>pg/         PostgreSQL repositories (sqlx)
        <mod>*           Other adapters (bcrypt, jwt, oidc, fosite, mail, secrets)
      <mod>svc/          Service (use-case orchestration)
      <mod>module/       Module assembler (wires adapters → service → ports)
```

### Module Inventory

| Module | Domain package | Purpose |
|--------|---------------|---------|
| application | `internal/iam/application` | OAuth/OIDC application registration |
| authentication | `internal/iam/authentication` | Password login, sessions, refresh tokens, challenges |
| authorization | `internal/iam/authorization` | Resources, roles, grants, role assignments |
| federation | `internal/iam/federation` | External OIDC identity provider connections |
| impersonation | `internal/iam/impersonation` | Audited admin impersonation |
| management | `internal/iam/management` | Workspaces, projects, environments, operators, keys |
| oauth | `internal/iam/oauth` | OAuth2/OIDC server (authorization code + PKCE) |
| organization | `internal/iam/organization` | Organizations, memberships, org units, positions |
| provisioning | `internal/iam/provisioning` | SCIM user provisioning |
| serviceaccount | `internal/iam/serviceaccount` | Machine-to-machine credentials |
| user | `internal/iam/user` | End-user CRUD |

---

## Ports & Adapters (Hexagonal Architecture)

Every module follows the same four-package layout:

```
<module>/
  ports.go           Interfaces only — Commands, Queries, Repository
  <entity>.go        Domain structs, Validate() methods, Mutation, constants
  adapters/
    <mod>http/       Inbound adapter — HTTP handlers (Fiber)
    <mod>pg/         Outbound adapter — PostgreSQL (sqlx)
  <mod>svc/          Service — implements Commands/Queries, depends on Repository interface
  <mod>module/       Assembler — New(Deps) Module, returns interface values
```

### Interface Segregation: Commands, Queries, Repository

Every module in `ports.go` defines **three interface roles**:

```go
// Commands — write operations exposed to handlers and other modules.
type Commands interface {
    Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.ApplicationID, error)
    Update(ctx context.Context, m Mutation, applicationID identity.ApplicationID, input Update) error
}

// Queries — read operations exposed to handlers and other modules.
type Queries interface {
    Find(ctx context.Context, environment identity.EnvironmentID, applicationID identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
}

// Repository — persistence contract consumed only by the service.
type Repository interface {
    Create(ctx context.Context, environment identity.EnvironmentID, applicationID identity.ApplicationID, input Create) error
    Find(ctx context.Context, environment identity.EnvironmentID, applicationID identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
    Update(ctx context.Context, m Mutation, applicationID identity.ApplicationID, input Update) error
}
```

**The three roles serve different consumers:**

| Interface | Implemented by | Consumed by |
|-----------|---------------|-------------|
| `Commands` | Service | HTTP handlers, other modules |
| `Queries` | Service | HTTP handlers, other modules |
| `Repository` | PG adapter | Service only |

**Key differences between Commands and Repository:**

- **Commands generate IDs** — `Create` returns `(identity.ApplicationID, error)`.
  The service calls `identity.NewApplicationID()` and passes it down.
- **Repository receives IDs** — `Create` takes the ID as a parameter and
  returns only `error`. It never generates identifiers.
- **Commands validate** — the service calls `input.Validate()` before
  delegating. The repository trusts the service layer.

**The service implements both Commands and Queries** with a compile-time check:

```go
var _ application.Commands = (*Service)(nil)
var _ application.Queries = (*Service)(nil)
```

**Modules with sub-domains** split further. Authorization has separate
`ResourceCommands`/`ResourceQueries` and `GrantCommands`/`GrantQueries`.
Organization has `StructureCommands`/`StructureQueries`. Management has
`ControlCommands`/`ControlQueries` and `ActivityCommands`/`ActivityQueries`.

**The module assembler** exposes only interface types, never the concrete service:

```go
type Module struct {
    Commands application.Commands
    Queries  application.Queries
    HTTP     *apphttp.Handler
}

func New(deps Deps) Module {
    service := appsvc.New(apppg.New(deps.DB))
    return Module{
        Commands: service,
        Queries:  service,
        HTTP:     apphttp.New(service, service, deps.ActorID),
    }
}
```

The HTTP handler constructor takes `Commands` and `Queries` as separate
parameters — it never sees `*Service` or `Repository`.

### Additional Port Interfaces

Beyond the core three, modules define additional interfaces for
infrastructure concerns that should be swappable:

| Interface | Module | Purpose |
|-----------|--------|---------|
| `Passwords` | authentication, management | `Hash(string) (string, error)`, `Compare(string, string) bool` |
| `Secrets` | authentication, federation, oauth, provisioning, serviceaccount | Token/key generation and hashing |
| `Delivery` | authentication | Send verification codes (email webhook) |
| `Provider` | federation | OIDC provider discovery and credential approval |
| `TokenCodec` | authentication | JWT sign/parse (combines `TokenIssuer` + `TokenValidator`) |
| `Transaction` | authentication, oauth | Database transaction handle for multi-step mutations |

These follow the same rule: defined in `ports.go`, implemented by adapters,
consumed by services.

### Rules

1. **`ports.go` contains only interfaces.** No structs, no constants, no
   `Validate()` methods. One file, predictable location.

2. **Domain files are named after the aggregate**, not `models.go` or `types.go`:
   `resource.go`, `grant.go`, `connection.go`, `credential.go`, etc.

3. **Domain structs own their validation.** Every create/update struct gets
   `Validate() error` on a value receiver. One field → one error message.

4. **Services are thin orchestrators.** They call `input.Validate()`, generate
   IDs, enforce cross-entity invariants, and delegate to the repository.

5. **Adapters never import other adapters** (except `authpg.Resolve` which is
   shared SQL reused by `fedpg` and `oauthpg` for session resolution).

6. **Module assemblers are the only place** where concrete adapter types appear
   together. They return a `Module` struct with interface-typed fields.

7. **The composition root** (`internal/bootstrap/container.go`) calls module
   assemblers and wires cross-module dependencies (e.g. authentication sessions
   into federation).

### Interface Parameter Naming

Interface methods **must** name every parameter. Bare positional types are
not allowed — they are unreadable at the call site:

```go
// ✗ Bad
LinkApplication(context.Context, string, string, string) error

// ✓ Good
LinkApplication(ctx context.Context, environment identity.EnvironmentID,
    applicationID identity.ApplicationID, resourceID identity.ResourceID) error
```

Naming conventions:
- `ctx context.Context` — always first.
- ID parameters: `environmentID`, `applicationID`, `userID`, `sessionID`, etc.
  Exception: `environment` (shorter, established throughout codebase).
- Non-ID strings: `email`, `password`, `name`, `role`, `code`, `purpose`.
- Struct parameters: `p Principal`, `m Mutation`, `b Boundary`, `input Create`.

---

## `identity` — The Foundation Package

`internal/identity/` is the lowest-level application package. It defines
**what identities are** — ID types, format validators, domain primitives.

### Dependency Rule

`identity` imports only `errx` and external libraries (`uuid`). It **never**
imports anything from `internal/iam/`. Every domain and adapter package imports
`identity`. This makes it the foundation of the type system.

```
stdlib → errx → identity → every domain package → adapters
```

### Typed IDs: `ID[T any]`

All entity identifiers use `identity.ID[T]`, a generic struct wrapping
`uuid.UUID` with a phantom type tag for compile-time discrimination:

```go
type ID[T any] struct{ v uuid.UUID }

// 20 entity types, each with an unexported tag:
type environmentTag struct{}
type userTag        struct{}
// ...

// Public aliases — these are the types used everywhere:
type EnvironmentID  = ID[environmentTag]
type UserID         = ID[userTag]
// ...
```

**Why this design:**
- Compile-time safety: `UserID` and `OrganizationID` cannot be mixed.
- Zero runtime cost: phantom tags are `struct{}`, aliases avoid wrapper overhead.
- Unexported tags: external packages cannot construct arbitrary IDs — they must
  use `ParseXID()` or `NewXID()`.

**API per entity type** (20 sets):
- `NewUserID() UserID` — generate new UUID
- `ParseUserID(raw string) (UserID, error)` — validation boundary
- `MustParseUserID(raw string) UserID` — panics, for tests/static init

**Methods on `ID[T]`:**
- `String() string` — canonical lowercase UUID
- `IsZero() bool` — true for zero value (replaces `id == ""` checks)
- `UUID() uuid.UUID` — unwrap when needed
- `MarshalText() / UnmarshalText()` — JSON support
- `Value() / Scan()` — database/sql support (sqlx struct tags work directly)

**Where parsing happens:**
- HTTP handlers: `identity.ParseUserID(c.Params("id"))` at the boundary
- JWT codec: `mustParseX` helpers at sign/parse boundary
- Services receive typed IDs — no parsing needed

### Other `identity` Exports

| Function | Purpose |
|----------|---------|
| `Email(string) (string, error)` | Normalize + validate email |
| `ValidatePermissions([]string, prefix)` | Permission catalog validation |
| `ValidatePrefix(string)` | Resource prefix format |
| `ValidateRedirects([]string)` | OAuth redirect URI validation |
| `Subset(requested, catalog []string)` | Permission subset check |
| `ParseTTL(*string) (time.Duration, error)` | Credential TTL parsing |

These are **pure validation functions**, not types. Email is a `string` because
there is only one kind of email — no discrimination problem to solve.

### Shared Domain Structs

`identity.User`, `identity.Membership`, `identity.Access` live in `identity`
because they cross module boundaries (authentication, federation, provisioning
all reference them).

---

## `errx` — The Error System

`internal/errx/` is the **only** error system. Every error in the application
is either an `*errx.Error` or gets wrapped into one before leaving a package.

### Error Types

| Type | HTTP Status | When to use |
|------|------------|-------------|
| `errx.Validation(msg)` | 400 | Bad input from client |
| `errx.Unauthorized(msg)` | 401 | Invalid credentials or token |
| `errx.Forbidden(msg)` | 403 | Valid identity, insufficient permissions |
| `errx.NotFound(msg)` | 404 | Entity does not exist |
| `errx.Conflict(msg)` | 409 | Unique constraint / state conflict |
| `errx.Business(msg)` | 422 | Domain rule violation |
| `errx.Internal(msg)` | 500 | System error (database, IO) |
| `errx.External(msg)` | 502 | Upstream service failure |
| `errx.Wrap(err, msg, type)` | varies | Wrap a cause with context |

### Rules

1. **Every package boundary wraps errors.** Repository methods wrap database
   errors: `errx.Wrap(err, "persistence failed", errx.TypeInternal)`. Services
   return `errx.Validation` for input errors, delegate persistence errors as-is.

2. **The HTTP error middleware** (`internal/server/errors.go`) converts
   `*errx.Error` to JSON responses. It **never** exposes wrapped causes or
   internal details to the client. 500s get a generic message.

3. **`identity` uses `errx`** for all parse/scan/unmarshal errors. This ensures
   a `ParseUserID` failure at the HTTP boundary produces a proper 400, not a
   bare `fmt.Errorf` that would become a 500.

4. **One field → one error message.** Never return "invalid request" for
   multiple fields. Validation errors name the specific field.

---

## Domain Validation Pattern

### `Validate() error` on Domain Structs

Every create/update input struct gets a `Validate() error` method in its
domain file (not in the service):

```go
// application.go
func (c Create) Validate() error {
    if strings.TrimSpace(c.Name) == "" {
        return errx.Validation("application name is required")
    }
    return nil
}
```

Rules:
- Value receiver (no mutation).
- Only validates structural invariants the struct owns (non-empty, format).
- Cross-entity checks (permissions ⊆ catalog, prefix enforcement) stay in services.
- `Update` structs with `*T` fields validate only non-nil fields.
- ID fields are typed (`identity.XID`) so they don't need UUID format validation.

### Where Validation Happens

| Layer | Validates |
|-------|-----------|
| HTTP handler | Parses path/query params via `identity.ParseXID()` |
| Domain struct | `input.Validate()` — field format, required fields |
| Service | Cross-entity rules, business invariants |
| Repository | Nothing — trusts the service layer |

---

## HTTP Adapter Pattern

Every `<mod>http/handler.go` follows the same structure:

```go
type Handler struct {
    commands module.Commands
    queries  module.Queries
    actor    func(*fiber.Ctx) string
}

// env parses the environment path parameter (every handler has this).
func env(c *fiber.Ctx) identity.EnvironmentID {
    id, _ := identity.ParseEnvironmentID(c.Params("environment"))
    return id
}
```

- Parse IDs at the boundary: `identity.ParseXID(c.Params("id"))`
- Return `errx.Validation` / `errx.NotFound` on parse failure
- Delegate to service — never contain business logic
- JSON binding via `c.BodyParser(&input)`

---

## PostgreSQL Adapter Pattern

Every `<mod>pg/repository.go`:

```go
type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

// Package-level error wrappers
func failure(err error) error { /* wraps with errx.TypeInternal */ }
func conflict(err error) error { /* detects pq constraint violations → errx.Conflict */ }
```

- Scan structs use typed ID fields directly (`identity.UserID` with `db:"id"`)
  because `ID[T]` implements `sql.Scanner`.
- Query parameters use typed IDs directly because `ID[T]` implements
  `driver.Valuer`.
- `var _ module.Repository = (*Repository)(nil)` — compile-time interface check.

---

## Authentication & JWT

Two separate authentication systems exist:

| System | Audience | Transport | Package |
|--------|----------|-----------|---------|
| Application auth | End users | JWT (RS256) | `authentication/`, `apiauth/` |
| Management auth | Operators | Secret-hash / session cookie | `management/` |

**JWT claims use strings** (wire format). Conversion to/from typed IDs happens
at the `Sign`/`parse` boundary in `authjwt/codec.go`:

```go
// Sign: typed ID → string
claims.SessionID = issued.Session.String()

// Parse: string → typed ID
session, err := identity.ParseSessionID(claims.SessionID)
```

**`apiauth` middleware** (`internal/server/apiauth/`) validates JWTs and
sets `identity.EnvironmentID` on the Fiber context. `apiauth.Environment(c)`
returns a typed ID. The middleware compares the JWT's environment against the
path parameter — both are typed, so mismatches are caught at compile time.

---

## Mutation & Audit Trail

Modules that support audited mutations define a `Mutation` struct:

```go
type Mutation struct {
    Environment identity.EnvironmentID
    Actor       string
    Action      string
    Target      string
}
```

Repository methods accept `Mutation` and insert into `audit_events` within the
same transaction as the data change. The HTTP handler constructs `Mutation`
from the authenticated context.

---

## External Dependencies

| Dependency | Purpose | Import boundary |
|-----------|---------|-----------------|
| `github.com/gofiber/fiber/v2` | HTTP framework | `*http/` adapters + `server/` only |
| `github.com/jmoiron/sqlx` | SQL extensions | `*pg/` adapters + `bootstrap/` only |
| `github.com/lib/pq` | PostgreSQL driver | `*pg/` adapters + `server/errors.go` |
| `github.com/google/uuid` | UUID generation | `identity/` only |
| `github.com/golang-jwt/jwt/v5` | JWT signing/parsing | `authjwt/` only |
| `github.com/ory/fosite` | OAuth2 server | `oauthfosite/` only |
| `github.com/coreos/go-oidc/v3` | OIDC discovery | `fedoidc/` only |

**Rule:** Domain packages and services never import framework types. They
depend only on `identity`, `errx`, and stdlib.

---

## What NOT to Change

- **Don't add a `Validate()` to repository/adapter code** — they don't validate.
- **Don't move validation helpers** (`Email`, `ValidatePermissions`, etc.) out
  of `identity` — they are shared primitives.
- **Don't make email a type** — there's only one kind of email, no discrimination
  problem. `identity.Email()` is a parse function that returns a clean `string`.
- **Don't rename `identity` to `kernel`/`core`/`base`** — Go names packages
  after content, not architectural role. `identity.UserID` reads correctly;
  `kernel.UserID` does not.
- **Don't import domain packages into `identity`** — it must remain the
  dependency graph leaf.
- **Don't use `fmt.Errorf` for application errors** — always use `errx`. The
  HTTP error middleware only understands `*errx.Error`.
- **Don't merge Commands and Queries into one interface** — they serve different
  consumers and may diverge (e.g. queries could be served from a read replica).
- **Don't let Repository generate IDs** — ID generation is a service
  responsibility. The repository receives the ID and persists it.
