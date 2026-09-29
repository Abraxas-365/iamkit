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
  httpx/                 HTTP-specific helpers (parse pagination from Fiber ctx)
  i18n/                  End-user text catalogs (locales/<code>.json), Resolve/T/Date — stdlib only
  identity/              Typed IDs, domain primitives, validation helpers
  netx/                  Guarded dialing to operator-supplied hosts (public addresses only)
  query/                 Pagination types (Pagination, Paginated[T]) — transport-agnostic
  logx/                  Structured logging
  ptrx/                  Pointer helpers
  console/               Embedded SPA assets
  server/                Fiber server, route registration, error middleware
    apiauth/             JWT authentication middleware for /api/v1/*
  iam/
    <module>/            Domain package (structs + interfaces + filters)
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
| authorization | `internal/iam/authorization` | Resources, roles, grants, role assignments, group role assignments |
| federation | `internal/iam/federation` | External OIDC identity provider connections |
| hosted | `internal/iam/hosted` | Server-rendered hosted sign-in/invitation pages for `hosted_login` OAuth clients, login branding |
| impersonation | `internal/iam/impersonation` | Audited admin impersonation |
| invitation | `internal/iam/invitation` | Email invitations into organizations (token issue, preview, accept) |
| management | `internal/iam/management` | Workspaces, projects, environments, operators, keys |
| mfa | `internal/iam/mfa` | Second factors (TOTP), recovery codes, pending MFA logins, per-organization MFA policy |
| oauth | `internal/iam/oauth` | OAuth2/OIDC server (authorization code + PKCE) |
| organization | `internal/iam/organization` | Organizations, memberships, org units, positions, groups, verified domains |
| provisioning | `internal/iam/provisioning` | SCIM user and group provisioning |
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
    Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
}

// Queries — read operations exposed to handlers and other modules.
type Queries interface {
    Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
}

// Repository — persistence contract consumed only by the service.
type Repository interface {
    Create(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, input Create) error
    Find(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID) (Application, error)
    List(ctx context.Context, environment identity.EnvironmentID) ([]Application, error)
    Update(ctx context.Context, m Mutation, application identity.ApplicationID, input Update) error
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
`ResourceCommands`/`ResourceQueries`/`ResourceRepository` and
`GrantCommands`/`GrantQueries`/`GrantRepository`.
Organization has `StructureCommands`/`StructureQueries`,
`GroupCommands`/`GroupQueries`/`GroupRepository` and
`DomainCommands`/`DomainQueries`/`DomainRepository` (plus the `Resolver` DNS
port, adapter `orgdns`, replaceable in tests via `bootstrap.WithResolver`);
provisioning has the same trio for SCIM groups. Federation's `fedoidc` adapter
dials providers through `GuardedTransport` (public addresses only, via
`netx.GuardedDialer`) for
sealed-secret connections; tests replace it via
`bootstrap.WithFederationTransport`. Authentication has
`DeliveryConfigCommands`/`DeliveryConfigQueries`/`DeliveryConfigRepository`
(per-environment email delivery; secrets sealed with `Cipher`, never returned)
and `TemplateCommands`/`TemplateQueries`/`TemplateRepository` (email wording
overrides per purpose × language, text only — `Copy` with `{{placeholders}}`,
no HTML). Its `authmail` SMTP/Resend/webhook adapters dial environment providers
through `netx.GuardedDialer` (webhooks also sign requests per Standard
Webhooks, `authmail.SignWebhook`); the deployment-wide provider (`EMAIL_PROVIDER`,
read in `bootstrap/mail.go`) may reach private hosts; tests override both via
`bootstrap.WithMail` (`Dial`, `ResendClient`, `WebhookClient`), and the
development-only `IAMKIT_ALLOW_PRIVATE_DELIVERY` sets `Dial`/`WebhookClient`
to unguarded ones (warning logged). Management has
`ControlCommands`/`ControlQueries` and `ActivityCommands`/`ActivityQueries`.
Method names still use standard verbs (`Create`, `List`, `Find`). When a
single Queries/Repository interface manages multiple entity types, prefix the
verb with the entity: `ListRoles`, `ListGrants` — the verb always leads.

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
| `Delivery` | authentication | Send challenge codes and invitations (`Message`); per environment a webhook, SMTP or Resend configuration (`DeliveryConfig.Provider`), else the global one |
| `Mailer` / `Renderer` / `Branding` | authentication | Send a rendered `Email` (SMTP, Resend); render a `Message` in the environment's `Brand` and language (`internal/i18n`); read that brand |
| `Mailer` | invitation | Send invitation mail and build links; `invmail` adapts authentication delivery |
| `Provider` | federation | OIDC provider discovery and credential approval |
| `Flows` | federation | Browser login flows (`Discover`, `Start`, `StartHosted`, `Callback`, `EnvironmentConnections`), separate from Commands/Queries. `Callback` returns an `Outcome`: a session, or for hosted starts (`Continuation` = OAuth ticket) only the `Verified` identity |
| `Authenticator` | authentication | Verify a credential without a session (`VerifyPassword`, `VerifyCode` → `Verified`), list accessible `Organizations`, then `Issue` the session once the organization is chosen (re-checks SSO enforcement) |
| `Flow` | hosted | The hosted sign-in journey; consumes the `Authorizations` (pending OAuth ticket), `Challenges`, `Federation`, `Invitations` and `SecondFactor` ports declared in `hosted/ports.go` plus `authentication.Authenticator`. The parked `hosted.Login{Verified, Chosen, Attempts}` carries state between pages; `hostedsvc.step` orders: MFA first for an enrolled user with several organizations (non-SSO logins; a factor applies in all of them) → chooser → MFA/enrollment for the chosen organization → `Issue`. Second-factor tries are reserved atomically (`Repository.Attempt`) before the code is checked |
| `SecondFactor` | authentication | Login-time MFA (`Requirement`, `Begin`, `Complete`, `Enroll`), implemented by `mfasvc` (`mfa.Logins`). `Login`/`VerifyChallenge` return `authentication.Result{Issued, MFA}`: `SignIn` commits the credential transaction, then either issues the session or parks a pending `ik_mfa_` login. `authhttp.Respond` renders either shape; federation receives it as the injected `Respond` closure |
| `Logins` | mfa | Everything login flows need from mfa (headless pending logins + hosted `Verify`/`Enrolling` without a pending token) |
| `TOTP` | mfa | RFC 6238 codes/URIs (`mfatotp`, stdlib only, RFC test vectors) |
| `Cipher` | authentication, federation, mfa | Seal/open stored secrets (SMTP password / Resend API key, client secrets, TOTP secrets); implemented by `internal/cryptox.Sealer` (`IAMKIT_ENCRYPTION_KEY`), injected via `bootstrap.WithSealer` |
| `TokenCodec` | authentication | JWT sign/parse (combines `TokenIssuer` + `TokenValidator`) |
| `Transaction` | authentication, invitation, mfa, oauth | Database transaction handle for multi-step mutations |

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
   into federation). Cycles between HTTP adapters are closed there with a
   setter: `fedhttp.Handler.Continue(hostedhttp.Handler.Federated)` lets the
   federation callback resume a hosted login, and the hosted module receives
   `oauthhttp.Handler.Finish` to complete the authorization.

8. **Hosted pages** (`hostedhttp`) are server-rendered `html/template` files
   embedded from `templates/`, without JavaScript. Every page sets its own CSP
   with a per-response style nonce; `internal/server/hosted.go` mounts them
   under `/hosted` with frame/referrer headers and per-route rate limits.
   Every form action re-validates the OAuth ticket and its binding cookie.

### Interface Parameter Naming

Interface methods **must** name every parameter. Bare positional types are
not allowed — they are unreadable at the call site:

```go
// ✗ Bad — unnamed, unreadable
LinkApplication(context.Context, identity.EnvironmentID, identity.ApplicationID, identity.ResourceID) error

// ✓ Good — short names, the type carries the "ID" semantics
LinkApplication(ctx context.Context, environment identity.EnvironmentID,
    application identity.ApplicationID, resource identity.ResourceID) error
```

Naming conventions:
- `ctx context.Context` — always first.
- **Typed ID parameters use the short entity name** — `environment`, `application`,
  `user`, `session`, `role`, `connection`, `credential`, etc. Do **not** suffix
  with `ID` — the type `identity.ApplicationID` already says it's an ID.
- Non-ID strings: `email`, `password`, `name`, `role`, `code`, `purpose`.
- Struct parameters: `p Principal`, `m Mutation`, `b Boundary`, `input Create`.
- When two IDs of the same entity kind appear, disambiguate with a prefix:
  `sourceUser identity.UserID, targetUser identity.UserID`.

---

## `identity` — The Foundation Package

`internal/identity/` is the lowest-level application package. It defines
**what identities are** — ID types, format validators, domain primitives.

### Dependency Rule

`identity` imports only `errx` and external libraries (`uuid`). It **never**
imports anything from `internal/iam/`. Every domain and adapter package imports
`identity`. This makes it the foundation of the type system.

```
stdlib → errx → identity ─┐
                           ├→ every domain package → adapters
              query ───────┘
```

### Typed IDs: `ID[T any]`

All entity identifiers use `identity.ID[T]`, a generic struct wrapping
`uuid.UUID` with a phantom type tag for compile-time discrimination:

```go
type ID[T any] struct{ v uuid.UUID }

// 24 entity types, each with an unexported tag:
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

**API per entity type** (24 sets):
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

## `query` — Pagination Foundation Package

`internal/query/` owns the pagination types that appear in domain interfaces.
It is transport-agnostic — no HTTP or framework imports.

```go
package query

// Pagination holds limit/offset for paginated queries.
type Pagination struct {
    Limit  int
    Offset int
}

// Page carries pagination metadata in API responses — the effective
// limit/offset the server applied (after clamping) plus the total match count.
type Page struct {
    Total  int `json:"total"`
    Limit  int `json:"limit"`
    Offset int `json:"offset"`
}

// Paginated is the standard paginated response envelope.
type Paginated[T any] struct {
    Items []T  `json:"items"`
    Page  Page `json:"page"`
}
```

Wire format: `{"items": [...], "page": {"total": N, "limit": N, "offset": N}}`.
This is the one envelope shape for every paginated list endpoint — do not
invent a flatter or differently-named variant per module.

### Dependency Rule

`query` is a foundation package at the same level as `identity` and `errx`.
It imports nothing from `internal/`. Every domain package can import it freely
in `ports.go` without pulling in transport types.

### Paginated Returns Use DB-Level Pagination

List methods that support pagination return `(query.Paginated[T], error)` —
never bare `([]T, int, error)`. The bare `int` is ambiguous (total? page
number? items returned?) at every call site:

```go
// ✗ Bad — ambiguous int
RoleAssignments(ctx context.Context, environment identity.EnvironmentID,
    filter RoleAssignmentFilter, page query.Pagination) ([]RoleAssignmentView, int, error)

// ✓ Good — self-documenting, serializes to JSON directly
RoleAssignments(ctx context.Context, environment identity.EnvironmentID,
    filter RoleAssignmentFilter, page query.Pagination) (query.Paginated[RoleAssignmentView], error)
```

The repository does the pagination — `COUNT(*)` for `Page.Total`, then
`LIMIT`/`OFFSET` for the page of rows — and returns `query.Paginated[T]`
directly. It never loads the full table and slices in memory. The service
and handler pass `query.Paginated[T]` straight through without touching it:

```go
// repository — owns the SQL, assembles the envelope
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID,
    page query.Pagination) (query.Paginated[User], error) {
    var total int
    if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM users WHERE environment_id=$1`, environment); err != nil {
        return query.Paginated[User]{}, failure(err)
    }
    items := []User{}
    err := r.db.SelectContext(ctx, &items,
        `SELECT * FROM users WHERE environment_id=$1 ORDER BY name LIMIT $2 OFFSET $3`,
        environment, page.Limit, page.Offset)
    if err != nil {
        return query.Paginated[User]{}, failure(err)
    }
    return query.Paginated[User]{Items: items, Page: query.Page{Total: total, Limit: page.Limit, Offset: page.Offset}}, nil
}

// handler — no slicing, just forwards the envelope
func (h *Handler) List(c *fiber.Ctx) error {
    out, err := h.queries.List(c.Context(), env(c), httpx.PaginationFromCtx(c))
    if err != nil {
        return err
    }
    return c.JSON(out)
}
```

### Filters Stay in Domain Packages

Filter structs are entity-specific — they reference typed IDs, enums, and
field names. They live in the domain package alongside the entity they filter,
**not** in `query`:

```go
// authorization/filter.go — domain-specific, stays here
type RoleAssignmentFilter struct {
    ResourceID     *identity.ResourceID
    OrganizationID *identity.OrganizationID
    UserID         *identity.UserID
}
```

Moving filters to `query` would force it to import `identity` and know about
every domain, destroying its foundation status.

### `httpx` — HTTP Bridge Only

`httpx` keeps only the Fiber-specific helper that parses HTTP query params
into `query.Pagination`. It does **not** build the response envelope — the
repository already returns `query.Paginated[T]` ready to serialize:

```go
// httpx/paginate.go
func PaginationFromCtx(c *fiber.Ctx) query.Pagination { ... }
```

This is the only package that imports both Fiber and `query`. Domain packages
and services never import `httpx`.

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
stores the token on the Fiber context; `apiauth.Environment(c)` returns its
typed environment. `apiauth.Scope` compares that environment with the
`:environment` path parameter and must sit on the group that binds it
(`/environments/:environment`) — on `/api/v1` the parameter is still empty.
Route families that share a path prefix with another family use `guarded`
(per-route checks), not a prefix group, so one family's permission check never
runs for another's routes (`tests/e2e/scoped_api_test.go`).

**`amr`** (authentication methods) is stored on `sessions.amr`, copied onto
every access token issued for the session (including refreshes) and onto OIDC
ID tokens via `oauth.Authorization.Session` → `oauth.SessionInfo`. First
factors: `pwd`, `email`, `fed` (`authentication.MethodAMR`); a second factor
appends `mfa.AMR(proof)` = `otp` + `mfa`. Headless second-factor logins park
as `mfa_logins` rows keyed by the hash of an `ik_mfa_` token (5 min, 5
attempts); no session exists until verification. Wrong codes also count per
factor across every path (`user_factors.failed_attempts`): every
`config.MFAFailures` in a row lock it for `mfa.Lockout` (15 min doubling,
24 h max, 429 `MFA_LOCKED` via `errx.TooManyRequests`, audited `mfa.locked`); callers commit the
transaction on a wrong code so the count sticks. Unconfirmed factors expire
for confirmation after `config.MFAEnrollTTL` (`Factor.Enrollable`). `SecondFactor.Complete`
runs the session-issuing callback before committing, so a failed session
never loses recovery codes. Tokens carry `auth_time`
(`sessions.authenticated_at`, written by `CreateSession` from the same
second as the first token and kept across refreshes); the self-service
`/identity/v1/me/factors*` routes (`mfahttp.RegisterSelf`) refuse
impersonated tokens and require a sign-in within `config.MFAFreshAuth` for
changes (`mfa.Fresh`, 403 `REAUTHENTICATION_REQUIRED`).

Operator console sessions store their sign-in `method` (`password`/`sso`)
and `authenticated_at` on `operator_sessions`; `management.Principal`
carries them (`Method` = `key` for management keys). `SetPassword` needs
the current password, a key, or a sign-in within `config.OperatorFreshAuth`
when no password is set (or from an SSO session), and revokes every other
session of the operator in the same transaction. A password someone else
chose (`SetTemporaryPassword`, used for `IAMKIT_BOOTSTRAP_PASSWORD`) sets
`operators.password_must_change`: `Login` answers `PASSWORD_CHANGE_REQUIRED`
until it receives `new_password`.

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
from the authenticated context. Exception: when one command can emit several
actions, the service sets `Action` itself (e.g. `mfasvc` writes `mfa.enrolled`,
`mfa.removed`, `mfa.recovery_regenerated`, `mfa.recovery_used`, `mfa.reset`,
`mfa.locked`).

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
| `rsc.io/qr` | Enrollment QR code (PNG data URI) | `hostedhttp/` only |

**Rule:** Domain packages and services never import framework types. They
depend only on `identity`, `query`, `errx`, and stdlib.

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
- **Don't put filter structs in `query`** — filters are domain-specific (they
  reference typed IDs and entity fields). `query` only owns `Pagination`,
  `Page`, and `Paginated[T]`.
- **Don't return bare `([]T, int, error)` for paginated queries** — use
  `(query.Paginated[T], error)`. The int is ambiguous at every call site.
- **Don't put pagination types in `httpx`** — `httpx` imports Fiber, so
  `ports.go` would need a framework import. Pagination types live in `query`;
  `httpx` only converts a `*fiber.Ctx` into `query.Pagination`.
- **Don't flatten the `page` envelope to a bare `total` field** — the wire
  format is `{"items": [...], "page": {"total", "limit", "offset"}}`. It's
  documented in the SDK reference and consumed by the frontend; don't change
  it while relocating the Go types.
- **Don't paginate by loading the full table and slicing in memory** — every
  paginated repository method runs `COUNT(*)` for `Page.Total` and
  `LIMIT`/`OFFSET` for the page of rows. In-memory slicing doesn't scale and
  makes `Page.Total` wrong once a repository cap is hit.
