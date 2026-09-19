# AGENTS.md — Coding Guidelines for IAMKit

## Domain Validation Pattern

### Problem

Validation logic is scattered across service methods as inline `strings.TrimSpace`
checks, loose `validID()` helpers duplicated in every `*svc` package, and raw
`uuid.Parse` calls. Error messages are generic ("invalid request"). Nothing
enforces validation at the type level.

### Pattern: Validate() on Domain Types, Typed IDs at Boundaries

#### 1. `Validate() error` on domain input structs

Every domain struct that enters a service method through a create/update path
gets a `Validate() error` method. The method lives in the same file as the
struct definition (not in the service package).

```go
// resource.go  (authorization package)
func (r Resource) Validate() error {
    if strings.TrimSpace(r.Name) == "" {
        return errx.Validation("resource name is required")
    }
    if strings.TrimSpace(r.Audience) == "" {
        return errx.Validation("resource audience is required")
    }
    if strings.TrimSpace(r.Prefix) == "" {
        return errx.Validation("resource prefix is required")
    }
    return nil
}
```

Rules:
- One field → one error message. Never "invalid request" for multiple fields.
- Use `errx.Validation(...)` for all domain validation errors.
- The method is on a **value receiver** (no mutation).
- Only validate structural invariants the struct owns (non-empty, format).
  Cross-entity checks (e.g. "permissions exist in catalog") stay in the service.
- `Update` structs with optional (`*T`) fields validate only non-nil fields.

#### 2. Typed IDs instead of loose `validID()`

Delete all per-package `func validID(id string) bool` helpers. Instead, use a
single shared helper in the `identity` package:

```go
// internal/identity/model.go
func ValidID(id string) bool { _, err := uuid.Parse(id); return err == nil }
```

Service methods call `identity.ValidID(id)` directly. This is the minimal
change; we are **not** introducing newtype ID wrappers at this stage to keep
the diff small and avoid interface churn.

#### 3. Service methods become thin orchestrators

```go
func (s *Service) CreateResource(ctx context.Context, env string, input authorization.Resource) (string, error) {
    if err := input.Validate(); err != nil {
        return "", err
    }
    // cross-entity / prefix / permissions checks remain here
    ...
}
```

#### 4. `authentication.Context.Validate()`

`authentication.Context` is validated inline in multiple places across
authentication, federation, impersonation. Give it a `Validate() error` method:

```go
func (c Context) Validate() error {
    for _, pair := range []struct{ name, value string }{
        {"environment_id", c.EnvironmentID},
        {"organization_id", c.OrganizationID},
        {"application_id", c.ApplicationID},
        {"resource_id", c.ResourceID},
    } {
        if _, err := uuid.Parse(pair.value); err != nil {
            return errx.Validation(pair.name + " must be a valid UUID")
        }
    }
    return nil
}
```

---

## Package File Organization

### Rule: ports.go is interfaces only, domain files hold structs

Every module under `internal/iam/<module>/` follows the same two-file-kind
convention:

| File | Contains | Never contains |
|------|----------|----------------|
| `ports.go` | Interfaces only: `Commands`, `Queries`, `Repository`, `Secrets`, etc. | Structs, `Validate()` methods, constants |
| Domain files (`resource.go`, `connection.go`, `account.go`, …) | Structs, `Validate()` methods, `Mutation`, constants, view types | Interfaces |

**Naming the domain files**: name them after the aggregate or concept they
describe, not "models.go" or "types.go". Examples:

```
authentication/   → ports.go, context.go, token.go
authorization/    → ports.go, resource.go, grant.go
application/      → ports.go, application.go
user/             → ports.go, user.go
organization/     → ports.go, organization.go, structure.go
federation/       → ports.go, connection.go
impersonation/    → ports.go, request.go
management/       → ports.go, workspace.go, activity.go
oauth/            → ports.go, client.go, registration.go
provisioning/     → ports.go, credential.go, scim.go
serviceaccount/   → ports.go, account.go
```

### Why

1. **Predictability**: any contributor knows interfaces live in `ports.go` and
   nowhere else. Grep for behavior contracts in one place.
2. **Diff clarity**: interface changes (which affect adapters) show up in
   `ports.go` diffs; struct/validation changes (domain-only) show up in domain
   file diffs.
3. **Import cycles**: keeping structs out of `ports.go` makes it easier to add
   imports like `identity` or `errx` to domain files without pulling them into
   the interface file.

### Self-documenting interface parameters

Interface methods **must** name every parameter. Bare positional `string` params
are not allowed — they are unreadable at the call site.

```go
// ✗ Bad — what are these three strings?
LinkApplication(context.Context, string, string, string) error

// ✓ Good — self-documenting
LinkApplication(ctx context.Context, environment, applicationID, resourceID string) error
```

Rules for naming:
- `ctx context.Context` — always first, always named `ctx`.
- ID parameters use the form `<entity>ID`: `environmentID`, `resourceID`, `userID`,
  `sessionID`, `connectionID`, `operatorID`, `clientID`.
- Environment is `environment` (it is always an ID but the shorter name is
  already established throughout the codebase).
- Non-ID strings use their domain name: `email`, `password`, `name`, `role`,
  `code`, `purpose`, `audience`.
- Struct parameters use short lowercase names: `p Principal`, `m Mutation`,
  `b Boundary`, `input Create`, `input Update`.

This applies to `Commands`, `Queries`, and `Repository` interfaces alike. The
concrete service and repository implementations already name their params; this
rule ensures the interface declarations match.

---

## Per-Module Refactoring Plan

Each section below is a self-contained unit of work. A smaller model can
execute one module at a time. Every section lists:
- **Add `Validate()`** — which structs get the method, which file, which fields.
- **Replace inline checks** — which service file, which methods, what to remove.
- **Replace `validID()`** — delete the local helper, import `identity.ValidID`.

---

### Module 0: identity (shared)

**File:** `internal/identity/model.go`

Add:
```go
func ValidID(id string) bool { _, err := uuid.Parse(id); return err == nil }
```

This is the single source of truth. All per-package `validID` functions will be
deleted in subsequent modules.

**Import needed:** `github.com/google/uuid` (already imported in some files;
add if missing).

---

### Module 1: authentication

**File:** `internal/iam/authentication/ports.go`

Add `Validate() error` to `Context`:
- `EnvironmentID` — must be valid UUID
- `OrganizationID` — must be valid UUID
- `ApplicationID` — must be valid UUID
- `ResourceID` — must be valid UUID

**File:** `internal/iam/authentication/authsvc/service.go`

- Delete `func validID(id string) bool`.
- Delete `func valid(c authentication.Context) bool`.
- Replace all `validID(...)` → `identity.ValidID(...)`.
- Replace all `valid(boundary)` → `boundary.Validate() != nil` (invert logic).
- Methods affected: `Login`, `InitiateChallenge`, `VerifyChallenge`.

**File:** `internal/iam/authentication/authsvc/tokens.go`

- Replace `validID(...)` → `identity.ValidID(...)`.
- Methods affected: `Validate`, `AddMember`, `UpdateProfile`.

---

### Module 2: authorization

**File:** `internal/iam/authorization/resource.go`

Add `Validate() error` to `Resource`:
- `Name` — non-empty after trim
- `Audience` — non-empty after trim
- `Prefix` — non-empty after trim

Add `Validate() error` to `Catalog`:
- `Name` — non-empty after trim

**File:** `internal/iam/authorization/grant.go`

Add `Validate() error` to `Role`:
- `Name` — non-empty after trim
- `Resource` — valid UUID

Add `Validate() error` to `Grant`:
- `Organization` — valid UUID
- `User` — valid UUID
- `Resource` — valid UUID

Add `Validate() error` to `RoleAssignment`:
- `Organization` — valid UUID
- `User` — valid UUID
- `Role` — valid UUID

**File:** `internal/iam/authorization/authzsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline `strings.TrimSpace` checks with `input.Validate()`.
- Methods affected: `CreateResource`, `Resource`, `UpdateCatalog`, `LinkApplication`.

**File:** `internal/iam/authorization/authzsvc/grants.go`

- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline checks with `input.Validate()` where applicable.
- Methods affected: `Roles`, `Grants`, `SaveRole`, `DeleteRole`, `AssignRole`,
  `PutGrant`, `DeleteGrant`.

---

### Module 3: application

**File:** `internal/iam/application/application.go`

Add `Validate() error` to `Create`:
- `Name` — non-empty after trim

Add `Validate() error` to `Update`:
- `Name` — if non-nil, non-empty after trim

**File:** `internal/iam/application/appsvc/service.go`

- Replace inline `strings.TrimSpace(input.Name) == ""` → `input.Validate()`.
- Replace `uuid.Parse(id)` → `identity.ValidID(id)`.
- Methods affected: `Create`, `Find`, `Update`.

---

### Module 4: user

**File:** `internal/iam/user/user.go`

Add `Validate() error` to `Create`:
- `Name` — non-empty after trim
- `Password` — if non-empty, length 12–72

Add `Validate() error` to `Update`:
- `Name` — if non-nil, non-empty after trim

**File:** `internal/iam/user/usersvc/service.go`

- Replace inline checks with `input.Validate()`.
- Replace `uuid.Parse(id)` → `identity.ValidID(id)`.
- Methods affected: `Create`, `Find`, `Update`, `Suspend`.

Note: `Create.Validate()` does NOT validate email — that uses `identity.Email()`
which does parsing+normalization and must remain in the service (it mutates the
value).

---

### Module 5: organization

**File:** `internal/iam/organization/organization.go`

Add `Validate() error` to `Update`:
- `Name` — if non-nil, non-empty after trim

Add `Validate() error` to `Membership`:
- `Organization` — valid UUID
- `User` — valid UUID

**File:** `internal/iam/organization/structure.go`

Add `Validate() error` to `Unit`:
- `Name` — non-empty after trim
- `Kind` — non-empty after trim
- `Parent` — if non-nil, valid UUID

Add `Validate() error` to `Position`:
- `Name` — non-empty after trim
- `Code` — non-empty after trim

Add `Validate() error` to `Assignment`:
- `Position` — valid UUID
- `User` — valid UUID
- `Unit` — if non-nil, valid UUID

Add `Validate() error` to `Profile`:
- `Unit` — if non-nil, valid UUID
- `Manager` — if non-nil, valid UUID

**File:** `internal/iam/organization/orgsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline checks with `input.Validate()` / `identity.ValidID()`.
- Methods affected: `Create`, `Find`, `Update`, `AddMember`, `RemoveMember`, `Members`.

**File:** `internal/iam/organization/orgsvc/structure.go`

- Delete `func optionalID(id *string) bool`.
- Replace with inline `id == nil || identity.ValidID(*id)` or call the
  struct's own `Validate()`.
- Replace inline checks with `input.Validate()`.
- Methods affected: `Check`, `View`, `SaveUnit`, `DeleteUnit`, `SetProfile`,
  `SavePosition`, `DeletePosition`, `AssignPosition`, `DeleteAssignment`.

---

### Module 6: federation

**File:** `internal/iam/federation/fedsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- In `Start`, replace inline 5-UUID check with `b.Validate()` (from
  `authentication.Context`).
- Methods affected: `Link`, `Disable`, `Start`.

No new `Validate()` methods needed — `Connection` validation is complex
(URL parsing, regex) and correctly lives in the service.

---

### Module 7: impersonation

**File:** `internal/iam/impersonation/ports.go`

Add `Validate() error` to `Request`:
- `Organization` — valid UUID
- `Application` — valid UUID
- `Resource` — valid UUID
- `User` — valid UUID
- `Reason` — trimmed length 10–1000

**File:** `internal/iam/impersonation/impsvc/service.go`

- Replace inline UUID loop + reason check with `input.Validate()`.
- The `environment` parameter is a raw string — validate with `identity.ValidID(environment)`.
- Methods affected: `Create`.

---

### Module 8: management

**File:** `internal/iam/management/mgmtsvc/control.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Methods affected: `RevokeKey`, `DisableOperator`, `CreateProject`,
  `CreateEnvironment`, `Environments`.

**File:** `internal/iam/management/mgmtsvc/activity.go`

- Replace `uuid.Parse(id)` → `identity.ValidID(id)`.
- Methods affected: `RevokeSession`.

**File:** `internal/iam/management/mgmtsvc/service.go`

- Replace `uuid.Parse(workspace)` → `identity.ValidID(workspace)`.
- Methods affected: `RecoverOwner`.

No new `Validate()` methods — management inputs are mostly primitives (email,
name, password) with validation that includes side effects (hashing, email
normalization).

---

### Module 9: oauth

**File:** `internal/iam/oauth/control.go`

Add `Validate() error` to `Registration`:
- `Application` — valid UUID
- `Resource` — valid UUID
- `Redirects` — non-empty (length > 0)

**File:** `internal/iam/oauth/oauthsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline checks in `Create` with `input.Validate()`.
- Methods affected: `Create`, `Disable`, `Client`, `Access`.

---

### Module 10: provisioning

**File:** `internal/iam/provisioning/control.go`

Add `Validate() error` to `CredentialInput`:
- `Organization` — valid UUID
- `Name` — non-empty after trim

Add `Validate() error` to `Link`:
- `Connection` — valid UUID
- `User` — valid UUID
- `External` — non-empty

**File:** `internal/iam/provisioning/provsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Methods affected: `Find`, `Create`, `Update`.

**File:** `internal/iam/provisioning/provsvc/control.go`

- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline checks with `input.Validate()`.
- Methods affected: `Issue`, `Revoke`, `Link`.

---

### Module 11: serviceaccount

**File:** `internal/iam/serviceaccount/ports.go`

Add `Validate() error` to `Input`:
- `Name` — non-empty after trim
- `Application` — valid UUID
- `Resource` — valid UUID

**File:** `internal/iam/serviceaccount/sacctsvc/service.go`

- Delete `func validID(id string) bool`.
- Replace `validID(...)` → `identity.ValidID(...)`.
- Replace inline checks in `Create` with `input.Validate()`.
- Methods affected: `Create`, `Revoke`.

---

## Execution Checklist

For each module above:

1. Add `Validate()` methods to the domain struct file(s).
2. Update the service file: replace inline validation with `Validate()` calls,
   replace `validID()` / `uuid.Parse()` with `identity.ValidID()`.
3. Delete the local `validID` / `optionalID` helper if present.
4. Add `"github.com/Abraxas-365/iamkit/internal/identity"` import where needed;
   remove unused `"strings"` / `"github.com/google/uuid"` imports if they
   become unreferenced.
5. Run `go build ./...` to verify compilation.
6. Run `go test ./...` to verify behavior.

### Import guidance

- Domain struct files (`resource.go`, `grant.go`, etc.) will need:
  `"strings"`, `"github.com/Abraxas-365/iamkit/internal/errx"`, and
  `"github.com/Abraxas-365/iamkit/internal/identity"` (for `ValidID`).
- Service files will need `"github.com/Abraxas-365/iamkit/internal/identity"`.
- `uuid` import may still be needed in services for `uuid.NewString()`.

### What NOT to change

- Repository/adapter files — they don't do validation.
- HTTP handler files — they parse requests, not validate domain rules.
- `identity.Email()`, `identity.ValidatePermissions()`,
  `identity.ValidatePrefix()`, `identity.ValidateRedirects()` — these are
  already correct shared helpers. Don't move them or wrap them.
- Cross-entity validation (catalog subset checks, prefix enforcement) stays in
  service methods.
- The `canonical()` function in `authsvc/service.go` — it normalizes, not validates.
