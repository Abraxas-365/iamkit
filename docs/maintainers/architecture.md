# Maintainer architecture

The Go binary wires domain services and adapters in `internal/bootstrap/` and
registers HTTP routes in `internal/server/`. PostgreSQL adapters live under each
`internal/iam/<module>/adapters/` directory. Embedded `migrations/` establish schema
and constraints. The React/Vite console in `frontend/` is embedded into the Docker
image via `//go:embed` (see `internal/console/`); `sdk/` is a separate Go module.

Modules own authentication, authorization, users, organizations, applications,
management, federation, OAuth, provisioning, service accounts and impersonation.
Keep shared identity parsing separate from cross-entity policy. HTTP handlers
parse DTOs, services orchestrate domain policy, repositories enforce transactional
state and database constraints.

Follow [AGENTS.md](../../AGENTS.md): domain input structs own `Validate()` in their
domain files; `ports.go` contains interfaces only with named parameters. Use
`identity.ValidID`. Do not turn a documentation change into an unrelated validation
refactor.

When changing behavior, trace registration → middleware → handler DTO → service
→ repository → migrations/tests. Update the owning API/configuration page and
SDK model in the same change. A handler route alone does not establish its full
security contract; review tenant filtering and current-state checks in SQL.
