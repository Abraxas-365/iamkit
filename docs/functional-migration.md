# Functional migration mapping

The previous implementation is replaced by the active environment-scoped model, not mounted as a fallback. This is behavior migration, not preservation of old URLs, interfaces or database contents.

| Previous capability | Current equivalent | Validation/reference |
| --- | --- | --- |
| Organization-owned users | Environment users + multiple organization memberships, profile and organization self-service | `tests/e2e/identity_test.go`, `migration_test.go` |
| Application scopes, role grants | Separate resources/catalogs, direct grants, resource roles/assignments; application-resource bindings | `internal/server/administration.go`, `resources.go`, migrations 002/010 |
| App sync | Application metadata PATCH + resource catalog PUT + explicit binding; no privileged slug | `docs/api.md` |
| Region/country/company org hierarchy | Configurable org-unit kinds, tree/ancestors/descendants/delete impact, cycle-checked member managers | `internal/server/details.go`, `administration.go` |
| Fixed business job catalog, GLT/DoA | Configurable organization positions and assignments; reporting relationships are not authorization | `tests/e2e/migration_test.go` |
| General API keys | Expiring service-account and separate SCIM credentials; revoke/reissue rotation | `internal/server/management.go`, `scim.go` |
| Email OTP login and enablement | Opt-in per-user OTP, hashed challenges, attempts/expiry, verification and reset | migrations 003/005/011; `authentication.go` |
| Sessions/refresh/logout | Persistent user families, rotating hashed refresh, replay revocation and live introspection | `tests/e2e/migration_test.go` |
| Google/Microsoft login | Generic verified OIDC provider discovery, exact deployment credential bindings and explicit subject links | `tests/e2e/federation_test.go`; real-provider live tests not run |
| OIDC server | Code/S256, public/confidential clients, discovery, persistent store, refresh and revocation | `tests/e2e/oidc_test.go`: invalid PKCE recovery, code replay, sequential/concurrent refresh replay |
| Impersonation | Owner-only reasoned actor-attributed 15-minute session, no refresh, audit | `internal/server/impersonation.go`, `tests/e2e/migration_test.go` |
| SCIM User provisioning | Dedicated organization-bound stable connection; create/read/list/replace/patch/deactivate; discovery and enterprise manager | `scim.go`, `scim_schema.go`, `tests/e2e/migration_test.go` |
| Explicit provisioning ownership | Operator-controlled `/provisioned-identities`; existing membership required, never email matching | `internal/server/provisioning_link.go` |
| Backend errors | `internal/errx`, sanitized HTTP envelope; protocol-specific OAuth/SCIM errors | `internal/server/errors_test.go` |
| Go clients/middleware | Typed management/identity/OAuth/SCIM clients, public SDK errors, offline/live validation, Fiber adapters | `sdk/`; SDK tests included in `make test` |
| Initialization | Embedded ordered/checksummed migrations, advisory lock, refusal of unmanaged schemas | `migrations/migrate.go`, `tests/e2e/identity_test.go` |

## Intentional non-equivalences

- Old `/api/v1`, `/auth`, SDK interfaces and existing data are not compatibility contracts. Management is exclusively operator-authenticated, not application scope-based.
- No privileged `iam`, wildcard administrative scope, identity merge by email or default credentials.
- Public email/account/org discovery is not retained; configuration is supplied by the application, organizations are listed after authentication.
- Provider-specific OAuth profile scraping is replaced by verified OIDC identity. Automatic provider profile overwrites and email fallback links are not retained.
- Admin OTP enablement does not assert email ownership. Password reset does not add a password to federation-only identities. Email OTP is not MFA.
- `prompt`/`max_age` requests are explicitly rejected until a proper fresh-authentication interaction is provided. No OIDC userinfo endpoint was present in the reference implementation or is advertised here.
- Fixed organization/job-title business assumptions are data now, not built-in authorization.
- General read collections replace specialized legacy list-by-app/user helper interfaces; callers filter appropriate scoped inventories. Some inventories remain bounded/unpaginated; no unlimited pagination claim is made.

## Validation limits

Build, root/SDK unit tests, vet and disposable PostgreSQL E2E cover the new model. They are not a mechanical port of every old test or a protocol certification. Production rate limiting, operational retention/cleanup, full audit coverage, key rotation, real Google/Microsoft deployments, licensing and independent security review remain release work. See `SECURITY.md`.
