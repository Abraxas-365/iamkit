# IAMKit documentation rebuild

## Objective and scope

Build a task-oriented documentation set that takes a developer from an empty
machine to an integrated application, and gives an operator the runbooks needed
to deploy, maintain, upgrade and recover that installation.

This is the implementation plan, not the completed documentation. The previous
Markdown pages have been removed; `docs/assets/` is preserved. New pages must be
written from the current implementation and verified examples, not copied from
the old documentation or inferred from previous discussions.

The README remains the usable entry point while the new documentation is written.
Do not publish empty pages or present planned functionality as available.

## Editorial standard

- Write for users: explain the outcome, show the procedure, verify the result.
- Use direct, production-oriented language. Avoid blanket labels such as “early
  development” or repetitive audit/certification disclaimers on every page.
- State concrete constraints where they matter. Example: “Rate limits are
  process-local. Enforce a shared limit at ingress when using multiple replicas.”
- Distinguish IAMKit behavior, application responsibilities and deployment
  responsibilities. Do not describe planned controls as implemented controls.
- Do not claim certification, independent audits, tested throughput, availability
  guarantees or release support without evidence. A documentation rewrite is not
  evidence of those properties.
- Use one example product throughout: InvoiceCloud, Acme organization, Web App,
  Invoices API and `invoices:read` / `invoices:write` permissions.
- Use “OAuth client” for an app obtaining tokens from IAMKit; use “OIDC federation
  connection” for an external identity provider authenticating a user.
- Put contributor architecture details after the user-facing material.
- Preserve the separate publication/license requirements until ownership and
  distribution permissions are resolved.

## Proposed structure

The paths below are planned outputs, not links to existing guides. Use plain
Markdown and relative links initially; a documentation-site framework is not a
prerequisite. Keep source examples alongside the documentation for execution.

```text
docs/
├── index.md                         # Role-based entry points and recommended paths
├── assets/                          # Existing SVGs; add accessible flow diagrams
├── start/
│   ├── overview.md                  # What IAMKit does, ownership split, platform fit
│   ├── docker-quickstart.md         # Empty machine → healthy instance → first API access
│   ├── first-application.md         # Provision InvoiceCloud and validate a permission
│   └── management-console.md        # Deploy console separately, TLS and operator login
├── concepts/
│   ├── identity-model.md            # Workspace/project/environment/user/org/app/resource
│   ├── credentials-and-boundaries.md # Who may use each API; scope and expiry matrix
│   ├── authorization.md             # Catalogs, bindings, roles, grants and tenant isolation
│   └── sessions-and-tokens.md       # JWTs, refresh families, revocation and introspection
├── guides/
│   ├── application-integration.md  # Browser + backend/BFF + protected API architecture
│   ├── signup-and-onboarding.md    # Backend-owned signup, membership/grant provisioning
│   ├── password-login.md           # Login, errors, tenant context, refresh and logout
│   ├── email-otp.md                # Challenge initiation/verification and resend UX
│   ├── password-reset.md           # Forgot password, eligibility and session effects
│   ├── email-verification.md       # Ownership verification and actual enforcement policy
│   ├── email-delivery.md           # HTTPS webhook contract, secret handling and failures
│   ├── federation.md               # Approved credentials, subject linking, callback flow
│   ├── google-login.md             # Provider registration → verified local login
│   ├── microsoft-login.md          # Tenant-specific issuer/configuration and validation
│   ├── oauth-oidc.md               # Client registration, login/consent, code + PKCE
│   ├── protect-an-api.md           # JWKS/introspection, tenant match and permission checks
│   ├── organizations.md            # Membership lifecycle, hierarchy and access changes
│   ├── service-accounts.md         # Machine token lifecycle; no management authority
│   ├── scim-provisioning.md         # Connection credentials, mapping and deprovisioning
│   └── impersonation.md            # Operator authority, attribution and restrictions
├── reference/
│   ├── configuration.md            # Every variable, default, validation and restart effect
│   ├── cli.md                      # Serve/migrate/bootstrap/recover-owner and exit behavior
│   ├── errors-and-pagination.md    # Actual envelopes, filtering, limits and exceptions
│   ├── token-claims.md             # Claims per token type; consumer validation rules
│   ├── webhooks.md                 # Current email payload, HTTP behavior and authentication
│   ├── glossary.md                 # Short definitions, not duplicate conceptual guides
│   ├── api/
│   │   ├── index.md                # API families, credentials and endpoint inventory
│   │   ├── management.md           # Operators, keys, projects, environments and sessions
│   │   ├── users-and-organizations.md
│   │   ├── applications-and-authorization.md
│   │   ├── integrations.md         # Federation, OAuth/SCIM management, service accounts
│   │   ├── identity.md             # Login/challenges/refresh/profile/memberships/machine
│   │   ├── oauth-oidc.md           # Discovery, JWKS and implemented protocol endpoints
│   │   └── scim.md                 # Implemented resources, filters and response semantics
│   └── sdk/
│       ├── go.md                   # Install/version/context/errors; executable examples
│       ├── management.md           # iamclient coverage and current compatibility
│       ├── authentication.md       # authclient login, validation and OAuth helpers
│       ├── fiber.md                # Authenticate/RequirePermissions/RequireOrganization
│       └── scim.md                 # scimclient usage and failures
├── operations/
│   ├── deployment.md               # Pinned image, PostgreSQL, TLS and startup topology
│   ├── reverse-proxy.md            # Same-origin routing, headers, CORS and cookie behavior
│   ├── secrets-and-keys.md         # Key mounts, management key lifecycle and rotation
│   ├── database-and-migrations.md  # Initialization, checksums, concurrency and upgrade order
│   ├── backup-and-restore.md       # Database + signing material, restore verification
│   ├── upgrades-and-rollback.md    # Compatibility, preflight, migration-aware recovery
│   ├── observability.md           # Health/logs/alerts and externally supplied monitoring
│   ├── scaling-and-abuse.md        # Shared state, ingress limits and measured capacity
│   ├── incident-response.md       # Compromise containment, revocation and owner recovery
│   ├── troubleshooting.md         # Symptom → diagnosis → repair → verification
│   └── launch-checklist.md         # Evidence-based deployment acceptance checklist
├── maintainers/
│   ├── architecture.md            # Domain boundaries, adapters and enforced conventions
│   ├── local-development.md       # Go, SDK and frontend builds; disposable test data
│   ├── testing.md                 # Unit/integration/browser/docs validation responsibilities
│   └── releases.md                # Registry workflow, tag/digest verification and licensing
└── examples/
    ├── README.md                  # Prerequisites and exact run order for tested examples
    ├── onboarding/                # curl + jq script; capture IDs, never paste fake UUIDs
    ├── browser/                   # Framework-neutral JS login/OTP/refresh integration
    ├── go-api/                    # Minimal compilable tenant-safe protected API
    └── deployment/                # Tested Compose override and reverse-proxy configuration
```

## Reader journeys

1. **First-time user:** overview → Docker quickstart → first application → protected
   API. Finish with one successful API request and one denied cross-tenant request.
2. **Application developer:** integration → onboarding → chosen login method →
   token/session handling → authorization. Explain what stays on their backend.
3. **Operator:** deployment → configuration → secrets → backups → observability →
   incident response → launch checklist. Finish with a tested recovery procedure.
4. **Identity administrator:** console → users/organizations → roles/grants →
   federation/SCIM. Confirm how changes affect current and future access.
5. **Maintainer:** architecture → local development → tests → release procedure.

## Required page contracts

### Tutorials and integration guides

Every guide must contain:

1. A concrete result and who runs each step (operator, app backend, browser or API).
2. Prerequisites: software versions, existing entities, authority and network setup.
3. A sequence diagram for flows involving more than one trust boundary.
4. Complete runnable requests/code, including headers and ID extraction.
5. Expected status codes and representative response bodies with no real secrets.
6. Success verification and at least one important rejection case.
7. Failure handling: retries, partial operations, duplicate requests and cleanup.
8. Links to canonical reference fields rather than duplicated default values.

Label pseudocode explicitly. Never imply a multi-request provisioning sequence
is atomic or that all writes support idempotency keys. Avoid `latest` for deployed
releases, world-readable keys, browser management secrets and logging OTP/token
payloads. Never run example cleanup against a user's existing database.

### API reference

Build a route coverage inventory from actual registrations. For every endpoint,
record method/path, accepted credential and authority, boundary, content type,
parameters, field requirements, status codes, errors and side effects. Include
pagination/filter support per endpoint, not a guessed universal list contract.
Document cookie/CSRF behavior, redirects, response headers, expiration, replay and
revocation where relevant. Include raw-array exceptions if they still exist.

Use handler DTOs, domain validation, service behavior, SQL constraints and tests
as evidence. An OpenAPI description may be added once it can be checked against
this inventory; do not publish an invented schema as the source of truth.

### Operations runbooks

Specify trigger, required authority, preflight, exact procedure, expected output,
verification, rollback/recovery and credential exposure risks. Distinguish
implemented health endpoints from monitoring supplied externally. State downtime
and session/token effects of manual key changes; do not promise seamless rotation
or zero-downtime upgrades without a tested implementation.

## Implementation phases and acceptance gates

### Phase 1 — Establish the verified contract

- Inventory routes in `internal/server/` and each module's HTTP adapter.
- Inventory configuration in `cmd/iamkit/`, `internal/bootstrap/`, provider adapters,
  Docker/Compose files and frontend configuration.
- Map credential types, scope, expiry and validation against services/repositories.
- Compare current SDK models to actual response envelopes before recommending SDK
  calls; record incompatibilities as implementation work, not hide them in docs.
- Record confirmed behavior, required deployment controls and product gaps in a
  working coverage checklist. Link every non-obvious assertion to code/test evidence.

**Gate:** every API family and setting has an owner page and a verification method;
no contradictions between HTTP contracts, SDK examples and the main README.

### Phase 2 — Deliver a complete first success

- Write `index.md`, the `start/` pages, the integration guide and core concepts.
- Add executable onboarding and protected API examples with consistent variables.
- Cover source-build Docker and verified registry-image paths separately.
- Test non-root key access, first boot, subsequent boot, console deployment and TLS.
- Run onboarding → password login → permitted API call → cross-tenant denial.

**Gate:** a new reader can execute the journey from a clean checkout/database
without guessing IDs, endpoints, credentials or which process runs a command.

### Phase 3 — Complete authentication and administration guides

- Write OTP, reset, verification, webhook, Google/Microsoft federation and OAuth.
- Document fixed client boundaries versus login-time context, and exactly where
  organization/application/resource context is available in each flow.
- Explain pre-created users, explicit linking, multiple login methods and separate
  sessions; do not infer federation auto-signup or OTP-as-MFA.
- Cover memberships, permissions, machine identities, SCIM and impersonation.
- Verify provider-specific claims against official provider documentation and test
  the integration in a controlled environment. Record anything not exercised.

**Gate:** each supported workflow has a successful path and documented failures;
provider, mail delivery and application responsibilities are unambiguous.

### Phase 4 — Finish reference and SDK coverage

- Complete all route families, configuration/CLI/claims/webhook references.
- Compile and execute Go examples against the supported SDK version.
- Cover error types, timeouts, context cancellation and credential redaction.
- Verify lists/filters, optional fields and documented numeric limits against code.

**Gate:** every registered route and every exposed configuration setting is covered;
all referenced SDK methods exist and examples match live responses.

### Phase 5 — Validate deployment and recovery

- Write and execute TLS/reverse-proxy, secrets, migrations and backup runbooks.
- Test restore into a separate disposable installation; verify identities, grants,
  key availability and token/session behavior rather than only database import.
- Exercise owner recovery, revoked credentials, webhook outage and database outage.
- Document replica-local limits and required edge controls; publish capacity numbers
  only with reproducible test conditions.
- Test upgrades against an identified release pair. Determine rollback from schema
  compatibility and backup recovery, not just changing the image tag.

**Gate:** procedures have recorded results, no secrets in logs/examples, and recovery
is demonstrated. Unresolved runtime gaps remain explicit work items.

### Phase 6 — Publish and maintain

- Replace transitional README links with verified new pages; check SDK/frontend and
  security-document links too. Add entry points for old public URLs where feasible.
- Keep `SECURITY.md` focused on security policy, trust boundaries and reporting;
  move detailed procedures to operations pages without deleting factual requirements.
- Add CI for Markdown links/anchors, formatting, SVG validity, secret scanning and
  executable docs examples. Use disposable data and redact failure output.
- Review releases for route/config/SDK changes; update the corresponding docs in
  the same change. State tested image tags/digests and versions on tutorials.
- Validate anonymous registry pulls before calling an image publicly available.

**Gate:** no broken links or placeholders masquerading as instructions, complete
coverage checklist, passing example checks and a reviewer unfamiliar with the
implementation successfully completing the first-user journey.

## Definition of done

- A developer can deploy, provision and integrate without undocumented setup.
- An operator can diagnose outages, rotate appropriate credentials and restore service.
- Endpoint/configuration coverage is complete and checked against the implementation.
- Browser/backend/operator boundaries and tenant isolation are clear in every example.
- All runnable examples are tested; untested third-party steps are identified precisely.
- Documentation describes supported behavior directly, without repetitive status
  disclaimers or unsupported production-readiness guarantees.

## Current progress

- [x] Remove previous documentation pages while preserving assets.
- [x] Define the new information architecture, page standards and acceptance gates.
- [ ] Execute phases 1–6 and publish the replacement documentation.
