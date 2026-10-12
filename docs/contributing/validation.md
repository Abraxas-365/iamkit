# Documentation validation record

This record distinguishes repository checks from deployment acceptance. Commands
and source review apply to this working-tree documentation revision, not an
unpublished registry artifact or third-party account.

## Current documentation review — 2026-10-12

The documentation was checked against the phase-8 source baseline `649647a`,
including reader-facing repository and SDK READMEs. Corrections cover credential
boundaries, SDK examples, federation/LDAP behavior, SAML logout, configuration,
worker jobs and operational instructions. Source review is not a guarantee of
third-party provider interoperability.

Confirmed in this review:

- All 114 reader-facing Markdown files pass local link/anchor and hygiene checks;
  dependency/build directories and agent rule files are excluded.
- The backend test suite (`GOWORK=off go test ./...`) passes, including architecture
  and generated OpenAPI checks. Database E2E tests are opt-in and were not enabled
  by that command.
- The nested Go SDK tests and vet pass. Protected-API handler unit tests pass.
- A fresh Docker source build and the disposable onboarding/restart smoke pass.
- The protected-API example was also tested against a separate disposable IAMKit
  instance: an allowed tenant request returned 200, a wrong-tenant request 403,
  and a request without a bearer token 401. Only a scratch-copy listener was
  adjusted for Docker networking; repository code and shared services were not
  changed. All resources created for that test were removed.
- Website tests, Astro check/build and the rendered-link check pass: 105 HTML
  pages, zero broken local links, anchors or assets. Astro retains an unrelated
  video-script type hint and existing optional-collection/sitemap build notices.
- Five screenshots were captured from the current live console/hosted pages on a
  disposable seeded stack, using fictional data. They show navigation and forms,
  not completed provider configuration, issued secrets or production settings.
  Browser checks confirm that the images load without horizontal overflow at
  desktop/mobile widths in light/dark themes, and mobile sidebar navigation works.

## Earlier locally confirmed checks

The following entries record earlier validation. They are not all re-executed
by the current editorial review:

- Backend Docker image built as `iamkit-docs-validation:local`.
- Disposable Docker smoke test exited 0: non-root signing-key mount, fresh schema,
  explicit bootstrap, project/environment/user/org/app/resource provisioning,
  membership/binding/grant, password login, online introspection, cross-tenant
  **login** denial and backend restart with retained database/key.
- The smoke script refreshes Docker's ephemeral host-port mapping after restart.
- Go protected-API example formatted and checked with `go test ./...` and
  `go vet ./...`; handler tests verify allowed access and missing/invalid token,
  wrong tenant, missing permission and wrong purpose rejection using a stub
  introspector. This is not a live HTTP integration test.
- Root and nested SDK `make test` and `make vet` exited 0.
- Local links/anchors across human-facing Markdown files, SVG/hygiene checks and
  shell syntax checks exited 0.
- Reviewer checked operational commands/security contracts against source;
  owner-recovery side effects and explicit restore archive were corrected.
- Final source-contract review identified scoped API environment-check bypass
  and overlapping permission middleware. Fixed on 2026-09-28 and covered by
  `tests/e2e/scoped_api_test.go` (cross-environment rejection, least permission
  per route family). Delivery override/fallback and user list/detail contracts
  were corrected.

## Reproducible checks

[Testing commands](testing.md) and `.github/workflows/docs.yml` maintain local
links/anchors across human-facing Markdown files, SVG parsing, basic documentation
hygiene, shell syntax, example compilation and disposable Docker smoke coverage.
Hosted CI results are separate from local execution. The private-key marker check
is intentionally narrow, not a complete secret scan.

## Acceptance still requiring a target environment

- Public HTTPS reverse-proxy/browser console, OAuth and federation end-to-end.
- Google/Microsoft tenant credentials, directory provisioning interoperability and
  real delivery webhook success/outage tests.
- Backup restore rehearsal with functional checks, owner recovery/outage drills,
  and a named release-pair upgrade/rollback.
- Live protected Go API success/denial journey, beyond compilation and IAMKit
  introspection/login denial in the smoke script.
- Anonymous registry pulls, published digest/architecture verification and
  ownership/distribution approval.
- Capacity measurements, shared ingress controls and platform alerts.

## Documentation/product follow-up

Route-family references are written, but an automated exhaustive per-route
request/response coverage matrix is not yet implemented. Some advanced guides
use labeled request templates rather than executable vendor-specific clients.
Typed SDK list helpers need live page-envelope compatibility work; see
[SDK notes](../reference/sdk/go.md). Finish those changes with their own tests,
not silent compatibility assumptions in documentation.

Use the [launch checklist](../operations/launch-checklist.md) to record evidence
for your deployment. These deployment-acceptance items are deliberately not
marked complete by this documentation pass.
