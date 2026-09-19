# Documentation validation record

This record distinguishes repository checks from deployment acceptance. Commands
and source review apply to this working-tree documentation revision, not an
unpublished registry artifact or third-party account.

## Confirmed locally

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
- Local links/anchors/SVG/hygiene checks and shell syntax checks exited 0.
- Reviewer checked operational commands/security contracts against source;
  owner-recovery side effects and explicit restore archive were corrected.
- Final source-contract review identified scoped API environment-check bypass
  and overlapping permission middleware. These are documented blockers, **not
  fixed by this pass**; smoke tests exercise management onboarding, not scoped IAM.
  Delivery override/fallback and user list/detail contracts were corrected.

## Reproducible checks

[Testing commands](testing.md) and `.github/workflows/docs.yml` maintain local
links/anchors, SVG parsing, basic documentation hygiene, shell syntax, example
compilation and disposable Docker smoke coverage. Hosted CI results are separate
from local execution. The private-key marker check is intentionally narrow, not
a complete secret scan.

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
for your deployment.
are deliberately not marked complete by this documentation pass.
