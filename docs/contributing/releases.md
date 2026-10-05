# Releases and registry publication

The [publishing workflow](../../.github/workflows/publish.yml) builds GHCR images
on main, v-prefixed tags and manual dispatch. It requests amd64/arm64 builds.
A configured image reference is not proof that a public package exists.

Before publication, obtain ownership/distribution authorization and review
[provenance](../../README.md#provenance--license), dependency licenses, secrets and
vulnerabilities. Publishing or changing package visibility is a shared-system
operation requiring explicit approval.

For an approved release:

1. Run root/SDK/frontend checks and documentation smoke tests.
2. Record tested schema/image versions and migration compatibility.
3. Rehearse the release-pair upgrade and recovery path.
4. Trigger the authorized workflow; inspect both architecture results and tags.
5. Verify package visibility and an anonymous pull from a clean environment.
6. Record the immutable digest and update user-facing deployment references.

Do not advertise `latest` or a release tag until the exact artifact is verified.
See [upgrade runbook](../operations/upgrades-and-rollback.md). No publication is
needed for the source-build quickstart.
