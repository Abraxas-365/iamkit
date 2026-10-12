# Releases and registry publication

The [publishing workflow](../../.github/workflows/publish.yml) builds and pushes
multi-architecture (amd64/arm64) GHCR images on main, v-prefixed tags and manual
dispatch. The [release workflow](../../.github/workflows/release.yml) packages
and pushes the Helm chart only for v-prefixed tags. A configured image or chart
reference is not proof that a public package exists.

Before publication, obtain ownership/distribution authorization and review
[provenance](../../README.md#provenance--license), dependency licenses, secrets and
vulnerabilities. Publishing or changing package visibility is a shared-system
operation requiring explicit approval.

For an approved release:

1. Run root/SDK/frontend checks and documentation smoke tests.
2. Record tested schema/image versions and migration compatibility.
3. Rehearse the release-pair upgrade and recovery path.
4. Trigger the approved image workflow (and, for a tag, the release workflow);
   inspect both architecture results and published image/chart tags.
5. Verify package visibility and an anonymous image pull from a clean environment;
   verify the published chart separately when releasing it.
6. Record the immutable digest and update user-facing deployment references.

Do not advertise `latest` or a release tag until the exact artifact is verified.
See [upgrade runbook](../operations/upgrades-and-rollback.md). No publication is
needed for the source-build quickstart.
