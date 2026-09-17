# IAMKit documentation

Self-hosted identity and access management with explicit workspace, project, environment and
resource boundaries. Start here, then follow whichever path matches what you're doing.

## Start here

| If you're... | Read |
| :--- | :--- |
| New to IAMKit | [Concepts](concepts.md) — the mental model: workspaces, environments, resources, tokens, why there's no wildcard admin scope |
| Setting up a local instance | [Getting started](getting-started.md) — a runnable, end-to-end tutorial from empty checkout to a validated permission check |
| Wiring a real product | [Recipes](recipes.md) — task-oriented walkthroughs: new product onboarding, Google/OIDC login, service accounts, SCIM, impersonation, OAuth clients |
| Looking up an exact request/response shape | [API guide](api.md) — full endpoint reference |
| Writing Go code against IAMKit | [SDK reference](sdk.md) — `iamclient`, `authclient`, `fiberauth`, `scimclient` |
| Setting every env var correctly | [Configuration](configuration.md) — every environment variable, required vs. optional |
| Deploying anywhere but a laptop | [Deployment](deployment.md) — a checklist built from [Security status](../SECURITY.md) |
| Debugging a specific error | [Troubleshooting](troubleshooting.md) — common error messages and their real cause |
| Contributing or auditing the code | [Architecture](architecture.md) — module layout, machine-enforced dependency rules |
| Looking up a term | [Glossary](glossary.md) — quick reference |
| Understanding security posture | [Security status](../SECURITY.md) — what's enforced, what's deployment work |

## Suggested reading order (new to the project)

1. [Concepts](concepts.md) — understand the model before touching the API.
2. [Getting started](getting-started.md) — run it locally, end to end.
3. [Recipes](recipes.md) — find the walkthrough matching your actual task.
4. [API guide](api.md) / [SDK reference](sdk.md) — as detailed reference while building.
5. [Configuration](configuration.md) → [Deployment](deployment.md) — before anything non-local.

## Everything in one line each

- **[Concepts](concepts.md)** — workspace/project/environment/organization/application/resource
  hierarchy, token purposes, permissions vs. roles vs. grants, why linking is explicit rather
  than inferred.
- **[Getting started](getting-started.md)** — copy-pasteable curl walkthrough: bootstrap, create
  a product, log in, validate a token, watch a permission change take effect.
- **[Recipes](recipes.md)** — onboard a product, Google/OIDC login for an application's users,
  background-worker service accounts, SCIM provisioning, Fiber permission middleware,
  impersonation, OAuth/OIDC clients.
- **[API guide](api.md)** — every `/management/v1`, `/identity/v1`, `/oauth`, `/scim/v2` route.
- **[SDK reference](sdk.md)** — `sdk/iamclient` (management), `sdk/authclient` (identity/OAuth),
  `sdk/authclient/fiberauth` (middleware), `sdk/scimclient` (SCIM), `sdk/apierror` (errors).
- **[Configuration](configuration.md)** — every environment variable IAMKit reads, and what's
  intentionally not yet configurable.
- **[Deployment](deployment.md)** — an ordered checklist for going beyond `docker compose up`.
- **[Troubleshooting](troubleshooting.md)** — real error messages, mapped to real causes and
  fixes.
- **[Architecture](architecture.md)** — package layout, and the tests that enforce it stays that
  way.
- **[Glossary](glossary.md)** — one-line definitions of every term used above.
- **[Security status](../SECURITY.md)** — enforced boundaries and deployment requirements; the
  authoritative security document, not superseded by anything above.
