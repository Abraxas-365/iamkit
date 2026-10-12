# IAMKit documentation

Build sign-in, manage customer organizations and protect your APIs with
self-hosted identity and tenant-aware authorization. Your application keeps its
business data and user experience; IAMKit manages identities and scoped access.

## Get started

Connect one application before adding more sign-in methods or enterprise features.

1. **[Run IAMKit](start/docker-quickstart.md).** Start the server and open the management console.
2. **[Create your first application](start/first-application.md).** Set up an organization, a user and an API resource, then issue a scoped token.
3. **[Protect your API](start/protect-an-api.md).** Verify that token and reject requests from the wrong organization.

Already running IAMKit? [Choose your integration](guides/applications/application-integration.md):
use [hosted sign-in](guides/applications/hosted-login.md), build a
[custom sign-in UI](guides/applications/custom-sign-in-ui.md), or start from an
[example app](examples/README.md).

## Build with IAMKit

### [Authentication](guides/sign-in/index.md)

Add passwords, email codes, passkeys, social login and multi-factor authentication.
Control sign-up, enable a waitlist, and protect public forms from abuse.

### [Enterprise connections](guides/enterprise/index.md)

Connect your customers' SAML or OpenID Connect identity providers, integrate an
LDAP directory, and provision people and groups through SCIM.

### [Users and organizations](guides/organizations/index.md)

Model customer organizations, memberships and profiles. Let customer
administrators manage their own people and SSO without operator access.

### [Authorization](guides/authorization/index.md)

Define API resources, roles and permissions. Enforce tenant boundaries in your
backend and keep permission definitions alongside your application code.

### [Events and extensibility](guides/platform/index.md)

React to identity events, run actions during authentication, record application
audit logs, and stream activity to your operational tools.

## Resources and tools

- **[SDKs](reference/sdk/index.md)** — choose a browser, React, Go, Node.js or Python integration.
- **[API reference](reference/api/index.md)** — authentication, endpoint families and the [OpenAPI schema](reference/api/openapi.md).
- **[CLI](reference/cli.md)** — configure and manage IAMKit from your terminal.
- **[Migrate users](guides/migration/importing-users.md)** — bring existing identities and supported password hashes from another provider.
- **[Identity model](concepts/identity-model.md)** and **[glossary](concepts/glossary.md)** — understand environments, organizations, applications and resources.

## Deploy and operate

Choose a [deployment](operations/deployment.md), configure
[TLS and your reverse proxy](operations/reverse-proxy.md), and review the
[launch checklist](operations/launch-checklist.md) before production.
Use [observability](operations/observability.md) and
[troubleshooting](operations/troubleshooting.md) to diagnose integration issues.

Working on IAMKit itself? See [contributing](contributing/local-development.md)
and the [architecture](contributing/architecture.md).
