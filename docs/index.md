# IAMKit documentation

Self-host authentication and tenant-aware authorization while your application
owns onboarding, UI and business data. Start with one working application, then
add the sign-in methods and operational controls you need.

## Start here

1. [Overview and responsibilities](start/overview.md): what IAMKit does and what stays yours.
2. [Run IAMKit with Docker](start/docker-quickstart.md)
3. [Provision your first application](start/first-application.md)
4. [Protect an API and reject cross-tenant access](start/protect-an-api.md)
5. [Set up the management console](start/management-console.md)

Then read the [concepts](concepts/identity-model.md): the
[identity hierarchy](concepts/identity-model.md),
[credentials and boundaries](concepts/credentials-and-boundaries.md),
[authorization](concepts/authorization.md) and
[sessions and tokens](concepts/sessions-and-tokens.md). The
[glossary](concepts/glossary.md) defines the terms.

## Guides by goal

| I want to… | Read |
| --- | --- |
| Choose how people sign in | [Sign-in methods](guides/sign-in/sign-in-methods.md), [passwords](guides/sign-in/passwords.md), [email codes](guides/sign-in/email-otp.md), [multi-factor and passkeys](guides/sign-in/mfa.md), [password policy](guides/sign-in/password-policy.md), [signup](guides/sign-in/signup-and-onboarding.md) |
| Connect my application | [Integration architecture](guides/applications/application-integration.md), [OAuth/OIDC clients](guides/applications/oauth-oidc.md), [hosted login](guides/applications/hosted-login.md), [custom sign-in UI](guides/applications/custom-sign-in-ui.md), [signing keys](guides/applications/signing-keys.md), [IAMKit as a SAML IdP](guides/applications/saml-apps.md) |
| Let customers bring their identity provider | [OIDC federation](guides/enterprise/federation.md), [social login](guides/enterprise/social-login.md), [SAML](guides/enterprise/saml.md), [LDAP / Active Directory](guides/enterprise/ldap.md), [SCIM provisioning](guides/enterprise/scim-provisioning.md) |
| Model tenants and people | [Organizations](guides/organizations/organizations.md), [customer-side administration](guides/organizations/organization-administration.md), [user profiles](guides/organizations/user-profiles.md), [impersonation](guides/organizations/impersonation.md) |
| Authenticate services | [Service accounts](guides/machines/service-accounts.md), [machine users and access tokens](guides/machines/machine-users.md) |
| Extend and tune the platform | [Actions](guides/platform/actions.md), [email delivery](guides/platform/email-delivery.md), [feature flags](guides/platform/feature-flags.md), [usage and limits](guides/platform/usage-limits.md) |

Runnable code is in the [examples](examples/README.md).

## Reference

- **HTTP API:** [overview and families](reference/api/index.md), including the
  [OpenAPI document](reference/api/openapi.md).
- **Go SDK:** [overview](reference/sdk/go.md), [middleware](reference/sdk/middleware.md),
  [authentication](reference/sdk/authentication.md), [management](reference/sdk/management.md)
  and [SCIM](reference/sdk/scim.md).
- **Platform:** [configuration](reference/configuration.md), [CLI](reference/cli.md),
  [token claims](reference/token-claims.md), [errors and pagination](reference/errors-and-pagination.md).
- **Events:** [event log](reference/events.md), [event webhooks](reference/event-webhooks.md)
  and the [email webhook contract](reference/email-webhooks.md).

## Operate

| Stage | Read |
| --- | --- |
| Deploy | [Deployment](operations/deployment.md), [TLS, proxy and CORS](operations/reverse-proxy.md), [secrets and keys](operations/secrets-and-keys.md), [database and migrations](operations/database-and-migrations.md) |
| Run | [Observability](operations/observability.md), [scaling and abuse](operations/scaling-and-abuse.md), [upgrades and rollback](operations/upgrades-and-rollback.md), [backup and restore](operations/backup-and-restore.md) |
| Prepare and respond | [Launch checklist](operations/launch-checklist.md), [incident response](operations/incident-response.md), [troubleshooting](operations/troubleshooting.md) |

## Contribute

[Architecture](contributing/architecture.md) · [Local development](contributing/local-development.md) ·
[Testing](contributing/testing.md) · [Releases](contributing/releases.md) ·
[Validation record](contributing/validation.md)
