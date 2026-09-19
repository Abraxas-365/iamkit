# IAMKit documentation

Self-host authentication and tenant-aware authorization while your application
owns onboarding, UI and business data. Start with one working application, then
choose the login methods and operational controls you need.

## Known integration blocker

The JWT-based `/api/v1` management surface has
[environment and permission-routing blockers](reference/api/scoped-iam.md#deployment-blockers).
Keep it restricted until corrected and tested. The onboarding tutorial uses the
separate workspace-operator management API; its credential is intentionally broad.

## Start here

1. [Overview and responsibilities](start/overview.md)
2. [Run IAMKit with Docker](start/docker-quickstart.md)
3. [Provision your first application](start/first-application.md)
4. [Protect an API and reject cross-tenant access](guides/protect-an-api.md)
5. [Set up the management console](start/management-console.md)

## Understand the model

[Identity hierarchy](concepts/identity-model.md) ·
[Credentials and boundaries](concepts/credentials-and-boundaries.md) ·
[Authorization](concepts/authorization.md) ·
[Sessions and tokens](concepts/sessions-and-tokens.md)

## Integrate an application

- [Architecture and responsibility split](guides/application-integration.md)
- [Signup and onboarding](guides/signup-and-onboarding.md)
- [Password login](guides/password-login.md), [email OTP](guides/email-otp.md),
  [password reset](guides/password-reset.md), [email verification](guides/email-verification.md)
- [Email delivery webhook](guides/email-delivery.md)
- [OIDC federation](guides/federation.md): [Google](guides/google-login.md),
  [Microsoft](guides/microsoft-login.md)
- [OAuth/OIDC clients](guides/oauth-oidc.md)
- [Organizations](guides/organizations.md), [service accounts](guides/service-accounts.md),
  [SCIM provisioning](guides/scim-provisioning.md), [impersonation](guides/impersonation.md)
- [Runnable examples and prerequisites](examples/README.md)

## Reference

[API families](reference/api/index.md) · [Go SDK](reference/sdk/go.md) ·
[Configuration](reference/configuration.md) · [CLI](reference/cli.md) ·
[Token claims](reference/token-claims.md) · [Webhooks](reference/webhooks.md) ·
[Errors and pagination](reference/errors-and-pagination.md) · [Glossary](reference/glossary.md)

## Operate

[Deployment](operations/deployment.md) · [TLS/proxy/CORS](operations/reverse-proxy.md) ·
[Secrets](operations/secrets-and-keys.md) · [Migrations](operations/database-and-migrations.md) ·
[Backup and restore](operations/backup-and-restore.md) ·
[Upgrades and rollback](operations/upgrades-and-rollback.md) ·
[Observability](operations/observability.md) · [Scaling and abuse](operations/scaling-and-abuse.md) ·
[Incident response](operations/incident-response.md) ·
[Troubleshooting](operations/troubleshooting.md) · [Launch checklist](operations/launch-checklist.md)

## Maintain

[Architecture](maintainers/architecture.md) · [Local development](maintainers/local-development.md) ·
[Testing](maintainers/testing.md) · [Releases](maintainers/releases.md) ·
[Validation record and remaining acceptance work](maintainers/validation.md)
