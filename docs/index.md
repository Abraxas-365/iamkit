# IAMKit documentation

Self-host authentication and tenant-aware authorization while your application
owns onboarding, UI and business data. Start with one working application, then
choose the login methods and operational controls you need.

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
  [password reset](guides/password-reset.md), [email verification](guides/email-verification.md),
  [multi-factor (TOTP)](guides/mfa.md), [password policy, lockout and expiry](guides/password-policy.md),
  [user metadata and profile schemas](guides/user-profiles.md),
  [sign-in methods](guides/sign-in-methods.md)
- [Email delivery (webhook, SMTP, Resend) and email wording](guides/email-delivery.md)
- [OIDC federation](guides/federation.md): [social login (Google, Microsoft, GitHub, Apple)](guides/social-login.md),
  [Google](guides/google-login.md), [Microsoft](guides/microsoft-login.md),
  [SAML 2.0 single sign-on](guides/saml.md), [LDAP / Active Directory](guides/ldap.md)
- [OAuth/OIDC clients](guides/oauth-oidc.md), [hosted login pages](guides/hosted-login.md),
  [custom sign-in UI (`@iamkit/js`, `@iamkit/react`)](guides/custom-sign-in-ui.md),
  [signing keys and rotation](guides/signing-keys.md), [SAML applications (IAMKit as IdP)](guides/saml-apps.md),
  [feature flags (beta features)](guides/feature-flags.md), [actions (sign-in, token and request hooks)](guides/actions.md),
  [usage and limits](guides/usage-limits.md)
- [Organizations](guides/organizations.md), [let customers administer their organization](guides/organization-administration.md), [service accounts](guides/service-accounts.md), [machine users, personal access tokens and keys](guides/machine-users.md),
  [SCIM provisioning](guides/scim-provisioning.md), [impersonation](guides/impersonation.md)
- [Runnable examples and prerequisites](examples/README.md)

## Reference

[API families](reference/api/index.md) · [Go SDK](reference/sdk/go.md) ·
[Configuration](reference/configuration.md) · [CLI](reference/cli.md) ·
[Token claims](reference/token-claims.md) · [Event log](reference/events.md) · [Event webhooks](reference/event-webhooks.md) · [Webhooks](reference/webhooks.md) ·
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
