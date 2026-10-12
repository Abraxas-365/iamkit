# Authorization

Decide what users and services can do in your application. A user's application
token carries permissions for an API resource and a selected organization;
your API checks both before accessing tenant data. Machine tokens have no
organization or user session: give them separate access policies.

## Start with one resource

Follow [your first application](../../start/first-application.md) to create an API
resource, link an application and grant a user access. Then
[protect your API](../../start/protect-an-api.md) to verify allowed requests and
cross-tenant denials.

## Model roles and permissions

Define a catalog of exact permission strings for each resource, such as
`invoices:read` and `invoices:write`. Use direct grants, resource roles and group
role assignments to give members the permissions they need.

The [authorization model](../../concepts/authorization.md) explains how those
sources combine. Membership or a successful SSO sign-in alone does not grant
API access. A resource can also
[require an organization grant](../organizations/organization-administration.md#resource-grants-vendor-organizations).

Keep the catalog and role definitions in your repository with
[permissions as code](../applications/permissions-as-code.md). This keeps the
strings your backend checks aligned with the configuration in IAMKit.

## Enforce access in your application

Use [API middleware](../../reference/sdk/index.md) or a verifier to check the
token's issuer, audience and permissions. For user application tokens, scope
queries to the token's organization. Do not apply that assumption to machine
tokens or API keys; check their [credential-specific boundaries](../../concepts/credentials-and-boundaries.md)
and [token claims](../../reference/token-claims.md). Choose introspection when
you need current-state evaluation rather than relying on permissions captured
in a token until expiry.

IAMKit's roles do not replace your application's rules for individual business
objects. Keep those checks in your API alongside permission and tenant checks.

## Authenticate non-browser callers

- [Service accounts](../machines/service-accounts.md) — OAuth credentials for a backend service.
- [Machine users](../machines/machine-users.md) — machine identities with resource permissions.
- [API keys](../machines/api-keys.md) — scoped credentials owned by a user, organization or machine.

## Reference

[Applications and authorization API](../../reference/api/applications-and-authorization.md) ·
[Token claims](../../reference/token-claims.md) ·
[Scoped IAM API](../../reference/api/scoped-iam.md)
