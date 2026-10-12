# Users and organizations

Represent your customers as organizations and give people access through
memberships. A user belongs to an environment and can participate in more than
one organization without duplicating their identity.

## Understand the model

Read the [identity model](../../concepts/identity-model.md) first if you are new
to IAMKit. An organization provides the tenant boundary; an application and its
API resource define what a person can access inside that boundary.

## Build your onboarding flow

1. [Create organizations and memberships](organizations.md) for your customers and their people.
2. Choose [self-service sign-up, invitations or backend provisioning](../sign-in/signup-and-onboarding.md). Do not trust role or tenant choices from a public form.
3. Assign [roles and permissions](../authorization/index.md) for the application's resource.
4. Configure [profiles](user-profiles.md) for the user data your application needs.

Use [domain-based membership](domain-join.md) when verified company domains
should admit eligible users to an organization. Connect
[enterprise SSO and provisioning](../enterprise/index.md) when a customer owns
their identity lifecycle.

## Let customers administer themselves

The [organization administration API and hosted portal](organization-administration.md)
let customer administrators manage people, roles, domains and connections in
their own organization. They do not receive operator access to your deployment.
Use scoped permissions or setup links for the tasks they need.

For self-service account screens in your application, use
[React account widgets](../../reference/sdk/react-widgets.md). These are separate
from customer administrator screens.

## Verify tenant boundaries

Test with a user who belongs to two organizations. Their token is scoped to the
selected organization, not all their memberships: your API must still
[reject cross-tenant requests](../../start/protect-an-api.md).

## Next steps

- [User profiles](user-profiles.md) — profile properties, verification and claims.
- [Impersonation](impersonation.md) — controlled support access.
- [Users and organizations API](../../reference/api/users-and-organizations.md) — management endpoints.
