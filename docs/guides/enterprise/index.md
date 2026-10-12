# Enterprise connections

Let each customer connect their organization's identity provider and directory
to your application. Single sign-on verifies a person's identity; provisioning
maintains users and groups. Configure them separately and test both.

## Before you begin

Create an [organization](../organizations/organizations.md) for your customer,
link your application to its API resource, and make sure IAMKit's HTTPS callback
is reachable from the identity provider. You need administrator access to the
customer's provider or a customer administrator who can complete the setup.

## Choose a connection

| Your customer's system | Start with |
| --- | --- |
| A SAML 2.0 identity provider | [SAML SSO](saml.md) |
| An OpenID Connect provider | [OpenID Connect federation](federation.md) |
| An LDAP or Active Directory server | [LDAP and Active Directory](ldap.md) |
| A directory that provisions users through SCIM | [SCIM provisioning](scim-provisioning.md) |

For Okta, Microsoft Entra ID, Google Workspace and other providers, follow the
[identity provider setup guides](idp-guides.md). They match the guided setup in
the management console and customer admin portal.

## Set up and test single sign-on

1. Create a connection for the customer's organization.
2. Exchange IAMKit's callback or SAML metadata with the provider, then save its configuration in IAMKit.
3. Use [Test connection](idp-guides.md#test-connection) before enabling browser SSO. The link opens a confirmation page; continuing starts the test without creating a user, session or identity link. LDAP is tested by signing in with a directory account instead.
4. Enable the connection. Only [enforce SSO](federation.md#organization-sso) after testing it with the customer's users and reviewing bypass settings.

Give customers control of this workflow with
[organization administration](../organizations/organization-administration.md).
They can manage their own connections without environment-wide operator access.

## Add directory provisioning

[SCIM](scim-provisioning.md) synchronizes identities and groups; it is not a
sign-in method. Configure its directory token separately and test create,
update and deactivate operations. Assign roles to [SCIM-provisioned groups](scim-provisioning.md#groups)
when pushed directory membership should grant access.

[SSO group mapping](federation.md#group-mapping) is a different mechanism: it
maps group claims received during sign-in to operator-managed organization
groups, not SCIM-owned groups.

## Next steps

- [Organizations and memberships](../organizations/organizations.md) — decide how customer users get access.
- [Authorization](../authorization/index.md) — grant permissions independently of successful SSO.
- [Integration API](../../reference/api/integrations.md) — connection and provisioning endpoints.
