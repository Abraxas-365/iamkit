# Glossary

- **API key:** `ik_key_…` secret owned by a user, an organization or a machine user; its permissions are recomputed on every use. See [API keys](../guides/machines/api-keys.md).
- **Audience:** identifier of the API expected to accept an access token.
- **Boundary:** environment/org/app/resource context selected for a user session.
- **Catalog:** exact permission names owned by one resource.
- **Connection:** configured federation or provisioning integration, with distinct
  credential and identity-mapping semantics for each protocol.
- **Environment:** isolated identity and application data namespace.
- **Federation:** verified identity from an external OIDC, OAuth 2.0, SAML or LDAP
  provider, resolved to a local user under the connection's linking/provisioning policy.
- **Grant:** permissions for an organization member on a resource.
- **IAM resource:** built-in resource whose explicit permissions gate `/api/v1`.
- **Introspection:** online check of current token/session/access state.
- **Management key:** opaque credential authenticating a workspace operator.
- **Membership:** association between a local user and organization; not a grant.
- **OAuth client:** registered app requesting tokens issued by IAMKit.
- **Operator:** workspace administrator identity, separate from end users.
- **Resource:** protected API with audience, prefix and permission catalog.
- **Role:** reusable set of resource permissions; assigned to organization users.
- **SCIM:** directory provisioning protocol; not a login method.
- **Service account:** machine identity bound to an application/resource.
- **Subject:** stable identifier in an issuer's verified identity token.

See [identity model](identity-model.md) for relationships.
