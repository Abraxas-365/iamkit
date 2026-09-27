# Microsoft Entra ID login

Two ways to use Microsoft:

- **Social login** for Microsoft accounts: an environment connection with
  `"provider":"microsoft"` and `options.tenant` `common`, `organizations` or
  `consumers`, optionally limited to `options.tenants`. See
  [social login](social-login.md#microsoft) for the account types, the
  per-tenant issuer check and when an email counts as verified (`xms_edov`).
- **One organization's Entra tenant** as its enterprise SSO: an
  [organization connection](federation.md#organization-sso) with
  `"provider":"microsoft","options":{"tenant":"TENANT_ID"}` (or
  `"provider":"oidc"` and issuer `https://login.microsoftonline.com/TENANT_ID/v2.0`).

Register a *Web* application in Entra with the exact redirect URI
`${JWT_ISSUER}/identity/v1/federation/callback`, create a client secret and
record its expiry: rotate it with `PATCH {"client_secret":"…"}` before it
expires. The account types chosen in the registration must match
`options.tenant`, which cannot change after creation.

Multi-tenant tokens are verified against the issuer of the tenant that signed
them (`https://login.microsoftonline.com/{tid}/v2.0`), so a token from one
tenant can never pass as another's.

Test an allowed and a refused tenant, an expired client secret, an unlinked
subject and local grant denial. Microsoft authentication does not imply
permission in your application.

Provider documentation: [Microsoft OIDC protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).
