# Microsoft Entra ID login

Prerequisites: [federation setup](federation.md), HTTPS IAMKit issuer and authority
to register an Entra application. Validate the full login with a test tenant before
rolling it out; this is not evidence of every Microsoft account-type combination.

1. Register a web application and choose the intended tenant/account policy.
2. Add `https://YOUR_IAMKIT_HOST/identity/v1/federation/callback` as an exact web
   redirect URI. Create/store a client secret and record its expiry.
3. For a single-tenant setup use the tenant-specific issuer
   `https://login.microsoftonline.com/TENANT_UUID/v2.0`, not a guessed `common`
   issuer. Compare the provider discovery document's issuer to the configured one.
4. Approve the exact environment/issuer/client/secret reference in deployment
   configuration, then create the local federation connection.
5. Link the verified OIDC `sub` for this issuer/client to the local user. Do not
   replace it with email, display name, or an Entra object ID without proving it
   is the same subject claimed by the ID token.
6. Start federation with a complete local access boundary and verify callback.

A general multi-tenant Microsoft login can require issuer handling beyond an
exact tenant issuer; do not assume the generic adapter supports that merely
because a `common` authorization URL exists. Prefer explicit trusted tenant
connections unless the desired policy has been implemented and tested.

Test issuer mismatch, expired client secret, unlinked subject and local grant
denial. Microsoft authentication does not imply permission in InvoiceCloud.

Provider documentation: [Microsoft OIDC protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).
