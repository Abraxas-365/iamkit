# Recipes

Task-oriented walkthroughs built from the primitives in the [API guide](api.md). Each recipe
assumes you already completed [bootstrap](../README.md#get-started) and hold an operator
`ik_mgmt_...` credential. Replace `ENV`, `PROJECT`, IDs, etc. with real UUIDs returned by the
calls that precede them.

## Recipe: onboard a new product (multi-tenant SaaS)

Goal: give a new product ("Saas Idea 1") its own isolated users, organizations and API.

1. Create a project and environment:
   ```
   POST /management/v1/projects                          {"name":"Saas Idea 1"}
   POST /management/v1/projects/{project}/environments    {"name":"production"}
   ```
2. Register the application and the API(s) it calls:
   ```
   POST /management/v1/environments/{env}/applications  {"name":"Saas Idea 1 Web","redirect_uris":["https://saasidea1.example/callback"]}
   POST /management/v1/environments/{env}/resources      {"name":"Saas Idea 1 API","audience":"https://api.saasidea1.example","permissions":["invoices:read","invoices:write"]}
   POST /management/v1/environments/{env}/application-resources {"application_id":"APP","resource_id":"RESOURCE"}
   ```
3. Create the first organization/tenant and its owning user:
   ```
   POST /management/v1/environments/{env}/organizations  {"name":"Acme Inc"}
   POST /management/v1/environments/{env}/users          {"email":"alice@example.com","name":"Alice","password":"a-long-initial-password"}
   POST /management/v1/environments/{env}/memberships    {"organization_id":"ORG","user_id":"USER","role":"owner"}
   ```
4. Grant that user permissions on the resource (membership alone issues no permissions):
   ```
   PUT /management/v1/environments/{env}/grants {"organization_id":"ORG","user_id":"USER","resource_id":"RESOURCE","permissions":["invoices:read"]}
   ```
5. The product's backend now logs users in with `POST /identity/v1/login` (see
   [User login](api.md#user-login)) using `environment_id`, `organization_id`, `application_id`,
   `resource_id` plus email/password.

Repeat step 1 with a `development`/`staging` environment name for an isolated non-production
identity store; nothing is shared between environments.

## Recipe: let a product's users sign in with Google

Goal: users of an application (e.g. "Saas Idea 1") authenticate via Google instead of a
password. See [External federation](api.md#external-federation) for the endpoint reference.

Federation connections are scoped to an **environment**, not to one application — every
application/resource in that environment can reuse the same Google connection by passing its
own `application_id`/`resource_id` at login time.

**One-time setup per environment:**

1. In Google Cloud Console, create an OAuth 2.0 client. Set the redirect URI to **IAMKit's own
   callback**, not the product's: `https://your-iamkit-host/identity/v1/federation/callback`.
   IAMKit is the OIDC relying party; the product application never talks to Google directly.
2. On the IAMKit deployment, approve the exact credential tuple (nothing works without this
   allow-list entry, regardless of what's posted to the management API):
   ```
   IAMKIT_PROVIDER_GOOGLE=<google client secret>
   FEDERATION_CREDENTIAL_BINDINGS=[{"environment_id":"ENV","issuer":"https://accounts.google.com","client_id":"<google client id>","secret_env":"IAMKIT_PROVIDER_GOOGLE"}]
   ```
3. Register the connection:
   ```
   POST /management/v1/environments/{env}/federation-connections
   {"name":"Google","issuer":"https://accounts.google.com","client_id":"<google client id>","secret_env":"IAMKIT_PROVIDER_GOOGLE"}
   ```
   → returns `connection_id`. Reuse it for every application in this environment.

**Per-user linking (required before that user can log in with Google):**

IAMKit does not auto-provision or auto-link accounts by email — this is an intentional
anti-takeover decision (see [Security status](../SECURITY.md)). A user must exist and be
explicitly linked to a Google `subject` (the OIDC `sub` claim) before federation login works:

```
POST /management/v1/environments/{env}/users               {"email":"alice@example.com","name":"Alice"}   // password omitted: passwordless
POST /management/v1/environments/{env}/external-identities  {"connection_id":"CONNECTION","user_id":"USER","subject":"<google sub>"}
```

If the product needs public self-service "Sign up with Google" (no operator in the loop), the
product's own backend — which holds the management credential — must perform this
create-user-then-link step itself, typically after its own lightweight verification of the
Google identity (e.g. a normal "Sign in with Google" button used only to obtain `sub`/email),
*before* redirecting into IAMKit's federation flow. IAMKit intentionally has no endpoint that
creates a user on first unverified federation callback.

**Login flow (per attempt, from the application):**

```
POST /identity/v1/federation/start
{"connection_id":"CONNECTION","environment_id":"ENV","organization_id":"ORG","application_id":"APP","resource_id":"RESOURCE"}
→ {"authorization_url": "..."}
```
Redirect the browser to `authorization_url`. Google authenticates the user and redirects to
IAMKit's callback, which verifies state/nonce/PKCE/issuer/subject and returns an IAMKit
`access_token`/`refresh_token` pair scoped to that application/resource/organization — exactly
like a password login.

The same steps work for Microsoft (or any verified OIDC provider): use a tenant-specific
issuer such as `https://login.microsoftonline.com/{tenant}/v2.0` instead of Google's.

## Recipe: give a background worker its own credential (no user)

Goal: a cron job or worker service calls a resource's API without impersonating a human.

```
POST /management/v1/environments/{env}/service-accounts
{"name":"Invoice sync worker","application_id":"APP","resource_id":"RESOURCE","permissions":["invoices:read"]}
```
Returns a one-time `ik_svc_...` secret. The worker exchanges it for a token:
```
POST /identity/v1/machine-token
Authorization: Bearer ik_svc_...
```
Returns a `purpose: machine` access token — no user membership, no organization-owner
privileges, and no refresh token (machine tokens are re-minted from the secret, not rotated).
Revoke with `DELETE /management/v1/environments/{env}/service-accounts/{id}` — this invalidates
outstanding tokens online immediately (offline validators still trust it until expiry).

## Recipe: provision users automatically from your identity provider (SCIM)

Goal: an external IdP (Okta, Azure AD, etc.) creates/updates/disables users in one organization
automatically. See [SCIM](api.md#scim) for the endpoint reference.

```
POST /management/v1/environments/{env}/provisioning-credentials {"name":"Okta","organization_id":"ORG"}
```
Returns a one-time `ik_scim_...` secret and a `connection_id`. Configure the IdP's SCIM
integration with base URL `https://your-iamkit-host/scim/v2` and that Bearer secret.

The IdP can now `POST /scim/v2/Users`, `PATCH`/`PUT`/`DELETE /scim/v2/Users/{id}`. Email
collisions fail rather than silently attaching to an existing user — to attach SCIM
provisioning to a user that already exists in IAMKit, link it explicitly first:
```
POST /management/v1/environments/{env}/provisioned-identities
{"connection_id":"CONNECTION","user_id":"USER","external_id":"IDP_USER_ID"}
```
This requires the user to already have membership in the connection's organization.

Rotate the secret without breaking existing identity links by supplying the existing
`connection_id` when creating a replacement credential, then revoke the old one:
```
POST   /management/v1/environments/{env}/provisioning-credentials {"name":"Okta","organization_id":"ORG","connection_id":"CONNECTION"}
DELETE /management/v1/environments/{env}/provisioning-credentials/{old_id}
```

## Recipe: protect your Fiber API with permission checks

Goal: an application's own backend (the resource owner) validates incoming access tokens and
enforces exact permissions, using the Go SDK instead of hand-rolled JWT parsing.

```go
import (
    "github.com/Abraxas-365/iamkit/sdk/authclient"
    "github.com/Abraxas-365/iamkit/sdk/authclient/fiberauth"
)

client := authclient.Client{BaseURL: "https://your-iamkit-host"}
validate := func(ctx context.Context, token string) (*authclient.Claims, error) {
    // Live validation: reflects revocation/logout immediately.
    return client.Introspect(ctx, token, "https://your-iamkit-host", "https://api.saasidea1.example", "ENV", "APP", "RESOURCE")
}

app.Use("/invoices", fiberauth.Authenticate(validate))
app.Get("/invoices", fiberauth.RequirePermissions("invoices:read"), handler)
```

For offline validation (no round trip to IAMKit per request, at the cost of not observing
revocation until token expiry), use `authclient.Validate` with the RSA public key from
`GET /.well-known/jwks.json` instead of `client.Introspect`.

## Recipe: temporarily act as a user for support (impersonation)

Goal: an operator investigates a support ticket by obtaining a short-lived token scoped to a
specific user, without a password reset.

```
POST /management/v1/environments/{env}/impersonations
{"organization_id":"ORG","application_id":"APP","resource_id":"RESOURCE","user_id":"USER","reason":"Support ticket #4821: investigating missing invoice"}
```
Owner-only. `reason` must be 10–1000 characters and is recorded in the audit log along with the
operator's `actor_id`. The returned token expires in 15 minutes, has no refresh token, cannot
update the impersonated user's self-service profile (`PATCH /identity/v1/me` returns 403), and
cannot authorize new OAuth grants. Normal resource-permission checks still apply to the
impersonated user's access.

## Recipe: let an application use its own OAuth/OIDC login screen

Goal: an application wants a standard authorization-code + PKCE flow (e.g. a third-party client,
or a mobile app) instead of calling `/identity/v1/login` directly. See
[OAuth/OIDC server](api.md#oauthoidc-server) for the full reference.

```
POST /management/v1/environments/{env}/oauth-clients
{"application_id":"APP","resource_id":"RESOURCE","redirect_uris":["https://saasidea1.example/callback"],"public":true}
```
Public clients (SPAs, mobile apps) get no secret; confidential clients receive a secret once.
The client then runs the standard code/PKCE dance against `/oauth/authorize`,
`/oauth/authorize/complete` (your own login UI authenticates the user first — IAMKit does not
host a login page), and `/oauth/token`. ID tokens identify the user; only the resource-bound
access token authorizes API calls.
