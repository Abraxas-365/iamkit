# OIDC federation

Use federation when an external provider authenticates your users. It is separate
from registering OAuth clients that obtain tokens from IAMKit. There are two
kinds of connection:

- **Organization connections** (`organization_id` set) are enterprise SSO for
  one tenant, e.g. Acme's Entra ID or Okta. They add email discovery,
  just-in-time (JIT) provisioning, a default group and optional enforcement.
  The client secret is stored encrypted.
- **Environment connections** (no `organization_id`) are the original model:
  any organization, explicitly linked users only, client secret held in an
  approved deployment variable.

Prerequisite for both: an HTTPS issuer and the exact callback
`${JWT_ISSUER}/identity/v1/federation/callback` registered at the provider with
a server-side client secret.

## Organization SSO

1. Set `IAMKIT_ENCRYPTION_KEY` (see [configuration](../reference/configuration.md#encryption-key)).
2. Verify at least one domain of the organization (Members → Domains, or
   [domain API](../reference/api/users-and-organizations.md#domains)). JIT and
   enforcement act only on emails in the organization's verified domains.
3. Optionally create an operator-managed group bound to roles (Members → Groups)
   so new users get access on their first login.
4. Create the connection:

   ```http
   POST /management/v1/environments/ENV_UUID/federation-connections
   {"organization_id":"ORG_UUID","name":"Acme Entra","issuer":"https://login.microsoftonline.com/TENANT/v2.0",
    "client_id":"CLIENT_ID","client_secret":"CLIENT_SECRET","jit_group_id":"GROUP_UUID"}
   ```

   `jit_provisioning` defaults to `true`; `enforcement` defaults to `optional`.
   The secret is never returned; detail shows `secret_source: "sealed"`.
5. Test a login, then optionally `PATCH` `{"enforcement":"enforced"}`.

### Discovery

Your login screen asks for the email first and calls
`POST /identity/v1/discover` with `{environment_id,email}`:

```json
{"method":"sso","organization_id":"ORG_UUID","connection_id":"CONN_UUID","required":true}
```

`method: "sso"` means start federation with that connection and organization;
`"password"` means show the password (or email code) form. The answer depends
only on the email's domain, never on whether an account exists, so it cannot be
used to enumerate users. It is rate limited per IP.

### Just-in-time provisioning

On the first login through an organization connection with an unlinked subject,
IAMKit:

1. requires an `email` claim whose domain is verified by the organization and
   rejects `email_verified: false` (an absent claim is accepted, since some
   enterprise providers omit it);
2. adopts the active local user with that email, or creates one (no password,
   email marked verified, name from the `name` claim);
3. links the provider subject (identity `origin: "jit"`), adds an active
   membership if there is none, and joins the default group if set.

A membership the operator deactivated is not re-activated. Without a default
group the account is created but has no roles, so the login is refused with
403 until access is granted. Later logins use the linked subject only; the
email claim is not consulted again. Only operator-managed groups (not SCIM
directory groups) can be the default group. With `jit_provisioning: false`,
users must be linked explicitly as for environment connections.

### Enforcement

With `enforcement: "enforced"`, password and email-code login in that
organization are refused with 403 code `SSO_REQUIRED` for emails in the
organization's verified domains. The check is per organization: the same user
may still use a password in another organization that does not enforce SSO.
Emails outside the verified domains (contractors, guests) are unaffected.
Password reset is not blocked, so a reset password simply stays unusable there.

If the provider cannot be reached or its discovery document is unusable, the
start fails with 502 code `PROVIDER_UNAVAILABLE` (the cause is logged, never
returned); hosted sign-in pages tell the user the SSO provider is not
responding. Check the issuer URL, DNS and outbound HTTPS — sealed-secret
connections only reach public addresses.

Break-glass: `PATCH /organizations/:organization/members/:user` with
`{"sso_bypass":true}` (console: key icon on Members) lets that member keep
using a password. Keep at least one administrator with the bypass before
enforcing, in case the provider is unavailable.

An organization can have one enforced connection. The last verified domain of
an organization with an enforced connection cannot be deleted (422); set
enforcement to `optional` first.

### Rotation and security

`PATCH` `{"client_secret":"…"}` replaces the stored secret (and converts an
environment-variable connection to an encrypted one). To rotate the encryption
key itself, see [configuration](../reference/configuration.md#encryption-key).

Because any operator may type an issuer URL, IAMKit refuses to contact
providers on private, loopback, link-local or shared addresses for connections
with stored secrets, and requires every provider endpoint to be HTTPS.

## Environment connections

1. Configure `FEDERATION_CREDENTIAL_BINDINGS` and the referenced
   `IAMKIT_PROVIDER_*` variable; see [configuration](../reference/configuration.md).
2. POST `/management/v1/environments/ENV_UUID/federation-connections` using
   `X-API-Key` and `{name,issuer,client_id,secret_env}`. Save its 201 `{id}`.
3. Obtain the verified provider subject for that exact issuer/client from a
   trusted enrollment process. POST `/external-identities` under the same prefix
   with `{connection_id,user_id,subject}`. Never use email as a substitute for `sub`.

Environment connections never create users or link equal emails. One local
user can be explicitly linked to several provider connections.

## Browser flow

```text
Browser → IAMKit /discover (optional): email → connection + organization
Browser → IAMKit /federation/start: full boundary + connection_id
IAMKit → browser: authorization_url + Secure binding cookie
Browser → external provider: redirect, authenticate
Provider → IAMKit /federation/callback: code + state, browser cookie
IAMKit → provider: code/PKCE exchange and ID-token verification
IAMKit → browser: local scoped token pair (JSON)
```

The start route is `/identity/v1/federation/start`; for an organization
connection the boundary's `organization_id` must be the connection's. Preserve
the cookie in the same browser that completes the callback. The server verifies
state, nonce, PKCE, issuer/client and subject link. Callback currently returns
JSON tokens; implement a controlled same-origin/BFF handoff if your product
needs a redirect. Do not redirect tokens in query strings or expect a built-in
login UI.

## Operations and verification

GET connection detail/identities to inspect links and their origin. DELETE
`/external-identities/:connection/:user` to unlink or DELETE
`/federation-connections/:id` to disable a connection. Removing a login method is
not automatically proof all existing sessions are revoked; revoke sessions when
that is the intended action.

Verify: linked login, unlinked subject denial, wrong nonce/state, missing
binding cookie; for organization connections also discovery for a verified and
an unverified domain, a JIT login with and without a default group, a provider
email outside the verified domains (401), and `SSO_REQUIRED` for a password
login after enforcing. If environment connection creation says binding not
approved, compare all four deployment values exactly. See
[Google](google-login.md) and [Microsoft](microsoft-login.md).
