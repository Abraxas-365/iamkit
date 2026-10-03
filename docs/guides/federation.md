# OIDC federation

Use federation when an external provider authenticates your users. It is separate
from registering OAuth clients that obtain tokens from IAMKit. There are two
kinds of connection:

- **Organization connections** (`organization_id` set) are enterprise SSO for
  one tenant, e.g. Acme's Entra ID or Okta. They add email discovery,
  just-in-time (JIT) provisioning, a default group and optional enforcement.
  The client secret is stored encrypted.
- **Environment connections** (no `organization_id`) serve every
  organization: [social login](social-login.md) with Google, Microsoft,
  GitHub or Apple, optionally with sign-up and linking by verified email, or
  explicitly linked users only.

Every connection has a `provider`: a preset (`google`, `microsoft`, `github`,
`apple`) whose issuer and endpoints IAMKit knows, or `oidc` (default) for any
OpenID Connect provider with an `issuer`. Organizations whose identity
provider speaks SAML 2.0 use a `saml` connection instead — see
[SAML single sign-on](saml.md). Organizations with an LDAP directory or
Active Directory use an `ldap` connection — see [LDAP](ldap.md). Presets work for both kinds, e.g. an
organization's Google Workspace or Entra tenant.

Prerequisite for both: the exact callback
`${JWT_ISSUER}/identity/v1/federation/callback` (`callback_url` on the
connection detail) registered at the provider with a server-side client
secret, and for `oidc` an HTTPS issuer.

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
users must be linked explicitly as for environment connections, unless
`link_email` is on.

### Linking members by email

`"link_email": true` on an organization connection links, without JIT, an
unlinked subject to the **existing member** whose email the provider sends,
when that email is on one of the organization's verified domains and is not
`email_verified: false`. Nobody is created and no membership is added: a
non-member, an unknown email or another domain gets 401. The identity has
`origin: "email"` and the link is audited `federation.email`. With JIT on as
well, JIT's adopt-or-create applies instead.

`"update_profile": true` refreshes a linked user's name and avatar at every sign-in, and
their email when it changes to another verified-domain address and the
account is passwordless and not SCIM-managed (see
[social login](social-login.md#keeping-profiles-in-sync)).

Organization SSO also accepts `"provider":"gitlab"` with `options.base_url`
for a company's self-managed GitLab.

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
connections only reach public addresses (in development,
[`IAMKIT_ALLOW_PRIVATE_DELIVERY`](../reference/configuration.md#private-delivery-addresses-development-only)
lifts this).

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

For social login with sign-up and email linking, follow
[social login](social-login.md). Without either, users must be linked
explicitly:

1. Configure `FEDERATION_CREDENTIAL_BINDINGS` and the referenced
   `IAMKIT_PROVIDER_*` variable; see [configuration](../reference/configuration.md),
   or set `IAMKIT_ENCRYPTION_KEY` and send `client_secret` instead.
2. POST `/management/v1/environments/ENV_UUID/federation-connections` using
   `X-API-Key` and `{name,issuer,client_id,secret_env}`. Save its 201 `{id}`.
3. Obtain the verified provider subject for that exact issuer/client from a
   trusted enrollment process. POST `/external-identities` under the same prefix
   with `{connection_id,user_id,subject}`. Never use email as a substitute for `sub`.

With `signup` and `link_email` off (the default), environment connections
never create users or link equal emails. One local user can be linked to
several provider connections.

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
state, nonce, PKCE, issuer/client and subject link. Without `return_to` the
callback answers JSON tokens at IAMKit's own URL; do not redirect tokens in
query strings.

### Returning to a custom sign-in UI

A sign-in UI on another origin (the `@iamkit/js` `federation` flow) adds
`return_to` and `code_challenge` to the start body:

```text
UI → IAMKit /federation/start: boundary + connection_id + return_to + code_challenge (S256)
… provider round trip as above …
IAMKit → browser: 303 return_to?federation_result=ik_fedres_…  (or ?error=CODE&error_description=…)
UI → IAMKit POST /federation/result: federation_result + code_verifier → like /login
```

`return_to` must be an absolute `https` URL (http only on localhost) on an
origin some active OAuth client of the boundary's application lists in
`allowed_origins`; anything else is 400. The callback stores no token: it
parks the verified identity for one minute under a one-time handle. Only the
holder of the verifier (kept by the UI, e.g. in `sessionStorage`) redeems it;
a wrong verifier spends the handle (401). Redemption issues the session then,
so a second factor, a refused method or missing access answers exactly like
`/identity/v1/login` (MFA pending token, 403).

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
[social login](social-login.md), [Google](google-login.md) and [Microsoft](microsoft-login.md).
