# OIDC federation

Use federation when an external provider authenticates your users. It is separate
from registering OAuth clients that obtain tokens from IAMKit. Prerequisites:
HTTPS issuer, trusted provider registration, an approved credential binding,
local user, membership and app/resource access.

## Configure and link

1. Register the exact callback `${JWT_ISSUER}/identity/v1/federation/callback` with
   the provider. Set a server-side client secret.
2. Configure `FEDERATION_CREDENTIAL_BINDINGS` and the referenced
   `IAMKIT_PROVIDER_*` variable; see [configuration](../reference/configuration.md).
3. POST `/management/v1/environments/ENV_UUID/federation-connections` using
   `X-API-Key` and `{name,issuer,client_id,secret_env}`. Save its 201 `{id}`.
4. Obtain the verified provider subject for that exact issuer/client from a
   trusted enrollment process. POST `/external-identities` under the same prefix
   with `{connection_id,user_id,subject}`. Never use email as a substitute for `sub`.

IAMKit does not create users on first provider login or automatically link equal
emails. One local user can be explicitly linked to several provider connections.

## Browser flow

```text
Browser → IAMKit /federation/start: full boundary + connection_id
IAMKit → browser: authorization_url + Secure binding cookie
Browser → external provider: redirect, authenticate
Provider → IAMKit /federation/callback: code + state, browser cookie
IAMKit → provider: code/PKCE exchange and ID-token verification
IAMKit → browser: local scoped token pair (JSON)
```

The start route is `/identity/v1/federation/start`; preserve its cookie in the
same browser that completes the callback. The server verifies state, nonce, PKCE,
issuer/client and subject link. Callback currently returns JSON tokens; implement
a controlled same-origin/BFF handoff if your product needs a redirect. Do not
redirect tokens in query strings or expect a built-in login UI.

## Operations and verification

GET connection detail/identities to inspect links. DELETE
`/external-identities/:connection/:user` to unlink or DELETE
`/federation-connections/:id` to disable a connection. Removing a login method is
not automatically proof all existing sessions are revoked; revoke sessions when
that is the intended action.

Verify linked login, unlinked subject denial, wrong nonce/state, and missing
binding cookie. If creation says binding not approved, compare all four deployment
values exactly. Only approve trusted discovery endpoints and restrict outbound
network access. See [Google](google-login.md) and [Microsoft](microsoft-login.md).
