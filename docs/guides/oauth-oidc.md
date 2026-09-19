# OAuth/OIDC client integration

Use this flow when your app is an OAuth client of IAMKit. For “Sign in with
Google,” use [federation](federation.md) instead. IAMKit fixes each OAuth client's
application/resource binding at registration; that is a product boundary, not a
universal OAuth requirement.

## Register

Operator POSTs `/management/v1/environments/ENV_UUID/oauth-clients` with
`application_id`, `resource_id`, `redirect_uris` and `public`. The app/resource must
be linked. Redirects must be exact HTTPS URLs. Capture `client_id`; a confidential
client also receives `client_secret` once. Never put a confidential secret in a SPA.

## Complete authorization code + S256 PKCE

1. Client generates cryptographically random state, nonce and PKCE verifier; save
   them in the initiating browser/BFF session. Compute the S256 challenge.
2. GET `/oauth/authorize` with `response_type=code`, client ID, exact redirect URI,
   state, nonce, scope including `openid`, `code_challenge`, and
   `code_challenge_method=S256`.
3. IAMKit returns JSON containing `authorization_ticket` and client context, and
   sets a Secure browser-binding cookie. It does **not** render a hosted login page.
4. Your interaction UI signs the user in to the same app/resource and displays
   consent. POST `/oauth/authorize/complete` with the user access token, browser
   cookie and `{authorization_ticket,approve:true}`.
5. Follow the authorization response to the registered callback. Verify state,
   then exchange the code with the original verifier at `/oauth/token`.
6. Validate the ID token's issuer/audience/nonce for client identity; use only the
   access token for API authorization.

The interaction must remain browser-bound over HTTPS. Do not try to complete a
stolen ticket from a server without the binding. `prompt` and `max_age` are rejected,
not silently accepted as fresh-authentication guarantees. Request `offline_access`
when refresh is needed and manage refresh rotation/replay carefully.

**Verify:** successful code exchange once; wrong verifier, reused code, incorrect
redirect and mismatched login boundary fail. Test denial separately. See
[protocol reference](../reference/api/oauth-oidc.md).
