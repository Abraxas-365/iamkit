# OAuth/OIDC client integration

Use this flow when your app is an OAuth client of IAMKit. For “Sign in with
Google,” use [federation](../enterprise/federation.md) instead. IAMKit fixes each OAuth client's
application/resource binding at registration; that is a product boundary, not a
universal OAuth requirement.

## Register

Operator POSTs `/management/v1/environments/ENV_UUID/oauth-clients` with
`application_id`, `resource_id`, `redirect_uris`, `public` and optionally
`hosted_login` and `post_logout_redirect_uris` (or `iam oauth-clients create
--app … --resource … --redirect-uris … [--post-logout-redirect-uris …]`). The app/resource must
be linked. Redirects must be exact HTTPS URLs; `http` is accepted only on loopback
(`localhost`, `127.0.0.1`, `[::1]`) for local development and native/CLI apps
(RFC 8252 §7.3) — a registered `127.0.0.1`/`[::1]` URI matches any port, so a CLI
can listen on an ephemeral one. Such clients carry `warnings`
(`{code:"loopback_redirect", field, value}`) on create, read and list, and the
console flags them; a deployed web app must use https. Capture `client_id`; a confidential
client also receives `client_secret` once. Never put a confidential secret in a SPA.

A confidential client may instead authenticate with `private_key_jwt`
(`token_endpoint_auth_method`, plus a `jwks` or HTTPS `jwks_uri` of its public
keys; `iam oauth-clients create|update … --auth-method private_key_jwt
--jwks-uri URL`, or **OAuth clients → client → Token endpoint authentication**
in the console). It then signs a short-lived assertion for every token/revoke
request instead of sending the secret; see the
[protocol reference](../../reference/api/oauth-oidc.md). Machine-to-machine calls
without a user use [service accounts](../machines/service-accounts.md) and
`grant_type=client_credentials`.

## Complete authorization code + S256 PKCE

1. Client generates cryptographically random state, nonce and PKCE verifier; save
   them in the initiating browser/BFF session. Compute the S256 challenge.
2. GET `/oauth/authorize` with `response_type=code`, client ID, exact redirect URI,
   state, nonce, scope including `openid`, `code_challenge`, and
   `code_challenge_method=S256`.
3. IAMKit returns JSON containing `authorization_ticket` and client context, and
   sets a Secure browser-binding cookie (ticket valid 10 minutes). For clients
   with `hosted_login` it instead redirects to its own pages; see
   [hosted login](hosted-login.md) and skip to step 5.
4. Your interaction UI signs the user in to the same app/resource and displays
   consent. POST `/oauth/authorize/complete` with the user access token, browser
   cookie and `{authorization_ticket,approve:true}`. The
   [custom sign-in UI guide](custom-sign-in-ui.md) covers this step with
   `@iamkit/js`/`@iamkit/react`, `allowed_origins` and the security model.
5. Follow the authorization response to the registered callback. Verify state,
   then exchange the code with the original verifier at `/oauth/token`.
6. Validate the ID token's issuer/audience/nonce for client identity; use only the
   access token for API authorization.

The interaction must remain browser-bound over HTTPS. Do not try to complete a
stolen ticket from a server without the binding. Request `offline_access`
when refresh is needed and manage refresh rotation/replay carefully.

### `prompt` and `max_age`

IAMKit keeps no browser session between authorize requests: every authorization
runs a full sign-in, so the ID token's `auth_time` is always the sign-in made
for that request (it is present in every ID token, which is what OIDC requires
when `max_age` is sent). `prompt` is a space-separated list and is case
sensitive; discovery lists the values in `prompt_values_supported`.

| Value | Behaviour |
| --- | --- |
| `login` | Accepted. The user always signs in again. A custom sign-in UI that completes the authorization with a token issued before the authorize request is answered with `error=login_required`. With a federation connection of type OIDC, Google or Microsoft the provider is also asked for `prompt=login` (Google has no such value and only gets `select_account`), so it does not reuse its own session. Other connection types sign in as usual. See [Upstream providers](#upstream-providers) for what is checked when the user comes back. |
| `consent` | Accepted and a no-op: IAMKit has no consent screen. |
| `select_account` | Accepted. The hosted pages show the organization chooser even when the user belongs to a single organization (unless the request names the organization with `organization_id`, or an organization SSO connection fixes it). OIDC, Google and Microsoft providers are asked for `prompt=select_account` too. |
| `none` | There is never a session to reuse, so the browser is redirected to the client's `redirect_uri` with `error=login_required`, the `state` and an `error_description` (OIDC Core 3.1.2.6), without a ticket or sign-in page. This only happens after the client and redirect URI are validated. A custom sign-in UI that calls `/oauth/authorize` with `Accept: application/json` gets `{"redirect_to": "..."}` instead of a redirect it cannot read (`@iamkit/js` throws `LOGIN_REQUIRED` with `details.redirect_to`). |

`none` combined with any other value, and an unknown value, are `invalid_request`
(HTTP 400 before any redirect). `max_age` must be a non-negative integer of seconds,
otherwise `invalid_request`; any value is satisfied because the sign-in is made for
the request, and `max_age=0` behaves like `prompt=login`. The device authorization
flow and the other endpoints do not read these parameters.

#### Upstream providers

When the hosted sign-in goes through a federation connection, IAMKit cannot
make the provider's own session fresh by itself, so it asks and then checks:

- `max_age` is forwarded to connections of type OIDC, Google and Microsoft
  (together with `prompt=login` for `prompt=login` and `max_age=0`). SAML,
  LDAP, GitHub and other OAuth 2.0 connections never receive it.
- When the user returns, IAMKit reads the `auth_time` claim of the provider's
  ID token. For `prompt=login` or `max_age=0` the provider's sign-in must be
  no older than the moment the request started; for `max_age=N` it must be at
  most `N` seconds old. A minute of clock skew is allowed. Otherwise the sign-in
  is refused (`LOGIN_REQUIRED`, 401) and the hosted page asks the user to sign
  in again.
- A provider that sends no `auth_time` cannot be checked, so the sign-in is
  accepted. Providers that ignore `prompt=login` or `max_age` and omit
  `auth_time` therefore may still reuse their session; connection types
  that never receive the parameters are not checked either.

## Read the user, check tokens, sign out

Standard OIDC libraries find these through discovery:

- **UserInfo** — `GET /oauth/userinfo` with the OAuth access token returns
  `sub`, `name`, `picture` and `preferred_username` (scope `profile`), `email`/`email_verified` (scope `email`),
  `phone_number`/`phone_number_verified` (scope `phone`, when the user has one),
  `environment_id` and `organization_id`.
- **Introspection** — a resource server holding a *confidential* client of the
  same environment posts `token=…` to `/oauth/introspect` with HTTP Basic. The
  answer is `{"active":false}` for anything no longer valid, else the token's
  claims plus current `permissions` and `sid`. Prefer it over local JWT
  validation when you must see revocation immediately.
- **Logout** — send the browser to `/oauth/end_session?id_token_hint=…&post_logout_redirect_uri=…&state=…`.
  IAMKit ends the session named by the ID token's `sid` (revoking its refresh
  tokens) and redirects to the URI if the client registered it, else shows a
  "Signed out" page. Register post-logout URIs on the client page in the
  console or with `iam oauth-clients update CLIENT --post-logout-redirect-uris …`.

The Go SDK wraps these as `OAuthClient.UserInfo`, `Introspect` and
`EndSessionURL`.

### Opaque access tokens

By default access tokens are signed JWTs your APIs can verify offline. To keep
claims out of the token, switch the client to opaque tokens (console: client page
→ **Access tokens**; CLI: `iam oauth-clients update CLIENT --access-token-format opaque`;
API: `PATCH …/oauth-clients/:id {"access_token_format":"opaque"}`). New access
tokens become `ory_at_…` handles; ID tokens stay JWTs. Resource servers must call
`/oauth/introspect` (or `/oauth/userinfo`) to resolve them — `/api/v1`,
`/identity/v1` and the SDK validators accept JWTs only. Tokens issued before the
switch keep working until they expire.

### Back-channel logout

To end your application's own session when the IAMKit session ends — the user
signs out elsewhere, an operator revokes the session, the user is suspended,
loses access or is deleted — give the client a back-channel logout URL
(console: client page → **Back-channel logout**; CLI:
`iam oauth-clients update CLIENT --backchannel-logout-uri https://app.example/bc`;
API: `PATCH …/oauth-clients/:id {"backchannel_logout_uri":"https://…"}`; empty
turns it off). The URL must be HTTPS on a public address.

To accept logins that start at the customer's identity provider (SAML
[IdP-initiated login](../enterprise/saml.md#idp-initiated-login)), give the
client a sign-in endpoint (`initiate_login_uri`; console client page; CLI
`iam oauth-clients update CLIENT --initiate-login-uri https://app.example/login`;
API `PATCH …/oauth-clients/:id {"initiate_login_uri":"https://…"}`). IAMKit
redirects there with `iss`, `connection_id` and `organization_id`; your
endpoint then redirects to `/oauth/authorize` adding `connection_id` (and
`organization_id`) so the hosted login goes straight to that connection.

When a session the client signed in (through `/oauth/authorize`) ends, IAMKit
POSTs `logout_token=<JWT>` (form-encoded) to the URL. The token is signed with
the environment's key (verify with the JWKS), `aud` is your `client_id`, and it
carries `sub`, `sid` (the `sid` of the ID token), `jti`, `iat`, `exp` (two
minutes) and `events` with `http://schemas.openid.net/event/backchannel-logout`.
End your session for that `sid` and answer any 2xx. In Go:

```go
keys := authclient.NewKeySet(issuer+"/.well-known/jwks.json", nil)
token, err := authclient.ValidateLogoutToken(ctx, r.PostFormValue("logout_token"), keys, issuer, clientID)
if err != nil { w.WriteHeader(400); return }
sessions.EndBySID(token.SessionID)
```

Deliveries run in the background on every IAMKit replica. A failed delivery
(network error or non-2xx) is retried after 30 s, doubling, eight attempts in
all (about an hour), then given up and audited (`oauth.backchannel_failed`).
**Monitoring → Logout deliveries** in the console (or
`iam oauth-clients logout-deliveries list --status failed`) lists them and
retries a failed one. Sessions of `/identity/v1/login` are not tied to a client
and send no notification.

## Devices without a browser (device authorization grant)

TVs, CLIs and IoT devices that cannot open a browser or type a password use
the [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) device flow. The client
needs `hosted_login` (the user approves on IAMKit's hosted pages) and the grant
`urn:ietf:params:oauth:grant-type:device_code` in its `grant_types` — console:
client page → **Grant types → Device authorization**; CLI:
`iam oauth-clients create --app … --resource … --public --hosted-login
--grant-types device_code,refresh_token` (no redirect URIs needed without
`authorization_code`); API: `grant_types` on create/PATCH.

1. The device POSTs `client_id` (and its secret or assertion, if confidential)
   and optional `scope` to `/oauth/device_authorization`. It gets
   `device_code`, `user_code` (`BCDF-GHJK` style, 8 consonants),
   `verification_uri` (`<issuer>/hosted/device`),
   `verification_uri_complete`, `expires_in` (600) and `interval` (5).
2. It shows the user code and URL (or a QR code of the complete URL).
3. The user opens the URL on a phone or computer, enters the code, sees which
   application asks, and signs in through the ordinary hosted journey
   (password, codes, SSO, passkeys, MFA, organization chooser — all apply),
   or refuses with **This wasn't me**.
4. Meanwhile the device POSTs `grant_type=urn:ietf:params:oauth:grant-type:device_code`,
   `device_code` and `client_id` to `/oauth/token` every `interval` seconds.
   Until the user decides it gets `400 authorization_pending`; polling faster
   gets `slow_down` (add 5 s to the interval). Then it receives the same
   tokens as the code flow (access, ID token with `openid`, refresh token with
   `offline_access`) exactly once, or `access_denied` / `expired_token`.

In Go:

```go
c := authclient.NewOAuth(issuer, clientID, "")
auth, err := c.AuthorizeDevice(ctx, "openid", "offline_access")
fmt.Printf("Open %s and enter %s\n", auth.VerificationURI, auth.UserCode)
tokens, err := c.WaitDevice(ctx, auth) // polls, honors slow_down
```

## Calling another API as the user (token exchange)

A backend that received a user's access token for one resource (say *Web
API*) can get a token for another resource of the **same application** (say
*Reports API*) without sending the user through sign-in again —
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange. The client
must be confidential and have `urn:ietf:params:oauth:grant-type:token-exchange`
in its `grant_types` — console: client page → **Grant types → Token
exchange**; CLI: `iam oauth-clients update ID --grant-types
authorization_code,refresh_token,token_exchange`.

```
POST /oauth/token   (client authentication as usual)
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the user's access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<the target resource's audience>
scope=reports:read            (optional: narrow the permissions)
```

The answer is `{access_token, issued_token_type, token_type, expires_in}` —
no refresh or ID token. The new token keeps the user, organization, `amr` and
`auth_time`; its permissions are the user's permissions **on the target
resource** (recomputed, not copied). It lives in a child session of the
original: signing out, revoking or suspending ends both. Exchanging again for
the same resource reuses that child session. In Go:
`authclient.NewOAuth(issuer, clientID, secret).ExchangeToken(ctx, userToken,
"https://reports.example", "reports:read")`.

Service accounts that a workspace owner allowed to **impersonate** can also
get a user's token with the same grant — see
[impersonation](../organizations/impersonation.md#service-accounts-token-exchange).

**Verify:** successful code exchange once; wrong verifier, reused code, incorrect
redirect and mismatched login boundary fail. Test denial separately. See
[protocol reference](../../reference/api/oauth-oidc.md).
