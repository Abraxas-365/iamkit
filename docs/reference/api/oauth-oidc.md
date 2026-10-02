# OAuth/OIDC protocol reference

Discovery: `GET /.well-known/openid-configuration`. Keys:
`GET /.well-known/jwks.json`. The configured issuer must match the client's trusted
issuer, including the public HTTPS origin.

| Endpoint | Contract |
| --- | --- |
| `GET /oauth/authorize` | Authorization code request; returns JSON ticket/context and Secure binding cookie, or `303` to `/hosted/login?ticket=…` for `hosted_login` clients |
| `POST /oauth/authorize/complete` | JSON `authorization_ticket`, `approve`; requires browser cookie and matching user Bearer token; `303` to the client, or `200 {redirect_to}` for `Accept: application/json` without `text/html` ([custom sign-in UI](../../guides/custom-sign-in-ui.md)); 403 `ORGANIZATION_HINT` for a session in another organization than the request named |
| `GET /hosted/login`, `POST /hosted/login/*` | [Hosted sign-in pages](../../guides/hosted-login.md) (HTML forms); every step requires the ticket and binding cookie |
| `GET,POST /hosted/invite` | Hosted invitation preview/accept (`token`) |
| `POST /oauth/device_authorization` | RFC 8628; form `client_id` (+ client authentication), optional `scope`; `{device_code,user_code,verification_uri,verification_uri_complete,expires_in,interval}` |
| `GET,POST /hosted/device`, `POST /hosted/device/approve`, `POST /hosted/device/deny` | Hosted device approval: enter the user code, confirm, then the hosted sign-in |
| `POST /oauth/token` | Form-encoded code, refresh, `client_credentials`, device code, token exchange or JWT-bearer grant; OAuth token response |
| `POST /oauth/revoke` | Form-encoded `token`, client authentication; protocol revocation response |
| `GET,POST /oauth/userinfo` | OIDC UserInfo; Bearer OAuth access token (or `access_token` form field on POST); `401` + `WWW-Authenticate: Bearer error="invalid_token"` otherwise |
| `POST /oauth/introspect` | RFC 7662; form `token` (+ optional `token_type_hint`), `client_secret_basic` of a confidential client |
| `GET,POST /oauth/end_session` | OIDC RP-Initiated Logout; `id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state` |
| `GET /saml/:environment/metadata` | [SAML IdP](../../guides/saml-apps.md) metadata (`application/samlmetadata+xml`); 404 for an unknown environment |
| `GET,POST /saml/:environment/sso` | SAML AuthnRequest (HTTP-Redirect or HTTP-POST, `SAMLRequest`, `RelayState`) of a registered service provider; `303` to `/hosted/login?ticket=ik_samlreq_…` with the binding cookie; the hosted sign-in ends in a page posting the signed `SAMLResponse` to the ACS URL; 400 for an invalid or unregistered request |

Authorize requires `client_id`, `response_type=code`, registered `redirect_uri`,
`state`, `nonce`, `scope` including `openid`, `code_challenge_method=S256` and
`code_challenge`. Supported scopes: `openid profile email phone offline_access`.
An optional organization hint — `organization_id=<id>` or a
`urn:iamkit:org:id:<id>` scope (the same organization when both; a malformed
one is `invalid_request`) — brands the hosted pages with the
[organization's overrides](../../guides/hosted-login.md#organization-branding)
and limits the sign-in to that organization (another organization's session
is refused, 403).
No implicit or password grant is advertised. `prompt`/`max_age` are unsupported.

Discovery advertises `userinfo_endpoint`, `introspection_endpoint`,
`end_session_endpoint`, `revocation_endpoint`, `claims_supported`,
`backchannel_logout_supported`, `backchannel_logout_session_supported` and
`device_authorization_endpoint`. Fields
are only ever added.

**UserInfo** answers `sub`, `environment_id` and `organization_id` always,
`name`, `picture` (when the user has an avatar) and `preferred_username` (when they have a username) with the `profile` scope (plus the [user schema's](../../guides/user-profiles.md) `x-iamkit-claim`
attributes, also added to ID tokens), `email` + `email_verified` with `email`,
`phone_number` + `phone_number_verified` with `phone` (when the user has a phone; also in ID tokens). It
needs an access token IAMKit issued at `/oauth/token` with the `openid` scope
(identity-API tokens from `/identity/v1/login` are refused) whose grant,
client and user session are still live.

**Introspection** authenticates the caller as a confidential OAuth client
(HTTP Basic); public clients and bad secrets get `401 invalid_client`. It
answers for access and refresh tokens of any client in the caller's
environment; anything else — unknown, expired, revoked, another environment,
ended session, disabled client — is `{"active":false}`. Active answers carry
`sub`, `client_id`, `scope`, `aud`, `iss`, `exp`, `iat`, `token_use`
(`access_token`/`refresh_token`), `token_type` (`Bearer`, access tokens) and
the IAMKit claims `environment_id`, `organization_id`, `application_id`,
`resource_id`, `permissions` (current, re-resolved), `sid`, `amr`,
`auth_time`. `/identity/v1/introspect` is unchanged.

**End session** accepts GET or form POST. `id_token_hint` must be an ID token
this issuer signed (expired tokens are accepted); its `sid` session is ended
and every refresh token and OAuth grant of it revoked (audited
`oauth.logout`, actor the user). `client_id`, when sent with a hint, must be
in its audience. `post_logout_redirect_uri` needs a client (`client_id` or the
hint) that registered it exactly; IAMKit then answers `302` to it, adding
`state`. Otherwise it renders a hosted "Signed out" page in the environment's
branding. Invalid requests render the page with the error (400) and never
redirect. Repeating a logout is harmless. ID tokens carry `sid`; sessions
record the OAuth client that created them (`sessions.oauth_client_id`).

Rate limits per IP: introspection and UserInfo 5× the general limit, end
session 30/min, device authorization the general limit, user-code entry
(`POST /hosted/device*`) 10/min, SAML SSO 30/min, SAML metadata 60/min.

**Device authorization grant** ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
Clients need `hosted_login` and `urn:ietf:params:oauth:grant-type:device_code`
in `grant_types`; others get `400 unauthorized_client`. `scope` must be a
subset of `openid profile email phone offline_access` (else `invalid_scope`). The
device code (`ik_device_…`) and the user code (8 letters from
`BCDFGHJKLMNPQRSTVWXZ`, shown `XXXX-XXXX`, case, spaces and dashes ignored)
are stored hashed; both expire after 10 minutes. On `/hosted/device` the user
enters the code, sees the application and requested scopes, and either
refuses (the code becomes `denied`) or continues into the ordinary hosted
sign-in on an internal authorization ticket; finishing it approves the code
(audited `oauth.device_approved`, actor the user, target the session) and
shows a "Device connected" page — nothing redirects. Polling
(`grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`,
client authentication) answers `authorization_pending` until then,
`slow_down` (and +5 s to the interval) when polled faster than the interval,
`access_denied`, `expired_token`, or `invalid_grant` for unknown or already
redeemed codes and codes of another client (`unauthorized_client`). Approved
codes are redeemed once for an access token, an ID token (`openid`) and a
refresh token (`offline_access` and the `refresh_token` grant) with the same
claims as the code flow; the session is bound to the client, so back-channel
logout applies.

**Token exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693),
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, advertised in
discovery `grant_types_supported`). `requested_token_type`, when given, must be
`urn:ietf:params:oauth:token-type:access_token`; `actor_token` is not
supported (the authenticated client or account is the actor). Answer:
`{access_token, issued_token_type: urn:ietf:params:oauth:token-type:access_token,
token_type: Bearer, expires_in}`, `Cache-Control: no-store`. Two subject types:

- `subject_token_type=urn:ietf:params:oauth:token-type:access_token` —
  resource exchange. Confidential OAuth clients with the grant in
  `grant_types` (public clients cannot have it; others get
  `unauthorized_client`), with client authentication as for other grants.
  `subject_token` is a user access token (JWT or opaque) of the client's
  application, not impersonated, whose session is live; otherwise
  `invalid_request`. `audience` (required) names a resource linked to the
  application, else `invalid_target`; the user must have access to it in the
  token's organization (`invalid_target`). Optional `scope` lists
  permissions to keep (a subset of the user's there, else `invalid_scope`).
  The token belongs to a child session (`sessions.parent_session_id`) of the
  subject's session — one live child per resource, reused, ending with its
  parent (trigger `session_children_ended`), expiring no later than it — or to
  the original session when `audience` is its own resource. It keeps `sid`
  (the child's), organization, `amr` and `auth_time`; `oauth_client_id` is not
  set. Audited `oauth.token_exchanged` when a child session is created.
- `subject_token_type=urn:iamkit:params:oauth:token-type:user_id` —
  impersonation by a service account (authenticated like
  `client_credentials`; `401 invalid_client` otherwise) with
  `can_impersonate` (else `unauthorized_client`). `subject_token` is the user
  ID, `organization_id` and `reason` (10–1000 trimmed characters) are
  required, `audience` is optional but must be the account's resource. The
  user must be active with access to the account's resource in that
  organization (`invalid_request`). The token (15 minutes, no refresh, no
  `auth_time`) carries `act: {"sub": "<account id>"}`; its session records
  `actor_account_id` and the reason, audited `oauth.impersonated`.

**JWT bearer** ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.1,
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, advertised in
discovery) signs in a [machine user](../../guides/machine-users.md#keys-jwt-bearer-login)
with one of its keys; no client authentication (a `client_assertion` is
`invalid_request`). Fields: `assertion` (header `kid` = key ID; `iss` = `sub`
= the machine user ID; `aud` = the issuer or its token endpoint; `exp` at most
one hour ahead; a `jti`, single use — shared replay table with
`private_key_jwt`), `organization_id`, `application_id`, `resource_id`, and
optional `environment_id` (the key's). Answer: `{access_token, token_type:
Bearer, expires_in}`, `Cache-Control: no-store`, no refresh or ID token; the
application JWT's session (`amr` `swk`) is reused per key and boundary and
ends when the key is removed. Every refusal (unknown or expired key, bad
signature or claims, replay, inactive user, no access) is `400 invalid_grant`.

**Client credentials** (`grant_type=client_credentials`) is for
[service accounts](../../guides/service-accounts.md): `client_id` is the
account ID. It authenticates with its `ik_svc_` secret (`client_secret_basic`
or `client_secret_post`) or, when configured, `private_key_jwt`
(`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion`; `client_id` may be omitted — the assertion's `sub` names
the account). The answer is the account's machine access token (same claims
and lifetime as `/identity/v1/machine-token`, no refresh token, no `scope`
parameter — permissions are the account's). Revoked, expired or unknown
accounts and bad credentials get `401 invalid_client`.

**private_key_jwt** ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)) is also
available to confidential OAuth clients (`token_endpoint_auth_method` on
create/PATCH) at `/oauth/token` and `/oauth/revoke`. Assertions: `iss` = `sub`
= client ID, `aud` = `<issuer>/oauth/token` (or the issuer), unique `jti`
(replay-checked per client until `exp`), `exp` at most one hour ahead, signed
with `token_endpoint_auth_signing_alg` (default RS256; RS/PS/ES 256–512) by a
key in the registered `jwks` (≤10 public RSA/EC keys) or `jwks_uri` (HTTPS,
public address only, ≤64 KB, cached one hour, refetched at most once a minute
for an unknown `kid`). Discovery advertises
`token_endpoint_auth_methods_supported` and
`token_endpoint_auth_signing_alg_values_supported`. Introspection still takes
the client secret over HTTP Basic.

Code exchange fields: `grant_type=authorization_code`, `code`, `redirect_uri`,
`code_verifier`, plus client identity/authentication. Refresh exchange uses
`grant_type=refresh_token` and `refresh_token`. Public clients have no secret;
confidential clients use `client_secret_basic` as advertised by discovery. Use a
standards-aware library for form/Basic credential encoding.

Authorization codes last five minutes; authorization tickets ten minutes; access and ID tokens fifteen minutes;
refresh lifespan is constrained by session validity. Replay protection is not a
license to retry old rotating credentials indiscriminately. Token endpoint errors
use OAuth fields (`error`, etc.), not the management JSON envelope.

Client administration: POST/GET `/management/v1/environments/:environment/oauth-clients`,
GET/PATCH `.../oauth-clients/:id` (`{hosted_login,redirect_uris,post_logout_redirect_uris,grant_types,access_token_format,backchannel_logout_uri,backchannel_logout_session_required,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks,jwks_uri}`, any of them; a changed method drops keys not given again), DELETE `.../oauth-clients/:id`.
Create also takes the four authentication fields (confidential clients only; public clients are always `none`).
Create also takes optional `grant_types` (default `["authorization_code","refresh_token"]`;
any of those two, `urn:ietf:params:oauth:grant-type:device_code` and
`urn:ietf:params:oauth:grant-type:token-exchange` (confidential clients only), no duplicates;
`refresh_token` alone is refused; the device grant needs `hosted_login`, and
`hosted_login` cannot be turned off while it is on; `redirect_uris` are required
only with `authorization_code`).
Create also takes optional `access_token_format`: `jwt` (default) or `opaque`.
Opaque access tokens (`ory_at_…`) are resolved only by `/oauth/introspect` (any
confidential client of the environment) and `/oauth/userinfo`; `/api/v1`,
`/identity/v1` and SDK local validation accept JWTs only. Refresh keeps the
client's current format; tokens issued before a format change keep validating;
revocation, logout and session end deactivate opaque tokens immediately.
Create also takes optional `backchannel_logout_uri` (HTTPS, no credentials or
fragment; `""` = off) and `backchannel_logout_session_required` (informational:
logout tokens always carry `sid`).

**Back-channel logout** (OpenID Connect Back-Channel Logout 1.0). When a session
bound to a client with a `backchannel_logout_uri` ends (`revoked_at` set by
logout, operator revocation, suspension, access changes; or the user deleted), a
database trigger queues a notification in the same transaction. Each replica's
dispatcher (every 5 s, `FOR UPDATE SKIP LOCKED` leases) POSTs
`application/x-www-form-urlencoded` `logout_token=…` over the guarded transport
(public addresses, 10 s timeout, no redirects). Logout token: header `typ:
logout+jwt`, `kid`; claims `iss`, `aud` (client ID), `iat`, `exp` (+2 min),
`jti`, `sub`, `sid`, `environment_id`, `events:
{"http://schemas.openid.net/event/backchannel-logout":{}}`, no `nonce`. Any 2xx
is delivered; otherwise retried after 30 s × 2ⁿ (max 1 h) for 8 attempts in
total, then marked failed and audited `oauth.backchannel_failed` (actor: the
user, target: the client). A client whose URI was removed or that was disabled
fails its pending notifications. Finished notifications are kept 7 days.

Delivery log: GET `.../logout-deliveries` (page of `{id,client_id,application_name,session_id,user_id,user_email,status,attempts,last_error,created_at,next_attempt_at,delivered_at,failed_at}`,
newest first; `status=pending|delivered|failed`, `client_id`, `search` on user
email or application name). POST `.../logout-deliveries/:id/retry` requeues a
failed one (202, audited; 404 if it is not failed).

Create also takes optional `post_logout_redirect_uris` (HTTPS, exact, like redirect URIs). Create returns 201
`{id,client_id,client_secret}`; list uses a page with `hosted_login`; update and disable return 204.
Branding: GET/PUT `.../login-settings` `{display_name,logo_url,accent_color,theme}` (200), per-client styles under
`.../login-settings/clients/:client` and previews at `.../login-settings/preview` (see [integrations](integrations.md)).

Source: `internal/iam/oauth/adapters/oauthhttp/handler.go`,
`oauthhttp/device.go`, `oauthhttp/exchange.go`, `oauthsvc/exchange.go`, `oauthpg/exchange.go`, `migrations/029_token_exchange.up.sql`, `oauthsvc/service.go`, `oauthsvc/backchannel.go`, `oauthsvc/device.go`, `migrations/027_backchannel_logout.up.sql`, `migrations/028_device_authorization.up.sql`, `internal/config/constants.go`. Follow the
[integration guide](../../guides/oauth-oidc.md) for the interaction sequence.
