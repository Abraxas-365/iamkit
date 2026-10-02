# Custom sign-in UI

Build your application's own sign-in pages instead of IAMKit's
[hosted pages](hosted-login.md). The custom pages run the same journeys:
identifier, password or emailed code, passkey, social and organization
single sign-on, LDAP, second factor and enrollment, expired password, reset,
sign-up and invitations. Your application stays an ordinary OIDC client
(authorization code + S256 PKCE). IAMKit still issues the code, so any OIDC
library works on your side.

Packages (in `clients/`):

| Package | What it is |
| --- | --- |
| `@iamkit/api` | Typed client generated from the [OpenAPI document](../reference/api/openapi.md) |
| `@iamkit/js` | Browser sign-in SDK: `createSignIn` with authorize, login, codes, MFA, passkeys, federation, sign-up, invitations and complete; PKCE and WebAuthn helpers; `IAMKitError` with stable `code`s |
| `@iamkit/react` | Headless `SignInFlow` state machine, the `useSignIn`/`useInvitation` hooks, and the unstyled `<SignInForm>`/`<AcceptInvitation>` components |

A complete Next.js application with Playwright parity journeys lives in
[`examples/nextjs-login`](../../examples/nextjs-login/README.md).

## How it works

```text
App → browser: /sign-in?client_id=…&redirect_uri=…&state=…&nonce=…&code_challenge=…
Browser → IAMKit GET /oauth/authorize (credentials: include, Accept: application/json)
IAMKit → browser: {authorization_ticket, client_id, environment_id, …} + __Host-iamkit-authorization cookie
Browser → IAMKit GET /identity/v1/authorize/:ticket   → methods, connections, branding, texts, locale
Browser → IAMKit POST /identity/v1/login (…/challenges, /mfa/verify, /signup, …) → access token
Browser → IAMKit POST /oauth/authorize/complete  Bearer access token + cookie → {redirect_to}
Browser → app redirect_uri?code=…&state=…   → app exchanges the code at /oauth/token
```

The client must **not** use `hosted_login`. For a `hosted_login` client,
`/oauth/authorize` redirects to the hosted pages, and `@iamkit/js` raises
`HOSTED_LOGIN`.

## Set up the client

Register a public client (code + PKCE) with the UI's origin in
`allowed_origins`:

```json
POST /management/v1/environments/ENV/oauth-clients
{
  "application_id": "APP", "resource_id": "RES", "public": true,
  "redirect_uris": ["https://app.example.com/callback"],
  "allowed_origins": ["https://app.example.com"]
}
```

`allowed_origins` holds at most 20 origins. Each is `scheme://host[:port]`
with nothing after it: no path other than `/`, no query, fragment, user
info or wildcard. Origins must be `https`, except `http` on `localhost` or
`127.0.0.1`. IAMKit normalizes them (lowercase host, default port dropped).
IAMKit answers CORS with credentials for these origins **only** on the
browser-facing routes `/identity/v1/*` and `/oauth/*`. It never does so on
`/management/v1` or `/api/v1`. The deployment-wide `CORS_ALLOWED_ORIGINS`
still applies everywhere. Origin answers are cached briefly, so a change
takes effect within about a minute. The same list also authorizes the
`return_to` of [single sign-on back to the UI](federation.md#returning-to-a-custom-sign-in-ui).

For passkeys and security keys on the UI's origin, also add it to
`IAMKIT_WEBAUTHN_ORIGINS` ([configuration](../reference/configuration.md)).
The relying-party ID stays IAMKit's host, so the UI must be on the same
registrable domain.

## Security model

- **The ticket is browser-bound.** `/oauth/authorize` sets the
  `__Host-iamkit-authorization` cookie (Secure, HttpOnly, `SameSite=Lax`,
  valid for the ticket's 10 minutes). Reading the ticket
  (`GET /identity/v1/authorize/:ticket`) and completing it both require
  that cookie. A ticket copied to another browser is useless, and a
  completed ticket cannot be used again.
- **No cookie authenticates a sign-in call.** `/identity/v1` takes its
  inputs in JSON bodies, and the user's proof is the bearer access token
  that the sign-in returned. A cross-site form or link therefore cannot
  act for the user. That is the CSRF protection: there is no ambient
  credential to ride on. The binding cookie only *restricts* a ticket to
  its browser. It is never sufficient on its own, because completing also
  needs a valid access token for the same application and resource. The
  JSON bodies with `Content-Type: application/json` also force a CORS
  preflight, which only listed origins pass.
- **Tokens stay out of storage and URLs.** The access token from the
  sign-in exists only in memory until `complete`. Your application gets
  its own tokens from the code exchange on its server. Single sign-on
  returns a one-time `federation_result` handle that only the holder of
  the PKCE verifier can redeem, never a token.
- **Same-site deployment.** Because the binding cookie is `SameSite=Lax`,
  browsers send it on the UI's `fetch` calls only when the UI and IAMKit
  are same-site, for example `login.example.com` and `app.example.com`
  (different ports of `localhost` count as well). Browsers that block
  third-party cookies drop it across sites, and the ticket calls then
  answer 401.
- **Same answers as the hosted pages.** Every check happens on IAMKit:
  sign-in methods, SSO enforcement, MFA, lockout, the organization hint,
  and access to the application. The UI renders the outcome but decides
  nothing.

## Read the ticket

`GET /identity/v1/authorize/:ticket` (with the binding cookie) describes the
sign-in, so the UI can render it the way the hosted pages would:

| Field | Meaning |
| --- | --- |
| `client_id`, `environment_id`, `application_id`, `resource_id`, `audience`, `scopes` | The boundary every sign-in call carries |
| `organization_id` | The authorize request's organization hint: the sign-in must end in that organization |
| `login_hint` | Prefills the identifier |
| `locale`, `languages` | The language to show (`ui_locales`, then the branding default, then `Accept-Language`) and the enabled ones |
| `methods` | `password`, `email_code`, `passkey`, `password_reset`, `signup`, `organization_sso`, `terms`; the client's [sign-in options](hosted-login.md) intersected with the [policy](sign-in-methods.md) |
| `connections` | Social and environment connections offered as buttons |
| `branding` | Display name, logo, accent color, theme, legal links (with [organization overrides](hosted-login.md#organization-branding) for the hint) |
| `texts` | [Custom sign-in texts](hosted-login.md) for `locale`, as `hosted.*` catalog keys |

## Complete the authorization

`POST /oauth/authorize/complete` with `Authorization: Bearer <access token>`,
the binding cookie and `{"authorization_ticket": "…", "approve": true}`.
With `Accept: application/json` (and without `text/html`), IAMKit answers
`200 {"redirect_to": "…"}` instead of a 303, and the UI navigates there
itself. The token must come from a sign-in into the ticket's application
and resource. When the request named an organization, it must also be that
organization (otherwise 403 `ORGANIZATION_HINT`).

## With React

```tsx
import { IAMKitProvider, SignInForm } from "@iamkit/react";

<IAMKitProvider baseUrl="https://login.example.com">
  <SignInForm ticket={ticket} organization={defaultOrganizationId} classNames={{ button: "btn btn-primary" }} />
</IAMKitProvider>
```

`<SignInForm>` covers every step (`identify`, `password`, `new_password`,
`code`, `reset`, `ldap`, `mfa`, `enroll`, `signup`, `signup_verify`,
`redirecting`, `failed`). It uses the ticket's custom texts, falling back
to English. You can override any key with `texts`. Style it with
`classNames` or `[data-iamkit="<part>"]` selectors. For a fully custom
layout, drive `useSignIn(options)` → `{state, flow}` yourself. The
framework-free `SignInFlow` class works with other frameworks as well.

`organization` decides where a sign-in lands when the authorize request
named no organization and the email's domain has no SSO organization. It
can be a fixed id or a function of the identifier. Without one, the flow
fails with `ORGANIZATION_REQUIRED`.

## Without React

```ts
import { createSignIn } from "@iamkit/js";

const iam = createSignIn({ baseUrl: "https://login.example.com" });
const start = await iam.authorize(location.search);                 // ticket + binding cookie
const authz = await iam.authorization(start.authorization_ticket);  // methods, texts, …
const boundary = { environmentId: authz.environment_id, organizationId, applicationId: authz.application_id, resourceId: authz.resource_id };
const result = await iam.login(boundary, { login: email, password });
if (result.status === "signed_in") {
  location.assign(await iam.complete(start.authorization_ticket, result.tokens.access_token));
}
// else result.mfa: verify with iam.mfa.verify(result.mfa.mfa_token, code)
```

See the package READMEs for every call and error code.

## Verify

`tests/e2e/custom_ui_test.go` covers the server contract: origin
validation, per-route CORS, the ticket description, and JSON completion.
`examples/nextjs-login/e2e` replays the hosted journeys through
`<SignInForm>` in Chromium against a real IAMKit (`bash e2e/run.sh`; the
optional `custom-ui-parity` CI job).
