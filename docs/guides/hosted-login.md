# Hosted login pages

IAMKit can render the sign-in UI itself for an OAuth client, so your app only
needs a standard OIDC library: redirect to `/oauth/authorize`, receive the code
at your callback, exchange it at `/oauth/token`. Without hosted login, the
[headless flow](oauth-oidc.md) returns an authorization ticket and your UI signs
the user in.

Hosted login is opt-in **per OAuth client**. Headless clients are unaffected.

## Enable

Create the client with `hosted_login: true`, or switch an existing one:

```sh
curl -X PATCH "$IAMKIT/management/v1/environments/$ENV/oauth-clients/$CLIENT" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"hosted_login": true}'
```

In the console: **OAuth clients → Use hosted pages**. SDK:
`env.UpdateOAuthClient(ctx, id, iamclient.OAuthClientPatch{HostedLogin: &yes})`.

Now `GET /oauth/authorize` answers `303` to `/hosted/login?ticket=…` and sets
the same browser-binding cookie as the headless flow. The ticket is valid for
10 minutes and useless without that cookie.

## What the user sees

1. **Email.** IAMKit runs [discovery](federation.md) for the address:
   - an organization that **enforces** SSO for the email's verified domain
     sends the browser straight to its identity provider;
   - an organization with **optional** SSO offers "Continue with SSO" next to
     the password form;
   - otherwise, the password form. [Social login](social-login.md)
     connections (Google, Microsoft, GitHub, Apple; `organization_id` unset)
     are offered as "Continue with …" buttons with the provider's logo.

   The client's [sign-in methods](#sign-in-methods) decide which of these
   are shown.
2. **Credential.** Password, an 8-digit email code (users with
   `otp_enabled`), or SSO. "Forgot password?" runs the
   [reset](password-reset.md) flow in place. Enforced SSO is checked before
   any password comparison, exactly like `/identity/v1/login`.
3. **Organization.** IAMKit lists the organizations where the user can use
   the client's application and resource (active membership plus a grant).
   One organization: it is chosen automatically. Several: the user picks one.
   None: the sign-in is refused. An organization SSO login always signs in to
   that organization only.
4. **Second factor.** When the user has an authenticator (or the chosen
   organization [requires MFA](mfa.md)), a code page follows; users who must
   enroll get a QR code, then their recovery codes once. Enrolled users with
   several organizations answer it before choosing (except after SSO).
5. **Back to your app.** IAMKit issues the session in the chosen organization
   and redirects to your `redirect_uri` with `code` and `state`.

No session exists until the organization is known. The verified login waiting
for the choice is bound to the ticket and single-use.

## Branding

The **Hosted login** console page lists the environment's *default style* and
the OAuth clients with hosted login. Each style opens in an editor with a live
preview of the real pages (any page, light or dark, desktop or phone width,
any language).

Per environment, `PUT /management/v1/environments/$ENV/login-settings`:

```json
{
  "display_name": "Acme",
  "logo_url": "https://cdn.acme.example/logo.png",
  "accent_color": "#ff6600",
  "theme": {
    "mode": "adaptive",
    "radius": 8, "spacing": "normal", "align": "center",
    "light": {"primary": "#ff6600", "background": "#f5f5f7", "card": "#ffffff", "text": "#1d1d1f", "header": ""},
    "dark":  {"primary": "#ff8a3d", "background": "", "card": "", "text": "", "header": ""},
    "logo_dark_url": "https://cdn.acme.example/logo-dark.png",
    "favicon_url": "https://cdn.acme.example/favicon.ico",
    "header": {"show": true}, "logo_position": "header",
    "footer": {"text": "© Acme Inc.", "links": [{"label": "Privacy", "url": "https://acme.example/privacy"}]},
    "background_image_url": "https://cdn.acme.example/background.jpg", "background_overlay": 40
  },
  "locale": "es"
}
```

| Field | Values |
|---|---|
| `display_name` | ≤100 chars; shown under the logo and in the browser tab (`Sign in · Acme`) |
| `logo_url`, `theme.logo_dark_url`, `theme.favicon_url` | HTTPS URLs; the dark logo replaces the logo on dark pages |
| `accent_color` | `#rrggbb`; the same color as `theme.light.primary` (either may be sent) |
| `theme.mode` | `light` (default), `dark`, or `adaptive` (follows the visitor's device) |
| `theme.light`, `theme.dark` | `primary`, `background`, `card`, `text`, `header` as `#rrggbb`; empty uses the default. An empty dark primary follows the light one |
| `theme.radius` | 0–24 px (default 12) |
| `theme.spacing` / `theme.align` | `compact`\|`normal`\|`roomy` / `center`\|`left`\|`right` |
| `theme.header.show`, `theme.logo_position` | optional header bar; `header` moves the logo and name into it |
| `theme.footer` | `text` ≤200 chars, up to 5 `links` (`label` ≤40, HTTPS or `mailto:`), opened in a new tab |
| `theme.background_image_url`, `theme.background_overlay` | optional HTTPS image covering the page behind the form (no quotes, parentheses, backslashes or spaces); tinted by 0–90 % of the scheme's background color |
| `locale` | Default style only: the environment's [language](#language), for the hosted pages and the [emails](email-delivery.md#emails-iamkit-writes-smtp-resend) (`en`, `es`; `""` = automatic; `GET .../login-settings/locales` lists them). Omitted on `PUT`: unchanged |

The default style also brands the emails IAMKit writes (SMTP, Resend): its
display name, logo and primary color.

Button text is black or white, whichever reads better on the primary color;
the console warns about text and link colors below WCAG contrast.

### Language

Hosted pages (titles, labels, buttons, and the errors people can act on) are
in, first match wins:

1. the application's `ui_locales` on `/oauth/authorize` (e.g. `es-MX en`);
2. the environment's `locale` (the **Language** setting of the default style;
   client styles have none);
3. the visitor's browser (`Accept-Language`), then English.

Invitation pages use steps 2–3. Available languages: `en`, `es`.

### Per-client styles

An OAuth client can have its own complete style:
`PUT .../login-settings/clients/$CLIENT` (same body). Its sign-in pages use it;
other clients and **invitation pages** (which have no client) use the default.
`DELETE .../login-settings/clients/$CLIENT` returns the client to the default,
`GET .../login-settings/clients` lists the clients with their own style.
Deleting a client deletes its style.

### Previews

`GET .../login-settings/preview?page=identify&scheme=dark&client=$CLIENT`
returns `{"html": "…"}`: a page rendered with the saved style and sample data.
`POST .../login-settings/preview` `{"page","scheme","settings"}` renders an
unsaved style (validated like a save, stored nowhere; operators with write
access). Pages: `identify`, `password`, `code`, `reset`, `organization`, `mfa`,
`enroll`, `recovery`, `invite`, `message`, `signup`, `signup-code`. `scheme` may be either one whatever
the mode; `locale` (`?locale=` on `GET`) picks the language, by default the
environment's.

An optional `sign_in` (a body field, or `?sign_in=` as JSON on `GET`) shows
only some methods on the `identify` and `password` pages, e.g. social login
only: `{"password":false,"email_code":false,"organization_sso":false,
"connections":[{"name":"GitHub","provider":"github"}]}`. Providers: `google`,
`microsoft`, `github`, `apple`, `oidc`; at most 50 buttons, and at least one
method. It changes the preview only; a client's real methods are set under
[sign-in methods](#sign-in-methods).

Every change is recorded in the environment's audit events. Free-form CSS is
deliberately not supported: every value is a closed format placed in the
pages' nonce-protected style block.

## Sign-in methods

By default every client offers everything: password, email code,
organization SSO and every active social connection. To narrow it (for
example a consumer app with only Google and Apple, or an admin app with only
organization SSO), set the client's sign-in methods (console: Hosted login →
Clients → Sign-in methods):

```http
PUT /management/v1/environments/ENV_UUID/login-settings/clients/CLIENT_UUID/sign-in
{"password":false,"email_code":false,"organization_sso":true,
 "all_connections":false,"connection_ids":["GOOGLE_CONN_UUID","APPLE_CONN_UUID"]}
```

- `password`: the password form and "Forgot password?".
- `email_code`: email one-time codes.
- `organization_sso`: an email of an organization's verified domain continues
  with that organization's connection.
- `all_connections`: every active environment connection, including ones
  added later; otherwise only `connection_ids` (active environment
  connections; organization connections are governed by `organization_sso`).
- `signup`: the **Create account** link, when the environment allows
  [sign-up](signup-and-onboarding.md#self-service-sign-up) (default `true`;
  it also needs `password` or `email_code`).

At least one method must stay on. The email field is shown when password,
email code or organization SSO is on; with only social connections the page
is just the buttons. Methods that are off are hidden **and** refused with 403
`SIGN_IN_METHOD_UNAVAILABLE`, so they cannot be reached by posting the form
directly. When a member of an organization that enforces SSO signs in to a
client with `organization_sso` off, they get 403 `SSO_REQUIRED`: that client
is not for them.

`GET .../clients/CLIENT_UUID/sign-in` returns the effective options
(`custom: false` when the client has none), `GET .../login-settings/sign-in`
lists clients with their own, and `DELETE` returns a client to every method.
These options only affect the hosted pages; they do not restrict the
[identity API](password-login.md) your own UI calls.

They narrow the environment's and the organization's
[sign-in methods](sign-in-methods.md), which apply everywhere: a method the
environment turns off is hidden on every client (and "Forgot password?"
disappears when the environment turns reset off), and the organization
chooser leaves out organizations that refuse the method used.

## Invitations

`/hosted/invite?token=ik_inv_…` previews and accepts an
[invitation](organizations.md): a new account sets a password (unless the
organization enforces SSO), an existing one just joins. Point the delivery
`invitation_url` at `https://IAMKIT_HOST/hosted/invite` to send users there.
Accepting does not sign the user in; they sign in through your app next.

## Security properties

- Pages are server-rendered HTML without JavaScript. Every response carries a
  strict CSP (`default-src 'none'`, per-response style nonce, `img-src https: data:` for the enrollment QR code,
  `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `no-store` and
  `Referrer-Policy: no-referrer`.
- Every form action re-validates the ticket and its browser binding; a stolen
  ticket cannot be used from another browser.
- Page views are limited to 60/min and form posts to 30/min per IP and route.
- Error messages do not reveal whether an account exists beyond what the
  identity API already does.

**Verify:** with hosted login on, `/oauth/authorize` redirects to
`/hosted/login`; signing in returns to your callback with a code that
exchanges once. A user in two organizations sees the chooser; an email on an
enforced-SSO domain goes straight to the provider.
