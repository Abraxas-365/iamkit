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
    "background_image_url": "https://cdn.acme.example/background.jpg", "background_overlay": 40,
    "font": {"family": "inter"},
    "heading_font": {"family": "custom", "url": "https://cdn.acme.example/brand.woff2"}
  },
  "legal": {
    "privacy_url": "https://acme.example/privacy", "terms_url": "https://acme.example/terms",
    "help_url": "https://help.acme.example", "support_email": "support@acme.example"
  },
  "locale": "es",
  "languages": ["es", "en"]
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
| `theme.font`, `theme.heading_font` | [Fonts](#fonts): `family` `system` (default; for headings, the text font), `inter`, `roboto`, `open-sans`, `lora`, or `custom` with `url` (HTTPS `.woff2`) |
| `legal` | [Legal links](#legal-links): `privacy_url`, `terms_url`, `help_url` (HTTPS) and `support_email`; all optional. Omitted on `PUT`: unchanged |
| `locale` | The default [language](#language) of the hosted pages — and, on the default style, of the [emails](email-delivery.md#emails-iamkit-writes-smtp-resend); one of the enabled `languages` (`GET .../login-settings/locales` lists the available ones). `""` = automatic (default style) or the environment's (client style). Omitted on `PUT`: unchanged |
| `languages` | Default style only: the languages hosted pages may use (≤64 codes, normalized and deduplicated); `[]` = every available one. Omitted on `PUT`: unchanged |

The default style also brands the emails IAMKit writes (SMTP, Resend): its
display name, logo and primary color.

Button text is black or white, whichever reads better on the primary color;
the console warns about text and link colors below WCAG contrast.

### Fonts

`theme.font` sets the text typeface and `theme.heading_font` the page
title's. Inter, Roboto, Open Sans and Lora are served by IAMKit itself
(`/hosted/fonts/`, latin and latin-ext subsets, SIL Open Font License), so
the page makes no third-party request. `custom` loads your own HTTPS
`.woff2` file (no quotes, parentheses, backslashes or spaces; served with
CORS, since browsers fetch fonts in CORS mode). The page's CSP gains
`font-src 'self'` and/or `font-src https:` only when a font needs it;
without fonts nothing changes.

### Legal links

`legal` puts links to your privacy policy, terms of service, help page and
support email (`mailto:`) under the sign-in and sign-up forms, in the page
language. On a client style, empty links inherit the environment default's.
They are separate from the free-form footer links.

When the [sign-in policy](sign-in-methods.md) sets `require_terms`, sign-up
asks people to accept the terms (a checkbox linking `terms_url` and
`privacy_url`) and records `terms_accepted_at` on the new user — see
[sign-up](signup-and-onboarding.md).

### Language

Hosted pages (titles, labels, buttons, and the errors people can act on) are
in, first match wins, among the environment's **enabled languages**
(`languages`; all when empty):

1. the application's `ui_locales` on `/oauth/authorize` (e.g. `es-MX en`);
2. the organization's `locale` once the page knows the organization
   ([organization branding](#organization-branding)), else the client
   style's `locale`, else the environment's `locale`;
3. the visitor's browser (`Accept-Language`), then English when enabled,
   else the first enabled language.

Codes match by language and region: `es-MX` picks `es`, `zh-Hant` and
`zh-HK` pick `zh-TW`, `zh` picks `zh-CN`, `pt-PT` picks `pt`, and a bare
code picks the one catalog of that language.
Invitation pages and emails use steps 2–3 (the organization's language
first). Available languages: `GET .../login-settings/locales` →
`{"items": [{"code", "name", "dir", "beta"}]}` (English first, then by code).

IAMKit ships 23 languages: `en`, `es`, and (beta) `ar`, `bg`, `cs`, `de`,
`fr`, `hu`, `id`, `it`, `ja`, `ko`, `nl`, `pl`, `pt`, `pt-BR`, `ro`, `ru`,
`sv`, `tr`, `uk`, `zh-CN`, `zh-TW`. Beta catalogs were machine-drafted and
carry `"beta": true` in the locales list (the console marks them) until a
native speaker reviews them; [sign-in texts](#sign-in-texts) and email
templates reword anything in the meantime. Arabic pages and emails are laid
out right to left (`<html dir="rtl">`); emails, passwords and codes stay
left to right inside them. Corrections are welcome as pull requests to
`internal/i18n/locales/<code>.json` (every catalog must keep English's keys
and placeholders; `go test ./internal/i18n` checks it). The
[`beta_languages` feature](feature-flags.md) (on by default) can hide the
beta languages from environments that have not listed their languages.

A wrong second-factor code on the hosted pages says how many tries are left
(`WRONG_CODE`, 401); the wrong code that spends the last of the five ends the
login at once (`MFA_ATTEMPTS_USED`, 401) and the page returns to the first
step. Errors carry machine codes (`LOGIN_INVALID`,
`SSO_ONLY`, `SSO_NOT_OFFERED`, `SSO_EMAIL`, `PASSWORD_REQUIRED`,
`CHOOSE_ORGANIZATION`, `ORGANIZATION_CHOSEN`, `FACTOR_REQUIRED`,
`NO_ACCESS`, …) that the pages translate.

### Sign-in texts

Every text of the hosted pages — titles, labels, buttons, notices, error
messages, device and invitation pages — can be reworded per language
(console: Hosted login → Sign-in texts, with a live preview), for the
environment, one OAuth client or one organization:

```bash
curl -X PUT "$IAM/management/v1/environments/$ENV/login-settings/texts/en" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"texts":{"hosted.title.sign_in":"Welcome back","hosted.form.continue":"Next"}}'
```

Paths: `.../login-settings/texts/$LOCALE` (environment),
`.../login-settings/clients/$CLIENT/texts/$LOCALE` and
`.../login-settings/organizations/$ORG/texts/$LOCALE`. `PUT` replaces the
scope's texts in that language (keys left out or empty inherit; at least one
text — `DELETE` returns every text to the inherited wording, 404 when there
are none); `GET` answers `{"texts":{}}` when there are none;
`GET .../login-settings/texts` lists every scope and language with texts.
A page resolves each key: organization (once the page knows it, as for
[branding](#organization-branding)) › client › environment › IAMKit's
wording in the page [language](#language) › English. Emails are worded with
[email templates](email-delivery.md#emails-iamkit-writes-smtp-resend).

`GET .../login-settings/texts/catalog?locale=es` lists the customizable
keys with IAMKit's wording, the `placeholders` a custom text must keep
(`%s`, `%d`, `{count}` — same ones, a literal percent sign is `%%`) and its
`max_length` (three times the original, 80–1000 characters). Texts are
plain, one-line text, always HTML-escaped on the pages. A text whose key
leaves the catalog, or whose placeholders change in a later version, is
ignored (the page shows IAMKit's wording). Every change is audited and emits
a `sign_in_texts.updated` / `sign_in_texts.deleted` event; deleting the
client or organization deletes its texts. CLI: `iam sign-in-texts
catalog|list|get|set|delete`.

`POST .../login-settings/texts/preview`
`{"page","locale","texts","client_id"?,"organization_id"?}` renders a page
with unsaved texts over the scope's saved branding and inherited texts.

### Per-client styles

An OAuth client can have its own complete style:
`PUT .../login-settings/clients/$CLIENT` (same body). Its sign-in pages use it;
other clients and **invitation pages** (which have no client) use the default
(or the organization's [branding](#organization-branding)).
`DELETE .../login-settings/clients/$CLIENT` returns the client to the default,
`GET .../login-settings/clients` lists the clients with their own style.
Deleting a client deletes its style.

### Organization branding

An organization can override parts of the style for its own users
(console: Organizations → the organization → Branding):

```bash
curl -X PUT "$IAM/management/v1/environments/$ENV/login-settings/organizations/$ORG" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"display_name":"Acme Corp","logo_url":"https://cdn.acme.example/logo.png","accent_color":"#aa0000"}'
```

The body has `display_name`, `logo_url`, `accent_color`, `theme` (same
rules as the default) and `locale` (the language of its pages and
invitation emails, one of the enabled languages); a missing or `null` field **inherits**, field by
field: environment default ← client style ← organization. A `theme` replaces
the inherited theme whole (an unset `theme.light.primary` takes
`accent_color`). `GET` answers every field `null` when the organization has
none; `DELETE` removes them all (404 when there are none). Deleting the
organization deletes them. The organization's own administrators manage the
same overrides at `…/admin/branding` ([organization
administration](organization-administration.md)); CLI:
`iam organizations branding get|set|delete ORG_ID`.

Sign-in pages use it once they know the organization, in this order:

1. **The application's hint** — the authorize request's `organization_id`
   parameter or a `urn:iamkit:org:id:<id>` scope (both must name the same
   organization; a malformed one is refused). The hint also **limits the
   sign-in**: the chooser is skipped for that organization, a user who cannot
   enter it cannot continue, and authorization refuses a session of another
   organization (403).
2. The organization the user **chose** (the pages after the chooser).
3. A **verified domain** of the email typed on the first page (the password
   and code pages). Unverified domains never brand.

```text
https://iam.example/oauth/authorize?client_id=…&response_type=code&…&organization_id=$ORG
https://iam.example/oauth/authorize?client_id=…&response_type=code&scope=openid%20urn:iamkit:org:id:$ORG&…
```

Invitation pages and invitation **emails** into the organization use its
branding; verification codes and other emails keep the environment's (users
are environment-wide). The email language stays the environment's.

### Previews

`GET .../login-settings/preview?page=identify&scheme=dark&client=$CLIENT`
returns `{"html": "…"}`: a page rendered with the saved style and sample data.
`POST .../login-settings/preview` `{"page","scheme","settings"}` renders an
unsaved style (validated like a save, stored nowhere; operators with write
access). Pages: `identify`, `password`, `code`, `reset`, `organization`, `mfa`,
`enroll`, `recovery`, `invite`, `message`, `signup`, `signup-code`. `scheme` may be either one whatever
the mode; `locale` (`?locale=` on `GET`) picks the language, by default the
environment's. `?organization=$ORG` on `GET` shows an organization's saved
overrides (over `?client=` or the default); `POST` with `"organization":
{…overrides}` instead of `settings` previews unsaved ones over the saved
default.

The `identify`, `password` and `signup` previews offer what the pages of
`client` (`?client=`, or `"client_id"` in a `POST` body; default: a client
without methods of its own) really offer under the environment's sign-in
policy: "Create account", "Sign in with a passkey", "Forgot password?" and
the terms checkbox appear exactly when they would there. The passkey button,
which a browser with WebAuthn reveals by script, is shown without one (the
preview runs no script).

An optional `sign_in` (a body field, or `?sign_in=` as JSON on `GET`) shows
only some methods on the `identify` and `password` pages, e.g. social login
only: `{"password":false,"email_code":false,"organization_sso":false,
"connections":[{"name":"GitHub","provider":"github"}]}`. Providers: `google`,
`microsoft`, `github`, `apple`, `oidc`; at most 50 buttons, and at least one
method. It only narrows what the client offers, and changes the preview
only; a client's real methods are set under
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
- `passkey`: **Sign in with a passkey** and passkey autofill on the email
  field, when the environment and organization allow
  [passkeys](mfa.md#passkeys) (default `true` for new clients; clients that
  saved their options before passkeys existed keep `false`). The page loads
  one small script, bound to its CSP nonce, only when a passkey or security
  key can be used.
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
organization enforces SSO), an existing one just joins. Invitations link here
unless the delivery `invitation_url` names a page of your own.
Accepting does not sign the user in; they sign in through your app next.

## Device approval

`/hosted/device` is where users approve a [device authorization](oauth-oidc.md#devices-without-a-browser-device-authorization-grant)
(TVs, CLIs): they type the code the device shows (prefilled from
`verification_uri_complete`), see the application and requested access, and
either refuse ("This wasn't me") or sign in through the journey above. The
pages wear the client's (else the environment's) branding and language; when
sign-in finishes they show "Device connected" instead of redirecting.

## Security properties

- Pages are server-rendered HTML without JavaScript. Every response carries a
  strict CSP (`default-src 'none'`, per-response style nonce, `img-src https: data:` for the enrollment QR code,
  `font-src` only when the theme sets a [font](#fonts), `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `no-store` and
  `Referrer-Policy: no-referrer`.
- Every form action re-validates the ticket and its browser binding; a stolen
  ticket cannot be used from another browser.
- Page views are limited to 60/min (font files: 600/min) and form posts to 30/min per IP and route
  (device code entry: 10/min).
- Error messages do not reveal whether an account exists beyond what the
  identity API already does.

**Verify:** with hosted login on, `/oauth/authorize` redirects to
`/hosted/login`; signing in returns to your callback with a code that
exchanges once. A user in two organizations sees the chooser; an email on an
enforced-SSO domain goes straight to the provider.
