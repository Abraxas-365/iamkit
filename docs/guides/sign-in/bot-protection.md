# Bot protection (CAPTCHA)

IAMKit can require a solved CAPTCHA before it looks at a sign-in, sign-up or
password-reset request. It supports [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
and [hCaptcha](https://docs.hcaptcha.com/). The provider is chosen **per
environment** and is **off until you configure it**: with no configuration
nothing changes, pages and CSP stay exactly as they were.

CAPTCHA stops scripted traffic. For abuse that looks like a person (stolen
passwords, a new country) use [risk signals](risk-signals.md); the two are
independent and can be combined.

## What is protected

| Surface | Where the widget runs | What is checked |
| --- | --- | --- |
| **Hosted** (`hosted` on) | IAMKit's [hosted pages](../applications/hosted-login.md): the identifier step (`/hosted/login`), sign-up and the device user-code page | One solved CAPTCHA covers the rest of that authorization: the password, code, reset and LDAP pages that follow need no second widget (the pass is bound to the authorization ticket, lasts 10 minutes and covers 5 credential posts; then the widget is shown again) |
| **Headless** (`headless` on) | Your own [custom sign-in UI](../applications/custom-sign-in-ui.md) | `captcha_token` on `POST /identity/v1/login`, `/challenges` (every purpose: `login`, `password_reset`, `email_verification`), `/signup` and `/federation/ldap/login` |

Both are on by default once a provider is saved; switch either off
independently. Not covered, by design: the SSO connection shortcut
(`connection_id` hint), passkey sign-in, token endpoints, API keys, machine
users and the SAML IdP — none of them is a password or code guess. Verifying a
code (`/challenges/:id/verify`, `/mfa/verify`) needs no widget either: it
follows a gated step and its attempts are capped per code.

## Set it up

### 1. Create the site at the provider

**Turnstile**

1. In the [Cloudflare dashboard](https://dash.cloudflare.com/) open **Turnstile**
   and choose **Add widget**.
2. Name it, then add the **hostnames** the widget will run on:
   - for hosted pages, the host of your IAMKit issuer (for example
     `iam.example.com`);
   - for a custom sign-in UI, the host of that UI (for example
     `login.example.com`).
3. Pick the widget mode (**Managed** is a good default) and create it.
4. Copy the **site key** (public) and the **secret key** (private).

**hCaptcha**

1. In the [hCaptcha dashboard](https://dashboard.hcaptcha.com/) create a site
   under **Sites**, adding the same hostnames. The **sitekey** is on that list.
2. Copy your **secret** from **Settings**.

### 2. Save it in IAMKit

Console: the environment's **Security** page, **Bot protection** tab: choose the provider, paste the site
key and secret, choose where it applies (hosted, headless) and save. The secret
is write-only: it is sealed with the deployment's `IAMKIT_ENCRYPTION_KEY`
(without one, saving answers 422 `ENCRYPTION_KEY_REQUIRED`) and is never
returned; reads show `has_secret`. Leaving the secret empty on a later save
keeps the stored one.

API (management, or `/api/v1` with `iam:security:write`):

```sh
curl -X PUT -H "Authorization: Bearer $IAMKIT_KEY" -H "Content-Type: application/json" \
  "$IAMKIT/management/v1/environments/$ENV/captcha" -d '{
    "provider": "turnstile",
    "site_key": "<site key>",
    "secret": "<secret key>",
    "hosted": true,
    "headless": true,
    "hostnames": ["login.example.com"]
  }'
```

| Field | Meaning |
| --- | --- |
| `provider` | `turnstile` or `hcaptcha` |
| `site_key` | The public key rendered in the widget (at most 200 characters) |
| `secret` | The provider's secret; omit it to keep the stored one (required the first time) |
| `hosted`, `headless` | Where a solved CAPTCHA is required; default `true` each |
| `hostnames` | Up to 20 hostnames a **headless** token may have been solved on (your sign-in UI's host). Empty accepts any hostname. Hosted tokens must have been solved on the issuer's host |

`GET` returns the configuration (`has_secret`, never the secret) and `DELETE`
removes it, which turns CAPTCHA off. Changes are audited as the
[events](../../reference/events.md) `captcha.updated` and `captcha.deleted`.

### 3. Press Test

**Test** (`POST …/captcha/test`, limited to 5 per minute per address) sends a
dummy token to the provider's verification endpoint. A provider answer of
`invalid-input-response` proves the secret was accepted; a rejected secret is
422 `CAPTCHA_SECRET_INVALID`. The test needs no browser and changes nothing.

CLI:

```sh
iam captcha get
printf %s "$SECRET" | iam captcha set --provider turnstile --site-key "$SITE_KEY" --secret-stdin
iam captcha test
iam captcha delete
```

## Test keys

Both providers publish keys that always pass or always fail, for local
development and automated tests. They work on any hostname, including
`localhost`. Real secrets reject the dummy token and dummy secrets reject real
tokens, so use the matching pair.

| Provider | Site key | Secret | Result |
| --- | --- | --- | --- |
| Turnstile | `1x00000000000000000000AA` | `1x0000000000000000000000000000000AA` | Always passes |
| Turnstile | `2x00000000000000000000AB` | `2x0000000000000000000000000000000AA` | Always fails |
| Turnstile | `1x00000000000000000000AA` | `3x0000000000000000000000000000000AA` | Always "token already spent" |
| hCaptcha | `10000000-ffff-ffff-ffff-000000000001` | `0x0000000000000000000000000000000000000000` | Always passes (test sitekey, hostname-independent) |

The Turnstile values come from the
[Cloudflare testing page](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
and the hCaptcha ones from its
[developer guide](https://docs.hcaptcha.com/#integration-testing-test-keys);
check those pages for the current list. The Turnstile test widget issues the
token `XXXX.DUMMY.TOKEN.XXXX`. Their answers carry a placeholder hostname
(`example.com`, `dummy-key-pass`), so IAMKit skips the hostname check when the
stored secret is one of these testing secrets. Never use test keys in
production: they accept every client.

## Hosted pages

Nothing to build. When the environment's CAPTCHA has `hosted` on, the identifier
page, sign-up and device-code page show the provider's widget; the form
posts only after it is solved. IAMKit verifies the answer, then lets the next
pages of the same sign-in through.

- The widget script, frame and connections are added to the
  Content-Security-Policy of **those pages only**, for the provider's hosts. With
  no CAPTCHA the policy is byte-for-byte what it was.
- The script tag carries the page's CSP nonce.
- Turnstile verifies the action (`login`, `signup`, `device`) and the hostname
  (the issuer's host).

## Headless (custom sign-in UI)

1. Read what to render. The public endpoint needs no authentication and is
   cached for a minute:

   ```sh
   curl "$IAMKIT/identity/v1/captcha/$ENV"
   # {"enabled":true,"provider":"turnstile","site_key":"…","headless":true}
   # {"enabled":false}   when headless CAPTCHA is off
   ```

   The [authorize ticket description](../applications/custom-sign-in-ui.md#read-the-ticket)
   also carries `captcha: {provider, site_key}` when headless CAPTCHA is on.
2. Render the provider's widget with that site key and read its token
   (`cf-turnstile-response` or `h-captcha-response`).
3. Send it as `captcha_token` in the same request body:

   ```sh
   curl -X POST "$IAMKIT/identity/v1/login" -H "Content-Type: application/json" -d '{
     "environment_id": "…", "organization_id": "…", "application_id": "…", "resource_id": "…",
     "login": "ada@example.com", "password": "…",
     "captcha_token": "<token from the widget>"
   }'
   ```

A missing, invalid, expired or already-spent token answers 403
`CAPTCHA_REQUIRED` with `details.provider`. Tokens are single use: after any
error, render a fresh challenge (reset the widget) before retrying. The check
happens before the credential is looked at, so the answer is the same for known
and unknown accounts.

With [`@iamkit/js`](../applications/custom-sign-in-ui.md#without-react),
`getCaptchaConfig(environmentId)` reads the public endpoint, and `login`,
`sendCode`, `signup.start` and `federation.ldap` take a `captchaToken` option;
`isCaptchaRequired(error)` and `captchaProvider(error)` read a
`CAPTCHA_REQUIRED` failure. `@iamkit/js` also keeps a random
`device_id` per browser for [risk signals](risk-signals.md#devices).

With [`@iamkit/react`](../applications/custom-sign-in-ui.md#with-react),
`<SignInForm>` shows a CAPTCHA step by itself when the environment asks for
one. For a custom layout, `<Captcha/>` loads the provider's script for the
site key, renders the widget and hands you the token (it also works as a render
prop); pass the token to the flow. See the package READMEs for the props.

The Go SDK (`authclient`) has `CaptchaToken` on its login, challenge, sign-up
and directory-login requests and `Captcha(ctx, environment)` for the public
endpoint; `apierror.Error.IsCaptchaRequired()` and `Provider()` read the failure.

## Fail-open semantics

IAMKit does not become unavailable because a CAPTCHA provider is:

- **Provider unreachable, 5 seconds without an answer, or a provider error
  (5xx)**: the request goes through. IAMKit logs a warning, counts
  `iamkit.captcha.unavailable` and records the sign-in attempt with
  `captcha: unavailable`.
- **The provider answers that the token is invalid** (wrong hostname or action
  included): the request always fails with 403 `CAPTCHA_REQUIRED`. A bad token
  is never waved through.
- **IAMKit cannot read its own CAPTCHA configuration** (a database error): the
  request fails (500) rather than skipping the check. Only the provider's own
  outage fails open.

Two settings weaken the check, so avoid them in production: an empty
**hostnames** list for headless (a token solved on any site using the same site
key is accepted; then only the provider's own domain list protects you), and
the provider's published **test keys**, which always pass.

The outbound call uses a guarded transport (public addresses only) and sends the
client address as `remoteip`.

## Turn it off

- Remove the configuration (`DELETE …/captcha`, **Remove** in the console).
- Or keep it saved and switch the `captcha`
  [feature flag](../platform/feature-flags.md) off for the environment or the
  deployment (`IAMKIT_FEATURES=captcha=false`): no check runs and no widget is
  rendered. Use this as a kill switch if a provider misbehaves.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Every hosted sign-in says the CAPTCHA failed | The site at the provider does not list the issuer's host, or the keys are a test pair mixed with a real one |
| Headless clients get `CAPTCHA_REQUIRED` with a fresh token | `hostnames` is set and the token was solved on another host; or the token was already used |
| The widget does not render on hosted pages | A proxy or browser extension blocks the provider's domain; check the browser console for CSP or network errors |
| Test answers `CAPTCHA_SECRET_INVALID` | The secret is wrong or belongs to another provider |
| Attempts show `captcha: unavailable` | IAMKit cannot reach the provider (egress firewall, DNS) — the sign-ins were let through |

See also [sign-in methods](sign-in-methods.md), [risk signals](risk-signals.md)
and the [errors reference](../../reference/errors-and-pagination.md).
