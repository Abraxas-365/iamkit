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
   - otherwise, the password form. Environment-wide connections (for example
     Google, `organization_id` unset) are always offered as buttons.
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

Per environment, `PUT /management/v1/environments/$ENV/login-settings`:

```json
{"display_name": "Acme", "logo_url": "https://cdn.acme.example/logo.png", "accent_color": "#ff6600"}
```

`logo_url` must be HTTPS; `accent_color` is `#rrggbb`. Empty fields use the
defaults. The console has a **Hosted login** page for this. Changes are recorded
in the environment's audit events.

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
