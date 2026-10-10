# Social login: Google, Microsoft, GitHub, Apple, GitLab and any OAuth 2.0 provider

Social login lets anyone sign in with an account they already have. It uses
**environment connections** (no `organization_id`) created from a provider
preset: IAMKit knows each provider's issuer, endpoints and quirks, so you only
supply the credentials from the provider's console.

Social login differs from an organization's [enterprise SSO](federation.md#organization-sso):

| | Social (environment connection) | Organization SSO |
| --- | --- | --- |
| Who | anyone with an account at the provider | one organization's employees |
| New users | sign-up into one organization you choose (optional) | JIT into the owning organization |
| Existing users | linked when the provider verifies their email (optional) | adopted by verified domain |
| Satisfies SSO enforcement | no | yes |
| Stands in for MFA | no, the user's own second factor applies | yes |

## Before you start

1. Set `IAMKIT_ENCRYPTION_KEY` so `client_secret` can be stored encrypted
   (see [configuration](../../reference/configuration.md#encryption-key)).
2. Register the redirect URI at the provider, exactly:
   `${JWT_ISSUER}/identity/v1/federation/callback`. The console shows it on the
   create dialog and on the connection page (`callback_url` in the API).
3. To let new users sign up, create the organization they will join and,
   optionally, an operator-managed group bound to the roles they should get.

## Create a connection

Console: **Federation → Create**, pick the provider. API:

```http
POST /management/v1/environments/ENV_UUID/federation-connections
{"provider":"google","name":"Google","client_id":"…apps.googleusercontent.com","client_secret":"…",
 "link_email":true,"signup":true,"signup_organization_id":"ORG_UUID","signup_group_id":"GROUP_UUID"}
```

`provider` is `google`, `microsoft`, `github`, `apple`, `gitlab`,
`github_enterprise`, `oauth2` or `oidc` (default; any OpenID Connect provider,
`issuer` required — this is also how you connect ZITADEL, Keycloak or another
IAMKit). Presets ignore `issuer`; the
connection shows the derived one. The name is the button label: "Continue
with Google".

### Google

Google Cloud → APIs & Services → Credentials → OAuth client ID → *Web
application*; add the redirect URI. Configure the consent screen (and publish
it, or add test users). Scopes: `openid profile email`, with PKCE and nonce.

**For one organization's Google Workspace** (enterprise SSO instead of social
login), create an [organization connection](federation.md#organization-sso) with
`"provider":"google"`, the organization's `organization_id` and
`"options":{"domains":["acme.com"]}`. IAMKit then refuses personal Google accounts
and other Workspaces before any user is looked up (the ID token's `hd` claim must
be one of the domains), and JIT provisioning still admits only emails of the
organization's verified domains.

IAMKit requests `openid profile email`, uses PKCE and a nonce, and verifies the ID
token against `https://accounts.google.com`; it never accepts an access token as
proof of identity. For redirect mismatches compare scheme, host and path with the
registration exactly; for consent errors check the consent screen's publishing
status and test users. A Google sign-in still needs local membership and grants.
Provider documentation: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

### Microsoft

Entra admin center → App registrations → New registration → platform *Web*,
add the redirect URI, then create a client secret (note its expiry).
`options.tenant` is required and must match the account types chosen in the registration:

| `options.tenant` | Accounts |
| --- | --- |
| `common` | work, school and personal Microsoft accounts |
| `organizations` | work and school accounts of any tenant |
| `consumers` | personal Microsoft accounts |
| a tenant ID | one tenant (like an organization connection) |

With `common` or `organizations`, `options.tenants` restricts sign-in to the
listed tenant IDs. IAMKit verifies each ID token against the issuer of the
tenant that signed it (`https://login.microsoftonline.com/{tid}/v2.0`), never
a placeholder. Personal accounts' emails are verified by Microsoft; for work
accounts the email counts as verified only when the token carries
`xms_edov: true` (add the optional claim `xms_edov` in *Token configuration*),
because an Entra administrator can set any address on a user. A single-tenant
connection trusts its tenant's directory for sign-in, but sign-up and email
linking still need `xms_edov`.

`options.tenant` cannot change after creation; `options.tenants` can.

**For one organization's Entra tenant** (enterprise SSO instead of social login),
create an [organization connection](federation.md#organization-sso) with
`"provider":"microsoft","options":{"tenant":"TENANT_ID"}` (or `"provider":"oidc"`
and issuer `https://login.microsoftonline.com/TENANT_ID/v2.0`).

Record the client secret's expiry and rotate it with `PATCH {"client_secret":"…"}`
before it expires. Test an allowed and a refused tenant, an expired client secret,
an unlinked subject and local grant denial: Microsoft authentication does not
imply permission in your application. Provider documentation:
[Microsoft OIDC protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).

### GitHub

GitHub → Settings → Developer settings → OAuth Apps → New OAuth App; set the
authorization callback URL to the redirect URI and generate a client secret.
GitHub speaks OAuth 2.0, not OpenID Connect: IAMKit uses PKCE, reads the
user's numeric ID as the subject and takes the **primary, verified** address
from `/user/emails` (scopes `read:user user:email`). Use an OAuth App, not a
GitHub App.

### GitHub Enterprise Server

The same OAuth App flow on your own server: `"provider":"github_enterprise"`
with `options.base_url` (e.g. `https://github.acme.com`). IAMKit uses
`{base_url}/login/oauth/*` and the REST API at `{base_url}/api/v3`; the base
URL is the connection's issuer and cannot change.

### GitLab

GitLab → Preferences (or Admin, or a group) → Applications; add the redirect
URI with the scopes `openid profile email`. GitLab is an OpenID Connect
provider: `"provider":"gitlab"` uses `https://gitlab.com`, or set
`options.base_url` to a self-managed instance (fixed after creation).

### Any OAuth 2.0 provider

Providers without OpenID Connect (Discord, Slack v1, a custom server) use
`"provider":"oauth2"` with their endpoints and a **claim mapping** that says
where the user info JSON keeps the identity (dotted paths for nested members):

```http
POST …/federation-connections
{"provider":"oauth2","name":"Discord","client_id":"…","client_secret":"…",
 "options":{"authorize_url":"https://discord.com/oauth2/authorize",
  "token_url":"https://discord.com/api/oauth2/token",
  "userinfo_url":"https://discord.com/api/users/@me","scopes":["identify","email"],
  "claims":{"subject":"id","email":"email","email_verified":"verified","name":"global_name"}}}
```

IAMKit uses PKCE and `state` (there is no ID token, so no nonce), then calls
`userinfo_url` with the access token. `subject` must be a string or number.
The email counts as verified **only** when the mapped `email_verified` member
is `true`; without that mapping it never is, so it cannot sign up or link.
The connection's issuer is the origin of `authorize_url`; endpoints may move
within that host, but a different host needs a new connection.

With the `iam` CLI:

```sh
iam federation create --provider oauth2 --name Discord --client-id ID --client-secret-file secret.txt \
  --authorize-url https://discord.com/oauth2/authorize --token-url https://discord.com/api/oauth2/token \
  --userinfo-url https://discord.com/api/users/@me --scopes identify,email \
  --claim-subject id --claim-email email --claim-email-verified verified --claim-name global_name
iam federation create --provider gitlab --base-url https://git.acme.com --name GitLab --client-id ID --client-secret-file secret.txt
iam federation update CONN_ID --update-profile
```

### Apple

Apple Developer → Certificates, IDs & Profiles:

1. an App ID with *Sign in with Apple* enabled;
2. a **Services ID** (this is the `client_id`), configured for Sign in with
   Apple with your domain and the redirect URI;
3. a **key** with Sign in with Apple enabled; download the `.p8` file once.

```http
POST …/federation-connections
{"provider":"apple","name":"Apple","client_id":"com.example.web",
 "client_secret":"<contents of AuthKey_KEY1234567.p8>",
 "options":{"team_id":"ABCDE12345","key_id":"KEY1234567"},"signup":true,"signup_organization_id":"ORG_UUID"}
```

`client_secret` is the PEM contents of the `.p8` key (P-256); IAMKit stores it
encrypted and signs a five-minute ES256 client secret for each code exchange,
so there is no expiring secret to rotate. `secret_env` is not supported for
Apple. To rotate the key, `PATCH` a new `client_secret` together with its
`options.key_id`. Apple posts the callback (`response_mode=form_post`); IAMKit
turns it into a normal redirect so the browser-binding cookie still applies.
Apple sends the user's name only on the very first authorization, and may
give a private relay address (`…@privaterelay.appleid.com`) as the email.

## First sign-in: sign-up and email linking

A returning user is found by the provider's subject. For a subject IAMKit has
not seen, two settings decide:

- `link_email`: if an active user already has the email and the provider
  verified it, link the subject to that user (identity `origin: "email"`).
- `signup`: otherwise create the user (no password, email verified) in
  `signup_organization_id`, add them to `signup_group_id` if set, and link
  (`origin: "signup"`).

Both require the provider to **explicitly** verify the email; an absent
`email_verified` is refused, unlike organization JIT. An existing email with
`link_email` off is refused with 401 `ACCOUNT_EXISTS` ("sign in with it"),
so sign-up can never take over an account. With both off the connection
works like before: only operator-linked subjects
(`POST /external-identities`) sign in.

`signup` requires `signup_organization_id` (an active organization of the
environment); `signup_group_id` must be an operator-managed group of it.
`PATCH {"signup": false}` also clears both. Organization connections cannot
use `signup`; they have [JIT provisioning](federation.md#just-in-time-provisioning)
and [email linking of members](federation.md#linking-members-by-email).

## Choosing the account

A provider that already has a session in the browser signs the user in with
it without asking. `options.prompt` (Microsoft, Google and generic OIDC; console:
**Account choice** on the connection) decides what happens on every sign-in:

| `options.prompt` | Console | The provider… |
|---|---|---|
| omitted or `""` | Sign in with the current account | reuses its session silently (picker only with several signed-in accounts) |
| `select_account` | Always choose the account | always shows its account picker, with "Use another account" |
| `login` | Always ask for the password | asks for the credentials again |

It can change at any time (`PATCH` with the whole `options`).

## Keeping profiles in sync

A provider's `picture` claim (GitHub: `avatar_url`; `oauth2`: the mapped
`picture` member) becomes a new user's avatar, and fills an existing
account's when it has none; only `https://` pictures are kept.

With `"update_profile": true` every sign-in refreshes the linked user's name
and avatar from the provider. The email follows too when the provider verifies a new
address, the account has no password (the provider is how it signs in), no
SCIM directory manages it and no other account has the address; the change is
audited `federation.profile_updated`. Off by default.

A new user without a default group has no roles, so the first sign-in ends
with 403 "signed in, but the user has no access to this application" until an
operator grants access. The account and link persist.

## Security rules

- A social login is a first factor like a password: an organization's
  [enforced SSO](federation.md#enforcement) still applies (`SSO_REQUIRED`), and
  users with an authenticator, or in organizations that
  [require MFA](../sign-in/mfa.md), must complete their second factor.
- Provider endpoints are always HTTPS; preset issuers are fixed, so operators
  cannot point a preset at an internal address.
- The binding cookie, state, nonce (OIDC providers) and PKCE (except Apple,
  which does not support it) are verified on every callback.

## Choose which clients show it

Every hosted-login client shows every active social connection by default.
To show some or none, or to turn password, email code or organization SSO
off for a client, see [sign-in methods](../applications/hosted-login.md#sign-in-methods).

## Troubleshooting

- `redirect_uri_mismatch` / `AADSTS50011` / GitHub "redirect_uri is not
  associated": the registered URI must equal `callback_url` exactly.
- "provider email is not verified": the user's provider email is unverified;
  for Microsoft work accounts add the `xms_edov` optional claim.
- "this Microsoft account is not accepted here": the account's tenant is not
  in `options.tenants`, or is not the configured single tenant.
- Apple `invalid_client`: the Services ID, Team ID, Key ID and `.p8` must
  belong together, and the key must have Sign in with Apple enabled.
