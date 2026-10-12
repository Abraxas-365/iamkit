# React account widgets

`@iamkit/react` ships self-service widgets for the signed-in user next to its
[sign-in components](../../guides/applications/custom-sign-in-ui.md): profile,
security, sessions, API keys and an organization switcher. They are unstyled
React components built on hooks, and call the user's own account API through
the `createAccount` client of `@iamkit/js` (`/identity/v1/me*`). Administrator
screens are not included; [organization admin](../../guides/organizations/organization-administration.md)
has its own portal.

| Need | Use |
| --- | --- |
| Edit name, avatar, phone and custom profile properties | `<UserProfile>` / `useAccount` |
| Change the password, manage second factors, passkeys and recovery codes | `<UserSecurity>` / `usePassword`, `useFactors` |
| List and end sessions | `<UserSessions>` / `useSessions` |
| Create and revoke the user's [API keys](../../guides/machines/api-keys.md) | `<ApiKeys>` / `useApiKeys` |
| Show and change the organization | `<OrganizationSwitcher>` / `useOrganizations` |

## Set up

The widgets need an access token of the user: an `application` token with a
session and an organization, such as the one a code + PKCE sign-in returns for
the application's resource. API keys cannot call these routes. Create the
client once and share it through `<AccountProvider>`:

```tsx
import { createAccount } from "@iamkit/js";
import { AccountProvider, ApiKeys, UserProfile, UserSecurity, UserSessions } from "@iamkit/react";
import "@iamkit/react/widgets.css"; // optional

const account = createAccount({
  baseUrl: "https://id.example.com",
  environmentId,
  audience, // the resource the access token was issued for
  getAccessToken: () => currentAccessToken(), // called before every request
});

export function AccountPage() {
  return (
    <AccountProvider account={account} onReauthenticate={() => signInAgain()}>
      <UserProfile />
      <UserSecurity renderQRCode={(uri) => <QRCode value={uri} />} />
      <UserSessions />
      <ApiKeys />
    </AccountProvider>
  );
}
```

Every widget also accepts `account` and `onReauthenticate` directly, so a
single widget works without a provider. The browser must be allowed to call
IAMKit: add the application's origin to the OAuth client's `allowed_origins`
([CORS](../../guides/applications/custom-sign-in-ui.md)).

`examples/nextjs-login` (`app/account`) is a complete page.

## Widgets

Props common to all of them: `account?`, `onReauthenticate?`, `texts?`
(overrides by `account.*` key, defaults in `accountTexts`) and `classNames?`.

### `<UserProfile>`

Name, avatar URL (an https link; empty clears it), read-only username and
email, phone with verification, and the custom profile properties.

- `fields?: {name, label?, type?: "text" | "number" | "boolean"}[]` — IAMKit
  does not publish the environment's user schema to users, so by default the
  form shows the primitive properties the profile already has; list a property
  that was never set to make it appear.
- `onSaved?()`.

Phone verification sends a code by SMS (`POST /me/phone`) and confirms it
(`/me/phone/verify`); both need a recent sign-in.

### `<UserSecurity>`

Sections, selectable with `sections?: ("password" | "factors" | "passkeys" | "recovery")[]`:

- **Password** — current and new password. The answer says how many other
  sessions ended. Refusals (`INVALID_CURRENT_PASSWORD`, `NO_PASSWORD`,
  `PASSWORD_POLICY`) show their message in the alert region.
- **Second factors** — authenticator app (TOTP), email codes and SMS codes:
  start, confirm with a code, remove with a proof (a current code or a recovery
  code). The authenticator step always shows the secret and the `otpauth://`
  link; `renderQRCode?: (otpauthURI) => ReactNode` adds a QR code (no QR
  library is bundled).
- **Passkeys and security keys** — add (browser WebAuthn ceremony), rename and
  remove. Browsers without WebAuthn get an explanatory message.
- **Recovery codes** — how many remain, regenerate with a proof. New codes are
  shown once, until the user confirms they saved them.

### `<UserSessions>`

Lists live sessions (application, organization, browser, address, time), marks
the current one (`data-current="true"` and a badge), ends one and ends all the
others. Use `useSessions({limit, offset})` to page the list yourself.

### `<ApiKeys>`

Lists the user's keys (obfuscated value, state, permissions, expiry, last use)
and creates one: a name, permissions chosen from what the resource allows users
to grant, and an expiry of `expiryDays?` (default 30, 90 and 365 days, or never)
capped by the environment's `max_ttl_days`. The key's value is shown **once**,
with a copy button (`copy?` replaces `navigator.clipboard`). Creating needs a
recent sign-in. When the environment's policy does not enable user keys the
widget says so and makes no list call.

### `<OrganizationSwitcher>`

Lists the organizations the user may use and marks the current one. Takes
`OrganizationsOptions`:

- `getRefreshToken?()` and `onSwitched?(tokens, organizationId)` — the switch
  exchanges the session's refresh token (`POST /identity/v1/refresh` with
  `switch_organization_id`); store the returned tokens, the old ones ended.
- `boundary?` — environment, organization, application and resource ids when
  the access token is opaque.
- `onSignInRequired?({organizationId, reason})` — the target needs a sign-in the
  session lacks (`reason`: `sso`, `mfa` or `method`). Start an authorization
  with that `organization_id`. Without it the widget calls `onReauthenticate`.
  The refusal is not shown as an error.
- `onSelect?(organizationId)` — replaces the refresh-token switch. Sessions
  issued through OAuth (code + PKCE) and impersonated sessions cannot switch in
  place (403), so applications using them start a new authorization pinned to
  the chosen organization here, as the example app does.

## Re-authentication

Changing sensitive data needs a sign-in no older than a few minutes. IAMKit
then answers 403 `REAUTHENTICATION_REQUIRED`; every widget and hook catches it,
calls `onReauthenticate()` (from the provider or the widget) and shows the
message. Implement it by sending the user through a new authorization with
`max_age=0`, then back to the page; see
[sessions](../../guides/sign-in/sessions.md).

## Hooks

Each hook needs an `<AccountProvider>` (or throws) and returns `loading`,
`error`, `busy` (a change is in flight), `refresh()` and `clearError()`. Changes
answer `false` or `undefined` instead of throwing, and reload what they changed.

| Hook | Returns |
| --- | --- |
| `useAccount()` | `profile`, `properties`, `updateProfile({name?, avatarUrl?})`, `updateProperties(patch)` (`null` removes a key), `phone.start/verify/remove`, `changePassword` |
| `usePassword()` | `changePassword(current, next)` |
| `useSessions({limit?, offset?})` | `sessions`, `page`, `revoke(id)`, `revokeOthers()` |
| `useFactors()` | `summary`, `factors`, `recoveryCodesRemaining`, `lockedUntil`, `totp`/`email`/`sms` (`start`, `confirm`, `send`, `remove`), `recoveryCodes(proof)`, `passkeys` (`add`, `rename`, `assert`, `remove`) |
| `useApiKeys(filter?)` | `keys`, `page`, `options` (`enabled`, `max_ttl_days`, `resources`), `create(key)` → issued key with `value`, `revoke(id)` |
| `useOrganizations(options?)` | `organizations`, `currentId`, `switchTo(id)`, `refusal` |

`useAccountClient()` returns the `@iamkit/js` account client for anything the
hooks do not cover.

## Markup, accessibility and styling

Widgets render semantic markup: every input has a label, every button a `type`,
errors go in a `role="alert"` region and confirmations in `role="status"`
(`aria-live`), lists are `<ul>`, and destructive buttons name their target
(`aria-label="Revoke: ci"`). Each element carries `data-iamkit="<part>"`
(`root`, `title`, `section`, `subtitle`, `notice`, `error`, `form`, `field`,
`label`, `input`, `button`, `secondary`, `danger`, `list`, `item`, `badge`,
`secret`, `codes`, `meta`); `classNames` adds classes per part.

`@iamkit/react/widgets.css` is an optional stylesheet: CSS variables
(`--iamkit-color`, `--iamkit-bg`, `--iamkit-border`, `--iamkit-accent`,
`--iamkit-danger`, `--iamkit-radius`, …) with a dark scheme, all rules inside
`:where()` so your own CSS wins. Override the variables on any ancestor.

## Related

- `createAccount` in `clients/js` (`@iamkit/js`) — the client behind the widgets.
- [Custom sign-in UI](../../guides/applications/custom-sign-in-ui.md) · [sessions](../../guides/sign-in/sessions.md) · [multi-factor authentication](../../guides/sign-in/mfa.md) · [API keys](../../guides/machines/api-keys.md) · [user profiles](../../guides/organizations/user-profiles.md)
