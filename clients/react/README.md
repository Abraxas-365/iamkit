# @iamkit/react

Headless hooks and unstyled components for **custom IAMKit sign-in UIs**,
mirroring the hosted pages step by step. Built on
[`@iamkit/js`](../js); see its README for what the IAMKit deployment must
allow (the client's `allowed_origins`, `IAMKIT_WEBAUTHN_ORIGINS` for
passkeys).

```tsx
import { IAMKitProvider, SignInForm } from "@iamkit/react";

export function Login({ ticket }: { ticket: string }) {
  return (
    <IAMKitProvider baseUrl="https://id.example.com">
      <SignInForm
        ticket={ticket}
        // Used when the authorize request named no organization and the
        // email's domain does not route to single sign-on.
        organization={process.env.NEXT_PUBLIC_IAMKIT_ORGANIZATION}
        classNames={{ button: "rounded bg-black px-4 py-2 text-white", input: "rounded border px-3 py-2" }}
        renderQRCode={(uri) => <QRCode value={uri} />}
      />
    </IAMKitProvider>
  );
}
```

## Components

- `<SignInForm ticket …>` — identifier → password / emailed code / passkey /
  social and organization single sign-on (routed by the email's verified
  domain, LDAP included) → second factor or required enrollment → recovery
  codes → back to the client through `POST /oauth/authorize/complete`. Also
  expired passwords, password reset and sign-up when the ticket's `methods`
  allow them. Single sign-on returns to the same page (`returnTo`, default:
  the current URL with `?ticket=`), where the form redeems the result.
- `<AcceptInvitation token>` — preview, name + password for new users,
  accept; render what follows with its child function.

Both are unstyled: pass `classNames` (e.g. Tailwind utilities) per part, or
style `[data-iamkit="title|subtitle|notice|error|form|label|input|button|secondary|divider|codes|root"]`;
the root also carries `data-step`.

Texts use the hosted catalog keys (`hosted.form.sign_in`, …): your `texts`
prop › the operator's custom texts for the ticket's locale
(`authorization.texts`) › English defaults (`defaultTexts`).

### Bot protection and risk steps

When the environment's CAPTCHA covers headless sign-in the ticket carries
`captcha{provider, site_key}`: `<SignInForm>` then pauses protected calls
(password, code, reset, sign-up, directory) at a `captcha` step, renders
`<Captcha>` and resumes with the answer; a `CAPTCHA_REQUIRED` reply does the
same. An unusual sign-in (`reason: "risk_challenge"`) becomes the
`risk_challenge` step (the emailed code is sent at once and answered like an
email second factor); `SIGN_IN_BLOCKED` and the other refusals end in the
`blocked` step. Pass `renderCaptcha` to draw the widget yourself and `nonce`
for a strict CSP; the page's CSP must allow the provider's script, frame and
connect hosts.

- `<Captcha widget={{provider, site_key}} onToken onExpire? onError? options? nonce?>` —
  loads the Turnstile or hCaptcha script once, renders explicitly with the
  site key and removes the widget on unmount. A render-prop child
  `({ref, status, reset}) => …` lets you host the widget in your own markup.
  Give it `key={state.captchaRound}` to get a fresh widget after an answer was spent.
- `loadCaptchaScript(provider, nonce?)`, `captchaScripts`.
- `IAMKitProvider` also takes `deviceId` / `deviceStorage` (see `@iamkit/js`).

## Hooks

- `useSignIn({ticket, organization?, returnTo?, navigate?, locale?})` →
  `{state, flow}`: `state.step` (`identify`, `password`, `code`, `mfa`,
  `enroll`, `new_password`, `reset`, `ldap`, `signup`, `signup_verify`,
  `captcha`, `risk_challenge`, `blocked`, `redirecting`, `failed`), `state.authorization` (methods, connections,
  branding, texts), `state.error` (`IAMKitError`), `state.busy`; actions
  `flow.identify(login)`, `submitPassword`, `changePassword`, `sendCode`,
  `verifyCode`, `forgotPassword`, `resetPassword`, `submitDirectoryPassword`,
  `passkey()`, `connect(connectionId)`, `verifyFactor(code)`,
  `sendFactorCode("email"|"sms")`, `securityKey()`, `enroll()`,
  `beginSignup()`, `signup(…)`, `verifySignup(code)`, `restart()`,
  `proceed()`, `setCaptchaToken(token)`, `expireCaptcha()` (`state.captcha`,
  `state.captchaToken`, `state.captchaRound`). Build any markup on it.
- `useInvitation(token)` → `{preview, accepted, accept}`.
- `useIAMKit()` → the `@iamkit/js` client.

`SignInFlow` is the same state machine without React (`subscribe` /
`getSnapshot`).

## Development

```sh
(cd ../typescript && npm ci && npm run build) && (cd ../js && npm ci && npm run build)
npm ci && npm run typecheck && npm test && npm run build
```
