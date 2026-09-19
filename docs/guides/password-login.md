# Password login

Prerequisites: active local user with a password, organization membership,
application-resource binding and effective resource grant. See
[first application](../start/first-application.md). Your browser/BFF needs IDs, not
management credentials.

```js
const response = await fetch('/identity/v1/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...boundary, email, password }),
})
if (!response.ok) throw new Error('Sign-in failed')
const tokens = await response.json()
```

`boundary` contains `environment_id,organization_id,application_id,resource_id`.
The URL assumes same-origin proxying. Use the [browser helpers](../examples/browser/auth.js)
for complete request handling. Keep tokens out of URLs/logs; a BFF should retain
refresh tokens server-side. Do not use browser local storage as an unexplained default.

For refresh, POST the same boundary plus `refresh_token` to `/identity/v1/refresh`.
Serialize requests and store the replacement atomically. Replay can revoke the
family. On logout, POST `{environment_id,audience}` with the access token to
`/identity/v1/logout`, then clear local tokens even if the network fails; distinguish
local signout from confirmed server revocation.

**Verify:** correct context succeeds; wrong password, absent membership or wrong
resource fails. Login does not automatically enforce `email_verified`; enforce
email-ownership onboarding policy deliberately. Show a generic sign-in error,
not whether an address exists. Provide [password reset](password-reset.md) when
email delivery is configured.
