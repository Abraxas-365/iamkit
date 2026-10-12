# Risk signals

Risk signals look at **how** a sign-in happens — the address, the country, the
device, how often it failed — and decide whether to let it through, ask for an
emailed code, alert the user or refuse it. Every environment has a risk policy;
**without a saved policy every detection is off** and sign-in behaves exactly as
before. Two things exist regardless of the policy while the `risk_signals`
[feature flag](../platform/feature-flags.md) is on: the
[sign-in attempt log](#sign-in-attempts) and the list of devices each user
signed in from.

Risk signals complement [bot protection](bot-protection.md) (a CAPTCHA) and
[multi-factor authentication](mfa.md) (a factor the user enrolled).

## Detections

| Detection | Fires when | Default threshold | Actions |
| --- | --- | --- | --- |
| `ip_velocity` | One IP address fails `ip_failures_per_hour` sign-ins, or tries `ip_distinct_logins_per_hour` different logins, within an hour | 20 failures, 10 distinct logins | `off` `log` `challenge` `block` |
| `user_brute_force` | One login fails `user_failures_per_hour` times within an hour, from any address | 10 failures | `off` `log` `challenge` `block` |
| `impossible_travel` | The previous successful sign-in was more than 500 km away and getting here would need more than `travel_speed_kmh`. Needs [GeoIP](../platform/geoip.md) **City** data (coordinates) | 1000 km/h | `off` `log` `challenge` `block` |
| `new_device` | The user never signed in from this [device](#devices). Not evaluated without a device id | — | `off` `log` `notify` `challenge` |
| `stale_account` | The user has not signed in for `stale_after_days` | 60 days | `off` `log` `notify` `challenge` |

Why the action sets differ: `new_device` and `stale_account` describe the
legitimate user coming back, so they can notify and challenge but never block;
the other three describe an attacker, so they cannot notify.

Failures are counted from the attempt log, over an unknown login's keyed hash as
well as known accounts, so enumeration attempts are caught too. IAMKit stores
no raw value for a login it does not know.

## Actions

| Action | Effect |
| --- | --- |
| `off` | The detection is not evaluated |
| `log` | Recorded on the attempt and emitted as a `risk.detected` event; the sign-in proceeds |
| `notify` | Like `log`, plus a `security_alert` email to the user (when `notify_user` is on) |
| `challenge` | The user must enter a code emailed to their verified address before the session exists |
| `block` | 403 `SIGN_IN_BLOCKED`, recorded as `blocked` with a `sign_in.blocked` event |

When several detections fire, the strongest action wins:
`block` > `challenge` > `notify` > `log`.

### Start in log mode

Set every detection you want to `log` first. For a week or two read the
attempt log and the `risk.detected` events: who would have been challenged or
blocked? Tune the thresholds until the false positives disappear, then raise
the action. Nothing in log mode changes a user's experience.

## Configure it

Console: the environment's **Security** page, **Risk policy** tab (restrictions have their own tab). API (management, or `/api/v1` with
`iam:security:read` / `iam:security:write`):

```sh
curl --fail --silent --show-error -X PUT -H "X-API-Key: $IAMKIT_KEY" -H "Content-Type: application/json" \
  "$IAMKIT/management/v1/environments/$ENV/risk-policy" -d '{
    "actions": {
      "ip_velocity": "log",
      "user_brute_force": "challenge",
      "impossible_travel": "log",
      "new_device": "notify",
      "stale_account": "log"
    },
    "thresholds": {"user_failures_per_hour": 10, "stale_after_days": 90},
    "notify_user": true,
    "block_if_unverifiable": false
  }'
```

`PUT` replaces the policy: detections left out are `off`, thresholds left out
take their default, `notify_user` defaults to `true`. `DELETE` returns to every
detection off; `GET` reports `saved: false` for that default. Ranges:
`ip_failures_per_hour` and `ip_distinct_logins_per_hour` 1–10000,
`user_failures_per_hour` 1–1000, `stale_after_days` 7–3650,
`travel_speed_kmh` 100–20000. Setting `impossible_travel` on a deployment
without GeoIP answers 422 `GEOIP_REQUIRED`. Changes are audited as
`risk_policy.updated` and `risk_policy.deleted`.

CLI:

```sh
iam risk policy get
iam risk policy set --ip-velocity log --new-device notify --stale-after-days 90
iam risk status
```

`GET …/risk/status` (`iam risk status`) reports the GeoIP source and what it
supports (`countries`, `travel`) and whether the `captcha` and `risk_signals`
flags apply to the environment.

## Restrictions

Restrictions are allow and deny lists, checked **before any credential**:

| Kind | Value | Matches |
| --- | --- | --- |
| `ip` | An address or CIDR (`203.0.113.0/24`, `2001:db8::/32`) | The client address |
| `country` | ISO 3166-1 alpha-2 (`RU`) — needs [GeoIP](../platform/geoip.md); otherwise 422 `GEOIP_REQUIRED` | The client's country |
| `email_domain` | A domain (`example.com`, IDNs in punycode) | The email's domain (after the last `@`) and its subdomains: the typed email before any credential, then the account's own email once the user is known — so a username, passkey or code sign-in of an account on that domain is refused too |

```sh
curl --fail --silent --show-error -X POST -H "X-API-Key: $IAMKIT_KEY" -H "Content-Type: application/json" \
  "$IAMKIT/management/v1/environments/$ENV/risk-restrictions" \
  -d '{"kind":"ip","value":"203.0.113.0/24","action":"deny","note":"scanner"}'
iam risk restrictions list
iam risk restrictions add --kind country --value XX --action deny
iam risk restrictions remove <id>
```

- **`deny`** refuses the sign-in or sign-up with 403 `SIGN_IN_BLOCKED` before any
  credential is checked. The answer is identical for known and unknown
  accounts. A matching deny always wins over an allow.
- **`allow`** skips the detections for matching sign-ins. It never skips a
  [CAPTCHA](bot-protection.md) and never overrides a deny.

Up to 1000 restrictions per environment (409 for a duplicate, 422
`RESTRICTION_LIMIT_REACHED` past the limit). They are audited as
`risk_restriction.created` and `risk_restriction.deleted`. Use allow rules for
your office egress range so a corporate NAT does not trip `ip_velocity`.

IAMKit reads the client address from the socket, or from `X-Forwarded-For`
when the request comes from a proxy listed in `IAMKIT_TRUSTED_PROXIES`.
Behind a proxy without that setting every user shares the proxy's address; see
[reverse proxy](../../operations/reverse-proxy.md#forwarded-headers).

## The challenge

A `challenge` action (from the policy or from an [action](#actions-pre_sign_in))
reuses the second-factor machinery: the credential was right, but no session
exists until the user enters a code emailed to their **verified primary email**.
No factor has to be enrolled and nothing is enrolled afterwards.

**Headless.** The login answers with the usual `mfa_required` shape plus a
reason, with the email factor only:

```json
{"mfa_required":true,"mfa_token":"ik_mfa_…","factors":["email"],"reason":"risk_challenge","enrollment_required":false,"expires_in":300}
```

Clients that already handle the email second factor work unchanged: call
`POST /identity/v1/mfa/challenge` `{mfa_token, factor:"email"}`, then
`POST /identity/v1/mfa/verify` `{mfa_token, code}`, exactly as in
[headless MFA](mfa.md#headless-login). Show different wording when
`reason` is `risk_challenge`. A pending challenge lasts 5 minutes and allows 5
wrong codes, like any pending login.

**Hosted.** The hosted pages show the email-code page with challenge
wording ("we noticed something unusual…"); nothing to build.

**Already satisfied.** The challenge is skipped, and the action is recorded as
`log` with `satisfied_by`, when:

- the sign-in needs MFA anyway (the second factor runs instead);
- the first factor already proved the inbox (an email-code sign-in) or is
  multi-factor (a passkey);
- the user has no verified email. They cannot be challenged, so the attempt
  is logged — unless the policy sets `block_if_unverifiable`, which blocks it.
  A challenge asked in a place where no code can be sent answers 403
  `CHALLENGE_UNAVAILABLE`.

A code that cannot be sent right now (the per-user cooldown or hourly cap, or
an email outage) never skips the challenge: the sign-in still waits for the
code, and the user asks for a new one. Until the code is entered the parked
login can do nothing else — no password change, no factor enrollment.

A completed challenge marks the device as known, so `new_device` does not ask
twice.

`RISK_CHALLENGE` (403) is what a server-side flow with nowhere to park a
challenge receives when an action asks for one; ordinary sign-in routes turn it
into the `mfa_required` answer above.

## Security alert emails

With `notify_user` on, a detection whose action is `notify` sends the user a
`security_alert` email: what was detected, the address, the approximate
location, the device and the time. At most one email per user per detection
per hour. The wording is the `security_alert` purpose of the
[email templates](../platform/email-delivery.md) (placeholders `{{app_name}}`,
`{{detection}}`, `{{ip}}`, `{{location}}`, `{{device}}`, `{{time}}`), in the
user's language, and is sent after the sign-in answers so timing reveals
nothing. Administrators are reached with the [events](#events) below through
[webhooks](../../reference/event-webhooks.md) or [log streams](../platform/log-streams.md).

## Devices

A device is a browser or app the user signed in from, identified by an opaque
id that IAMKit stores only as a keyed hash:

- **Hosted pages** set the cookie `__Host-iamkit-device` (128-bit random, `HttpOnly`, `Secure`,
  `SameSite=Lax`, 400 days).
- **Custom sign-in UIs** send `device_id` (16–128 printable characters) in
  the body of `login`, `challenges`, `signup` and LDAP login. `@iamkit/js`
  generates one, keeps it in `localStorage` and sends it automatically (you can
  opt out); other clients should generate a random value once per browser or
  install and send the same one every time.

**There is no fingerprinting and no user-agent fallback**: without a device id
the `new_device` detection is not evaluated, so headless clients that do not
send one are never flagged. A device is learned on a successful sign-in; each
user keeps at most 50, the least recently seen forgotten first, and a device
not seen for 180 days is forgotten (with its last address and user agent).
`GET …/users/:id/devices` lists them (first and last seen, last address and
country, user agent; never the id) and the console shows them on the user page.

## Sign-in attempts

Every sign-in, sign-up and password-reset request is recorded in the attempt
log: when, address, user agent, country (and coordinates when the GeoIP
database has them), method, surface (`hosted`/`headless`), outcome, detections,
the strongest action and the CAPTCHA result. The outcomes are `success`,
`failure`, `blocked`, `challenged` and `captcha_failed`. The row is written after the
sign-in transaction ends, and a failure to write only logs; it never fails the
sign-in. Unknown logins are stored only as a keyed hash (HMAC-SHA256 per
environment), never as text.

```sh
curl --fail --silent --show-error -H "X-API-Key: $IAMKIT_KEY" \
  "$IAMKIT/management/v1/environments/$ENV/sign-in-attempts?outcome=blocked&country=RU&limit=50"
iam risk attempts list --outcome blocked
iam risk attempts get <id>
```

Filters: `user_id`, `ip`, `outcome`, `detection`, `country`, `limit` (default 50,
at most 200) and the cursor `before` (the previous page's `next`), newest first.
Console: **Security**, **Sign-in attempts** tab.

Attempts older than **30 days** are pruned hourly; change it with
`IAMKIT_SIGN_IN_ATTEMPT_RETENTION` (a Go duration of at least `24h`, for
example `720h`; see [configuration](../../reference/configuration.md)).

## Events

| Event | When | `data` |
| --- | --- | --- |
| `risk.detected` | A sign-in fired detections whose action is `log` or stronger; subject = the attempt | `user_id`, `detections`, `action`, `outcome`, `ip`, `country`, `method`, `surface` |
| `sign_in.blocked` | A deny restriction or a `block` detection refused a sign-in or sign-up; at most one per client address and reason per minute (every attempt is still in the log) | `reason` (`restriction` or `detection`), `restriction_id` or `detections`, `ip`, `country` |
| `session.created` | Every session | Gains `ip`, `user_agent`, `country` and `risk_detections` |
| `risk_policy.updated` / `.deleted` | The policy changed | — |
| `risk_restriction.created` / `.deleted` | A restriction changed | `kind`, `value`, `action` |

See the [event log](../../reference/events.md); subscribe with a
[webhook](../../reference/event-webhooks.md) on `risk.*` or `sign_in.blocked`.

## Actions (`pre_sign_in`)

The `function:pre_sign_in` [action](../platform/actions.md) receives what risk
evaluation saw in a `risk` object and may ask for a challenge:

```json
{"condition":"function:pre_sign_in","user":{"id":"…","email":"ada@example.com"},"amr":["pwd"],
 "risk":{"ip":"203.0.113.7","user_agent":"Mozilla/5.0 …","country":"PE",
         "detections":["new_device"],"action":"log","device_known":false,
         "surface":"hosted"}}
```

Answer `{"challenge": true}` to require the emailed code (or `{"deny": true,
"message": "…"}` as always). The challenge is ignored when the sign-in already
has MFA or proved the inbox; after the user completes it `pre_sign_in` runs
again with `risk.challenged: true`, and a second `challenge` is ignored.
`risk` is omitted when the `risk_signals` flag is off.

## Fail open

Risk evaluation never takes sign-in down: a GeoIP read error, an attempt
write or a failing risk query is logged and counted
(`iamkit.risk.errors`) and the sign-in proceeds as if nothing was detected.
The one exception is an explicit `deny` restriction, which is a plain list
match and always applies.

## Turn it off

- `DELETE …/risk-policy` and remove restrictions to keep only the log.
- The `risk_signals` feature flag (environment-scoped, on by default) skips
  everything — attempt writes, devices, detections and restrictions:
  `IAMKIT_FEATURES=risk_signals=false`, or per environment under **Settings →
  Features**. With it off, behaviour is exactly that of a deployment without
  this feature.

## Limits of the design

- Detections are heuristics; IP reputation and fingerprinting are not
  included. Use `challenge`, not `block`, until you trust a threshold.
- Country and travel data are only as good as the GeoIP source.
- Users without a verified email cannot be challenged.
- `ip_velocity` counts exact addresses: an attacker rotating through an IPv6
  /64 is counted as many clients. Deny the range as a restriction instead.
- Failed attempts against a user drive `user_brute_force`, so anyone can push
  a victim's sign-ins to the configured challenge or block. Prefer
  `challenge`: the real user passes it with their inbox.
- `new_device` needs a device id; headless clients that omit it are never
  flagged.
- The emailed challenge code belongs to the user, not to one sign-in: a code
  sent for a parked login also completes another parked login of the same user
  (attempts per code stay capped).
- Machine users, API keys, token refresh, token exchange, client credentials and
  the SAML IdP are not part of this evaluation.

See also [sign-in methods](sign-in-methods.md), [GeoIP](../platform/geoip.md),
[sessions](sessions.md) and [incident response](../../operations/incident-response.md).
