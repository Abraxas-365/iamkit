# Waitlist

With the waitlist on, nobody can create an account with a password or an email
code until an operator approves them. People ask to join, you decide, and
approved people receive a single-use link to finish signing up. It is **off by
default**: nothing changes until you turn it on.

The waitlist sits on top of [self-service sign-up](signup-and-onboarding.md#self-service-sign-up).
Read that page first for the sign-up flow itself.

## Turn it on

Console: **Sign-in methods → Self sign-up**. Turn on **Allow sign-up**, then
**Waitlist** (the switch stays disabled until sign-up is allowed). Two optional
settings appear:

| Field | Meaning |
| --- | --- |
| `waitlist` | Hold new sign-ups for approval. Needs `allow_signup` (400 otherwise) |
| `waitlist_auto_approve_domains` | Email domains (at most 50) approved on the spot, for example your company's |
| `waitlist_signup_url` | Your sign-up page, HTTPS (HTTP only on loopback). `?waitlist=<token>` is appended to it. Its origin must be IAMKit's own or listed in `allowed_origins` of an active [OAuth client](../applications/custom-sign-in-ui.md) of the environment, else 422. Empty: the approval email carries the token but no link |

```sh
iam sign-in-policy set --allow-signup --signup-organization ORG_UUID \
  --waitlist --waitlist-auto-approve-domains acme.io \
  --waitlist-signup-url https://app.acme.io/signup
```

Or `PUT /management/v1/environments/ENV_UUID/sign-in-policy` with the three
fields above (`/api/v1` with `iam:security:write`). A PUT that omits them keeps
their stored values (`waitlist_auto_approve_domains: []` clears the list), so a
client that does not know the waitlist never turns it off. Turning
`allow_signup` off also requires turning `waitlist` off.

The approval email links to `waitlist_signup_url` with the token in the query,
so IAMKit only accepts a page whose origin (`scheme://host[:port]`) is its own
issuer or an `allowed_origins` entry of an active OAuth client of an active
application in the environment: whoever can edit the policy cannot point the
link at a foreign host and collect tokens. The check runs when the page is set
or changed (422 `waitlist_signup_url must be IAMKit's origin or an allowed_origins
entry of one of the environment's OAuth clients`; saving the policy with the
stored page unchanged is not re-checked, so other edits are never blocked) and
again on every approval:
if the client was disabled or lost the origin since, the email still carries
the token but no link, and the server logs a warning. The list holds at most 100,000 pending
entries; past that, joins are dropped silently to the person (the answer never
changes) and logged as `waitlist full: join dropped` — turn on
[CAPTCHA](bot-protection.md) for public sign-up pages. An approval
that expires unused goes back to pending when the person asks again.

Until the waitlist is on, the console's **Waitlist** page (under *Users &
access*) is empty and tells you how to enable it.

## What people see

`POST /identity/v1/signup` answers 202 with a `status`:

```json
{"challenge_id": "…", "status": "waitlisted", "message": "…", "expires_in": 600}
```

- `code_sent`: the usual flow, a verification code was emailed.
- `waitlisted`: the address joined the list (or was already on it). **No code
  was sent** and `challenge_id` is a placeholder; do not call
  `/signup/verify` with it.

The answer is the same for a new address, one already waiting and one that
already has an account, so it never reveals which exist. Show the same
"thanks, we'll email you" text in every case. To keep the response time from
telling them apart either, a successful sign-up answer is never sent sooner
than 250 ms after the request arrived, counted from after the password hash when
there is one (errors answer at once). New entries receive a
`waitlist_joined` email. Risk screening, restrictions, CAPTCHA and rate limits
apply exactly as they do to sign-up. An address on an auto-approve domain skips
the list and gets the normal code at once.

The hosted sign-up page shows a "You're on the waitlist" page. In your own UI:

- [`@iamkit/js`](../../reference/sdk/authentication.md): `signup()` returns
  `status: 'code_sent' | 'waitlisted'` and accepts `waitlistToken`.
- [`@iamkit/react`](../../reference/sdk/react-widgets.md): `<SignInForm>` moves
  to a `waitlisted` step with overridable text (`hosted.title.waitlisted`,
  `hosted.notice.waitlisted`); pass `waitlistToken` (read from
  `?waitlist=`) to the flow.
- Go: `authclient.SignupRequest.WaitlistToken` and `Challenge.Status`
  (`SignupCodeSent`, `SignupWaitlisted`).

## Approving

Approving creates a token (`ik_wait_…`, shown only in the email, valid **7
days**) and emails `waitlist_approved` with the link
`<waitlist_signup_url>?waitlist=<token>`. The hosted sign-up page prefills the
address from the token; a headless app sends it as `waitlist_token` together
with the same email. The normal email-code verification still follows, and
completing it marks the entry `completed`. A wrong, expired or used token, or
one for another email, is treated as no token: the request joins the list again
and gets the usual `waitlisted` answer. `WAITLIST_TOKEN_INVALID` (400) is
returned only when an approval is consumed at completion and no longer holds.

Approving an entry that is already approved issues a new token and link; the
old one stops working.

Entries are `pending`, `approved`, `rejected` or `completed`. At most 100,000
entries can be pending in an environment.

### Retention

An hourly background job (`waitlist_prune`) deletes `completed` and `rejected`
entries decided longer ago than `IAMKIT_WAITLIST_RETENTION` (default `8760h`,
365 days; a Go duration of at least `24h`, an invalid value stops start-up).
Age counts from `decided_at` (completing an entry sets no time of its own, so
a completed entry ages from its approval; `created_at` is used when there is
none). `pending` and `approved` entries are never pruned, and pruning writes
no events. Pruning a rejected entry lets that address join again.

## Operating the list

| Surface | How |
| --- | --- |
| Console | **Users & access → Waitlist**: filter by status, search by email prefix, approve, reject (with a **Notify them by email** checkbox), delete, select several rows and approve them, or **Approve all pending** |
| CLI | `iam waitlist list [--status pending] [--email ana]`, `get ID`, `approve ID… \| --all-pending`, `reject ID [--notify]`, `delete ID` |
| API | `…/environments/ENV_UUID/waitlist` under `/management/v1` (or `/api/v1` with `iam:waitlist:read` / `iam:waitlist:write`) |
| SDKs | Go `iamclient` (`ListWaitlist`, `ApproveWaitlistEntry`, `ApproveWaitlist`, `RejectWaitlistEntry`, `DeleteWaitlistEntry`), `@iamkit/node` `waitlist`, Python `iam.waitlist` |

```sh
curl -H "Authorization: Bearer $KEY" \
  "https://IAMKIT_HOST/management/v1/environments/ENV_UUID/waitlist?status=pending&limit=50"
```

| Method and path | Effect |
| --- | --- |
| `GET …/waitlist?status=&email=&limit=&offset=` | List: `{items, page: {total, limit, offset}}`; `email` is a prefix |
| `GET …/waitlist/:id` | One entry |
| `POST …/waitlist/:id/approve` | Approve one |
| `POST …/waitlist/approve` `{ids}` or `{all_pending: true}` | Approve many, at most 500 per call; answers `{approved, skipped, more}`. Entries decided meanwhile are skipped, not errors. Repeat while `more` is true (the CLI's `--all-pending`, the console and the SDKs' `approveAllPending` do) |
| `POST …/waitlist/:id/reject` `{notify?}` | Reject. Silent unless `notify` is true, which sends `waitlist_rejected` |
| `DELETE …/waitlist/:id` | Remove the entry (204). The address can join again |

Approve and reject work on `pending` and `approved` entries; deciding a
`rejected` or `completed` one answers 409 `WAITLIST_ENTRY_NOT_PENDING`. Delete
the entry to let the address join again.

An entry has `id`, `email`, `name`, `locale`, `status`, `created_at`,
`decided_at`, `decided_by`, `expires_at` (of the approval) and
`completed_user_id`.

## Emails

Three [email purposes](../platform/email-delivery.md) are new, customizable
per language like the others (console **Notifications**, or the email-template
API). Placeholders:

| Purpose | Sent | Placeholders |
| --- | --- | --- |
| `waitlist_joined` | When a new address joins | `app_name`, `email` |
| `waitlist_approved` | On approval, with the link | `app_name`, `email`, `expires_at` |
| `waitlist_rejected` | On rejection with `notify` | `app_name`, `email` |

With a [webhook delivery](../../reference/email-webhooks.md), `waitlist_approved`
carries `token`, `link` and `expires_at`; `link` is empty when no
`waitlist_signup_url` is set, so build your own from `token`.

## Who skips the waitlist

The waitlist gates only self-service sign-up with a password or an email code.
These never go through it:

- **Federation** sign-in and first sign-in through social or SSO connections.
- **Invitations**: accepting an organization invitation.
- **SCIM** provisioning.
- **Operator-created users**: the management API, imports and the console.

People who already have an account are unaffected.

## Events

`waitlist.joined` (actor `system`; the data carries the email domain, never the
address), `waitlist.approved`, `waitlist.rejected`, `waitlist.deleted` (actor
the operator) and `waitlist.completed` (the approved person created their
account; `data.user_id`). Subscribe with an [event
webhook](../../reference/event-webhooks.md) to notify your team or sync a CRM.
See the [event reference](../../reference/events.md).
