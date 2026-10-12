# Signup and onboarding

Two ways to create accounts:

- **Self-service sign-up** — people create their own account after confirming
  their email. Off by default; see [below](#self-service-sign-up).
- **Backend onboarding** — your backend decides eligibility and calls the
  management API. Use it when sign-up needs your own checks (payment, an
  invitation code, an approval) or lands users in different organizations.

## Self-service sign-up

Turn it on in the environment's [sign-in methods](sign-in-methods.md)
(console **Sign-in → Sign-in methods → Sign-up**, `PUT /sign-in-policy`,
`iam sign-in-policy set --allow-signup --signup-organization ORG_UUID
[--signup-group GROUP_UUID]`, SDK `iamclient.SetSignInPolicy`):

| Field | Meaning |
| --- | --- |
| `allow_signup` | Offer sign-up; needs `allow_password` or `allow_email_code` |
| `signup_organization_id` | Required with `allow_signup`: the organization every new account joins |
| `signup_group_id` | Optional group of that organization (not a SCIM-provisioned one) the account joins; give the group roles to grant access |
| `require_terms` | Sign-up must accept the terms ([below](#terms-acceptance)); `iam sign-in-policy set --require-terms` |
| `waitlist` | Put password / email-code sign-up behind an operator's approval ([below](#waitlist)); needs `allow_signup` |
| `waitlist_auto_approve_domains` | Email domains (≤ 50) that skip the waitlist |
| `waitlist_signup_url` | HTTPS sign-up page the approval email links to (`?waitlist=<token>` is appended); its origin must be IAMKit's own or an `allowed_origins` entry of an active OAuth client of the environment (422 otherwise); empty: the email carries the token only |

The flow, headless ([identity API](../../reference/api/identity.md)) or hosted:

1. `POST /identity/v1/signup` `{environment_id, email, name, password?,
   locale?, accept_terms?, waitlist_token?}` → 202 `{challenge_id, status,
   message, expires_in}` and an `email_verification`
   code by email (`status` is `code_sent`; `waitlisted` with the [waitlist](#waitlist) on). The password follows the [password
   policy](password-policy.md) of the sign-up organization; without one the
   account signs in with email codes (only when the organization allows them).
   A successful answer takes at least 250 ms (after the password hash, when
   one is set) whether the address is new or already has an account (errors
   are immediate), so timing reveals nothing.
2. `POST /identity/v1/signup/verify` `{environment_id, challenge_id, code}` →
   201 `{user_id, organization_id, email}`. Only now does the account exist
   (email verified, member of the organization and group; audited
   `user.signup`). It returns no session: sign in next. The hosted pages
   continue the sign-in themselves.

Nothing reveals existing accounts: an email that already has one gets the same
202 and no email (its code never works); at most 5 sign-ups per email per 10
minutes send mail. Codes expire in 5 minutes and allow 5 wrong tries.
An email taken between both steps answers 409 `ACCOUNT_EXISTS`; an email of an
organization enforcing SSO answers 403 `SSO_REQUIRED`; sign-up off (or the
organization allowing neither passwords nor email codes) answers 403
`SIGNUP_DISABLED`.

On the [hosted pages](../applications/hosted-login.md) the sign-in page shows **Create
account**. A client can hide it (`"signup": false` in its sign-in methods).
When the new account's group grants nothing in the client's application, the
page says the account was created and access is pending.

### Waitlist

With `waitlist` on, only people an operator approves can sign up with a
password or an email code. Social sign-ups (federation connections that
create accounts), invitations, SCIM and operator-created users are not gated.

- `POST /identity/v1/signup` from an address that is not auto-approved
  (`waitlist_auto_approve_domains`) and has no valid `waitlist_token` joins the
  list: 202 `{challenge_id, status: "waitlisted", …}`, no code. The answer is
  identical for a new address, one already waiting, one with an account and a
  full list, so it never reveals which exist. New entries get a
  `waitlist_joined` email. Risk screening, restrictions, CAPTCHA and rate
  limits still apply.
- Operators list entries (`?status=pending|approved|rejected|completed`,
  `?email=` prefix), approve (`POST …/waitlist/:id/approve`, or in bulk
  `POST …/waitlist/approve` `{ids}` / `{all_pending: true}`, ≤ 500 per call),
  reject (`POST …/waitlist/:id/reject` `{notify?}`; silent unless `notify`) and
  delete (frees the address, also after a rejection) under
  `/management/v1/environments/ENV_UUID/waitlist` (`/api/v1`:
  `iam:waitlist:read` / `iam:waitlist:write`).
- Approving emails (`waitlist_approved`, customizable like other
  [email templates](../platform/email-delivery.md#emails-iamkit-writes-smtp-resend)) a link `<waitlist_signup_url>?waitlist=<ik_wait_…>`
  valid 7 days. The hosted sign-up page prefills the address and carries the
  token; headless apps send it as `waitlist_token` with the same email. The
  normal email-code verification still follows, and completing it marks the
  entry `completed`.

### Terms acceptance

With `require_terms`, a sign-up without `"accept_terms": true` answers 400
`TERMS_REQUIRED` before anything is sent. The acceptance time is kept with
the pending sign-up and written to the user as `terms_accepted_at` (`GET
/users/:id`) once the email is confirmed. The hosted sign-up page shows a
required checkbox linking the branding's [legal](../applications/hosted-login.md#legal-links)
`terms_url` (and `privacy_url`); set them before turning this on. Accounts
created otherwise (operators, invitations, SCIM, federation) have no
`terms_accepted_at`.

Accounts created this way get only what the organization and group give. For
anything conditional, use backend onboarding instead.

## Backend onboarding

Your backend decides eligibility and calls IAMKit; do not let the frontend
choose privileged organization IDs or grants.

### Authority

Use `X-API-Key` on `/management/v1/environments/ENV_UUID` from a trusted operator
backend. This credential is workspace-wide; your backend must restrict requested
environments, organizations and grants. The alternative JWT
[`/api/v1` surface](../../reference/api/scoped-iam.md) is limited to one environment
and the IAM permissions of its service account; grant only the families you use.

### Orchestrate

1. Validate signup policy, invitation and email-ownership requirements in your app.
2. `POST /users` with name/email and optional password/OTP preference; save the ID.
3. `POST /memberships` with server-selected organization and user ID.
4. `PUT /grants` or `POST /role-assignments` with a server-selected default policy.
5. Return an application-level success result; never return automation credentials.
6. Start normal identity login using the app/resource boundary.

See the [executable tutorial](../../examples/onboarding/run.sh) for exact management
requests and ID handling. Creation, membership and grant are separate operations,
not an atomic signup transaction. Persist progress, handle conflicts and resume
only the missing operations. Do not blindly recreate users after a timeout or
assume email equality authorizes linking to an existing identity.

If onboarding fails midway, leave an explicit pending state in your application
and avoid granting access until policy checks complete. Compensation must not
suspend an existing user shared by another organization.

Federation signup requires a pre-created local user and a trusted provider-subject
link. Do not auto-link by matching email. Password reset cannot add a password to
a passwordless account through the reset flow.

**Verify:** a user without membership/grant cannot log into the resource; an
onboarded user can. A second tenant cannot claim the same permissions by changing
request IDs. Test duplicate submission and failure after every write.
