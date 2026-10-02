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

The flow, headless ([identity API](../reference/api/identity.md)) or hosted:

1. `POST /identity/v1/signup` `{environment_id, email, name, password?,
   locale?, accept_terms?}` → 202 `{challenge_id, expires_in}` and an `email_verification`
   code by email. The password follows the [password
   policy](password-policy.md) of the sign-up organization; without one the
   account signs in with email codes (only when the organization allows them).
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

On the [hosted pages](hosted-login.md) the sign-in page shows **Create
account**. A client can hide it (`"signup": false` in its sign-in methods).
When the new account's group grants nothing in the client's application, the
page says the account was created and access is pending.

### Terms acceptance

With `require_terms`, a sign-up without `"accept_terms": true` answers 400
`TERMS_REQUIRED` before anything is sent. The acceptance time is kept with
the pending sign-up and written to the user as `terms_accepted_at` (`GET
/users/:id`) once the email is confirmed. The hosted sign-up page shows a
required checkbox linking the branding's [legal](hosted-login.md#legal-links)
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
[`/api/v1` surface](../reference/api/scoped-iam.md) is limited to one environment
and the IAM permissions of its service account; grant only the families you use.

### Orchestrate

1. Validate signup policy, invitation and email-ownership requirements in your app.
2. `POST /users` with name/email and optional password/OTP preference; save the ID.
3. `POST /memberships` with server-selected organization and user ID.
4. `PUT /grants` or `POST /role-assignments` with a server-selected default policy.
5. Return an application-level success result; never return automation credentials.
6. Start normal identity login using the app/resource boundary.

See the [executable tutorial](../examples/onboarding/run.sh) for exact management
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
