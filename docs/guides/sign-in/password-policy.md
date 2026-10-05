# Password policy, lockout and expiry

Each environment has one end-user password policy. Without a saved policy the
default applies: at least 12 bytes (72 at most, the bcrypt limit), no
composition rules, no breach check, no lockout, no expiry. Operator console
passwords are not governed by it.

Manage it in the console (**Sign-in → Password policy**), with the
[management API](../../reference/api/management.md) (`GET|PUT|DELETE
/environments/:environment/password-policy`), the CLI
(`iam password-policy get|set|delete`) or the Go SDK
(`iamclient` `PasswordPolicy`, `SetPasswordPolicy`, `DeletePasswordPolicy`).

| Field | Range | Effect |
| --- | --- | --- |
| `min_length` | 8–72 | Minimum bytes of a new password |
| `require_upper`, `require_lower`, `require_digit`, `require_symbol` | bool | Composition rules for new passwords |
| `breach_check` | bool | Reject passwords found in [Have I Been Pwned](https://haveibeenpwned.com/Passwords) |
| `max_age_days` | 0–3650 | Replace the password at the next password sign-in after this many days; 0 never expires |
| `lockout_threshold` | 0–100 | Wrong passwords in a row that lock the account; 0 never locks |
| `lockout_minutes` | 1–1440 | First lockout; each further lockout doubles, up to 24 hours |

`PUT` replaces the whole policy and is audited as `password_policy.update`;
`DELETE` restores the default (`password_policy.delete`). `GET` returns
`custom: false` for the default.

## New passwords

User creation, [invitation](../organizations/organizations.md) acceptance,
[password reset](passwords.md#forgot-password) and expired-password replacement check the
policy. A rejected password answers 400 `PASSWORD_POLICY` with
`details.rule` — `length`, `upper`, `lower`, `digit`, `symbol`, `breached` or
`reused` (an expired password replaced by itself) — and `details.min_length`, so
your UI can explain the rule without parsing the message:

```json
{"error":{"code":"PASSWORD_POLICY","message":"password must contain a digit","type":"VALIDATION","http_status":400,"details":{"rule":"digit","min_length":12}}}
```

The breach check uses k-anonymity: only the first five hex characters of the
password's SHA-1 leave the server. When the service is slow (3 s) or unreachable
the password is accepted, so an outage never blocks sign-up. Changing the policy
does not invalidate existing passwords; they are checked when next replaced.

## Lockout

Every wrong password counts against the user (`failed_logins` on `GET
/users/:id`), across headless and hosted password sign-ins; a correct one resets
the count. When `lockout_threshold` is set, reaching it sets `locked_until` and
audits `user.locked`. While locked, every password attempt — right or wrong —
answers the same 401 as a wrong password and counts nothing, so an attacker
cannot tell a locked account from a wrong guess. Email-code and SSO sign-ins are
not affected.

Unlock early with `POST /users/:id/unlock` (management, or the scoped API with
`iam:users:write`; audited `user.unlocked`), **Unlock** on the user's console
page, `iam users unlock USER_ID` or `UnlockUser` in the SDK. A completed
password reset also unlocks.

## Expiry

With `max_age_days` set, a correct but expired password is not enough:

- **Headless** (`POST /identity/v1/login`) answers 403
  `PASSWORD_CHANGE_REQUIRED`. Send the same request again with `new_password`;
  the new password must follow the policy and differ from the old one. When the
  user has a [second factor](mfa.md) the login continues with `mfa_required` and
  the new password is saved only once `/identity/v1/mfa/verify` succeeds.
- **Hosted** pages ask for a new password last — after the organization is
  chosen and any second factor passes — just before the session is issued.

Email-code sign-ins are not subject to expiry, and a password reset restarts the
clock. Every new password the user sets this way or by reset is recorded as
`user.password_changed` (`data.method` `sign_in` or `reset`).

### Requiring a change for one user

An operator can make one user's next password sign-in behave as expired, with or
without `max_age_days`: `POST /users/:id/require-password-change` (management,
or the scoped API with `iam:users:write`; audited
`user.password_change_required`), **Require password change** in the danger
zone of the user's console page, `iam users require-password-change USER_ID` or
`RequirePasswordChange` in the SDK. The user shows `password_change_required:
true` until a new password is set (sign-in change or password reset). Users
without a password (email code, SSO, SCIM, machine users) answer 422. The flag
does not end existing sessions: for a suspected compromise also sign the user
out everywhere (see [incident response](../../operations/incident-response.md)).

## Organization requirements

Users belong to the environment, not to one organization: one account, one
password, many memberships. An organization therefore cannot replace the
environment's policy — it can only **add** requirements for its members:

| Field | Effect |
| --- | --- |
| `min_length` | 0 keeps the environment's; otherwise 8–72, the longer applies |
| `require_upper`, `require_lower`, `require_digit`, `require_symbol` | Added to the environment's rules |
| `breach_check` | Turns the breach check on for members |
| `max_age_days` | 0 keeps the environment's; otherwise the shorter expiry applies |

Lockout stays environment-wide. A member's effective policy is the environment
policy tightened by every organization they are an active member of, so a
member of two organizations meets both. It applies to password resets,
expired-password replacement, invitation acceptance into the organization and
users created with it as their `home_organization_id` (by operators or the
organization's [administrators](../organizations/organization-administration.md));
users outside it keep the environment policy.

Existing passwords are not re-checked when requirements change; a shorter
`max_age_days` makes members choose a new, compliant password at their next
password sign-in once theirs is older.

Manage it on the organization's console page (**Password requirements**), with
`GET|PUT|DELETE /environments/:environment/organizations/:id/password-policy`
(`GET` returns `custom: false` when the organization adds nothing; audited
`organization_password_policy.update`/`.delete`),
`iam password-policy get|set|delete --organization ORG_ID` or the SDK
(`OrganizationPasswordPolicy`, `SetOrganizationPasswordPolicy`,
`DeleteOrganizationPasswordPolicy`).

Which methods users may sign in with (password at all, reset, email code,
social) is the [sign-in methods](sign-in-methods.md) policy.

Source: `internal/iam/authentication/password.go`, `authsvc/password.go`,
`adapters/authhibp`, `adapters/authhttp/password.go`.
