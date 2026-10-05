# Errors and pagination

Ordinary API failures use a JSON `error` object with `code`, `message`, `type`
and `http_status`. Treat HTTP status as the transport result and code as a
machine-readable classification; do not branch on English messages. Internal
errors must not be surfaced as stack traces or secret payloads. A few client
errors add a `details` object: `PASSWORD_POLICY` (400, a new password breaks the
[password policy](../guides/sign-in/password-policy.md)) carries `rule`
(`length`, `upper`, `lower`, `digit`, `symbol`, `breached`, `reused`) and
`min_length`. `PASSWORD_CHANGE_REQUIRED` (403) means the password matched but has
expired; resend the login with `new_password`. `METHOD_NOT_ALLOWED` (403) means
the environment or organization does not allow that
[sign-in method](../guides/sign-in/sign-in-methods.md); `PASSWORD_RESET_DISABLED` (403)
that the environment does not offer password reset. `SIGNUP_DISABLED` (403)
means [sign-up](../guides/sign-in/signup-and-onboarding.md#self-service-sign-up) is off;
`ACCOUNT_EXISTS` (409) that the email got an account before the sign-up was
confirmed. `ACTION_DENIED` (403) means an [action](../guides/platform/actions.md) refused
the request (its message is the receiver's); `ACTION_FAILED` (502) that an
action target set to interrupt on error failed.

| Status | Typical action |
| --- | --- |
| 400 | Correct invalid fields/context, not a blind retry |
| 401 | Missing/expired/wrong credential; reauthenticate |
| 403 | Correct authority/permission/tenant policy |
| 404 | Check entity ID and environment visibility |
| 409 | Inspect conflicting state and reconcile |
| 422 | Domain rule; `ENCRYPTION_KEY_REQUIRED` means a secret (SSO client secret, SMTP password, Resend API key) cannot be stored until `IAMKIT_ENCRYPTION_KEY` is set |
| 429 | Back off; avoid parallel login/resend storms |
| 5xx | Check service/dependency health; reconcile ambiguous writes before retry |

OAuth uses OAuth protocol error responses; SCIM uses its SCIM error schema. Do not
force all families into a management error decoder. 204 responses have no JSON.
Some 201 endpoints use a status-only response; only parse `{id}` where documented.

## Entity-list envelope

```json
{"items":[],"page":{"total":0,"limit":50,"offset":0}}
```

Users, organizations, applications, resources, roles, grants, service accounts,
federation lists/identities, OAuth clients and organization members use this
shape. Role assignments use database pagination: default 50, maximum 200,
non-positive limit → 50, negative offset → 0; total reflects all filtered matches.

Other envelope endpoints currently slice an already-loaded collection in memory:
default `limit=0` means all **loaded** items, not necessarily every database row.
Negative limit/offset are normalized; offset beyond the collection clamps to its
length. Repository caps can bound `page.total`; do not use these inventories as
complete exports without checking the underlying query/endpoint.

Workspace keys/operators/projects/environments, sessions/audit, provisioning
credentials and structure read models do not all use the envelope. Preserve
endpoint-specific response handling. SCIM has separate 1-based pagination.
Search parameters are not universal: only document and send filters supported by
the endpoint, notably the role-assignment filters.

Source: `internal/httpx/paginate.go`, handlers, `internal/server/errors.go`.
