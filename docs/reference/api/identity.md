# Identity API

Base: `/identity/v1`. JSON bodies use `Content-Type: application/json`.
`boundary` below means UUID fields `environment_id`, `organization_id`,
`application_id`, `resource_id`. No management key is accepted as user login proof.

| Method/path | Input/authority | Success |
| --- | --- | --- |
| `POST /login` | boundary + `email`, `password` | 200 token pair |
| `POST /refresh` | original boundary + `refresh_token` | 200 replacement token pair |
| `POST /machine-token` | Bearer `ik_svc_…`; no body needed | 200 access token, no user refresh |
| `POST /challenges` | `environment_id`, `email`, `purpose` | 202 challenge response |
| `POST /challenges/verify` | `environment_id`, `challenge_id`, `code`, `purpose`; full boundary for login; `password` for reset | Login: 200 pair; reset/verification: 204 |
| `POST /discover` | `environment_id`, `email` | 200 `{method:"sso"\|"password",organization_id?,connection_id?,required}`; by email domain only; rate limited |
| `POST /invitations/preview` | `token` | 200 [invitation preview](#invitations); 401 unknown, used, revoked or expired; rate limited |
| `POST /invitations/accept` | `token`, `name?`, `password?` | 200 `{user_id,organization_id,email,sso_required,created}`; no session; rate limited |
| `POST /federation/start` | boundary + `connection_id`; organization connections need their own `organization_id` | 200 `{authorization_url}` + binding cookie |
| `GET /federation/callback` | `code`, `state` query + binding cookie | 200 token pair |
| `POST /introspect` | Bearer access token; `environment_id`, `audience` | 200 `{active:false}` or `{active:true,claims:{…}}` |
| `POST /logout` | Bearer user token; `environment_id`, `audience` | 204 |
| `GET /me` | Bearer user token; query `environment_id`, `audience` | 200 profile |
| `PATCH /me` | Bearer user token; `environment_id`, `audience`, `name` | 204 |
| `GET /organizations` | Bearer user token; query `environment_id`, `audience` | 200 organization array |
| `POST /memberships` | Bearer user token; `environment_id`, `audience`, `user_id` | 201; requires `iam:members:write` |

The membership endpoint uses the authenticated user's organization context; it
is not unrestricted signup. Impersonated tokens cannot update self-service profiles.
Encode query values using `URLSearchParams`/`url.Values`, especially audiences.

Token pair:

```json
{"access_token":"SECRET_JWT","refresh_token":"SECRET_REFRESH","token_type":"Bearer","expires_in":900}
```

Challenge response:

```json
{"challenge_id":"UUID","message":"If eligible, a code will be sent.","expires_in":300}
```

Purpose is exactly `login`, `password_reset` or `email_verification`. Unknown or
ineligible users get a generic challenge result to avoid exposing registration
state; 202 does not prove delivery. Login requires OTP enabled, reset requires an
existing password. Codes are 8 characters, expire in 5 minutes and allow 5 failed
attempts. Delivery must be configured before issuing challenges.

Profile endpoints require application-purpose access and current valid state.
Logout revokes the session; offline JWT consumers still need expiry or online
checking. Refresh rotates the token: never reuse the predecessor after success.

Federation is browser-cookie-bound over HTTPS. The callback returns JSON tokens,
not a hosted application redirect. See [federation](../../guides/federation.md).
Errors follow [the JSON contract](../errors-and-pagination.md), except protocol
families documented separately.

Source: `internal/server/server.go`,
`internal/iam/authentication/adapters/authhttp/{handler,tokens}.go`.

## Invitations

Invitation tokens (`ik_inv_…`) travel in the JSON body, never in the URL, so
they stay out of request logs. Your invitation page reads `token` from its own
query string and posts it.

Preview returns `{organization_id,organization_name,email,expires_at,status,password_required,sso_required}`
with the email masked (`b***@example.com`). An invalid, used, revoked or expired
token returns the same 401, so tokens cannot be probed.

Accept rules:

- **New account:** `password` (12–72 characters) is required, unless the
  organization enforces SSO for the email's verified domain; then it is
  rejected (400) and the person signs in through SSO, which links by email.
- **Existing account:** `password` is rejected (400); accepting never changes
  credentials. An inactive account returns 422; an inactive membership is
  reactivated.
- The email is marked verified (the invitee proved control of the mailbox),
  the membership, invited roles and still-existing operator-managed groups are
  added in one transaction, and the token is consumed. Roles or groups deleted
  since the invitation are skipped.
- Accept does not sign the person in; call `/login` (or start SSO when
  `sso_required`) afterwards. Inactive organizations return 422.
