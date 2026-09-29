# Impersonation

Use impersonation for attributable support actions, not normal login. A workspace
**owner** calls POST `/management/v1/environments/ENV_UUID/impersonations` with
`organization_id`, `application_id`, `resource_id`, `user_id` and a meaningful
`reason` (10–1000 trimmed characters), authenticated with a management key/cookie.

The target still needs valid local access. Success returns an application access
token with `actor_id` identifying the operator, a short expiry and **no refresh**.
Record the support ticket/reason in your process and never expose the owner key
to the support user's browser.

Impersonated tokens cannot authorize OAuth or mutate self-service profiles. Your
business API should inspect `actor_id` and restrict sensitive actions (payments,
credential changes, exports) according to your policy. Never strip attribution
when forwarding identity.

## Service accounts (token exchange)

Support tooling that runs unattended can impersonate through
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange instead of a
management key. A workspace **owner** first allows the service account:
console **Service accounts → ⋯ → Allow impersonation**, CLI
`iam service-accounts set-impersonation ID --allow`, or PUT
`.../service-accounts/:id/impersonation` `{"allowed":true}` (audited
`service_account.impersonation`; admins get 403). The account then
authenticates at `/oauth/token` exactly as for `client_credentials`
(secret or `private_key_jwt`) and sends:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user UUID>
subject_token_type=urn:iamkit:params:oauth:token-type:user_id
organization_id=<organization UUID>
reason=Support ticket 4812: invoices missing
audience=<the account's resource audience>   (optional)
```

The token is for the account's own application and resource, with the
**user's** permissions there (the user needs access in that organization),
15 minutes, no refresh. It carries `"act": {"sub": "<account id>"}` instead of
`actor_id`; like operator impersonation it cannot authorize OAuth or change
self-service settings. Each exchange opens a session with the reason, audited
`oauth.impersonated`. Forbidding impersonation again (`--forbid`) ends every
session the account opened. In Go:
`authclient.NewOAuth(issuer, accountID, secret).Impersonate(ctx, userID, orgID, reason)`.

**Verify:** owner succeeds for a properly entitled user; admin/viewer fails; absent
target grants fail; inspect the actor claim and audit record. End the support flow
and revoke its session when done. Do not promise comprehensive audit coverage for
unrelated operations merely because impersonation is attributable.
