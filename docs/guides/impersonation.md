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

**Verify:** owner succeeds for a properly entitled user; admin/viewer fails; absent
target grants fail; inspect the actor claim and audit record. End the support flow
and revoke its session when done. Do not promise comprehensive audit coverage for
unrelated operations merely because impersonation is attributable.
