# Secrets and key lifecycle

Inventory owners, storage location, consumers, expiry and rotation procedure for:
PostgreSQL credentials, RSA signing key, OAuth HMAC secret, operator/management
credentials, service/SCIM credentials, provider secrets, email webhook token and
SMTP passwords / Resend API keys (global variables and per-environment settings).
Do not keep secrets in examples, browser builds, logs or screenshots.

## Management/service/SCIM credential rotation

1. Authenticate with current authorized credentials.
2. Issue replacement with finite `expires_in`; capture its secret once privately.
3. Deploy it to consumers and test intended requests plus an unauthorized request.
4. Revoke the predecessor by its credential ID and prove rejection.
5. Remove stale copies and update expiry monitoring.

SCIM replacements must retain the connection ID to preserve mappings. Raw service
keys are exchanged for JWTs; revoking them does not retroactively make every
offline JWT consumer aware of the event. Choose online checking when necessary.

## Signing key change

Prefer [environment signing keys](../guides/signing-keys.md): they rotate with
overlap (publish, activate, retire) and need no restart or re-login. Their
private halves are sealed with `IAMKIT_ENCRYPTION_KEY`; keep the old key in
`IAMKIT_ENCRYPTION_KEYS_OLD` while any active or retiring environment key was
sealed with it, or that environment stops signing.

The deployment key (`JWT_PRIVATE_KEY_PATH`) still signs for every environment
without an active key and has no overlap protocol. Schedule a change, back up current material securely, determine
which sessions/tokens must be invalidated, replace the mount atomically, restart
all signers consistently and refresh consumers' JWKS caches. Expect old tokens
not to verify against a key set containing only the replacement. Test re-login,
issuer/audience checks and failure behavior in staging first.

Restoring an old key can re-enable verification of old signatures; evaluate
revocation and compromise implications before rollback. A stolen signing key
requires incident containment, not merely routine restart.

## Encryption key rotation

`IAMKIT_ENCRYPTION_KEY` seals SSO client secrets and LDAP bind passwords, TOTP
secrets, environment SMTP passwords / Resend API keys, SMS credentials (Twilio
auth token, SMS webhook token), event webhook and action target secrets, and
the private halves of environment signing keys. (The environment email
webhook token is stored as is.) To rotate: set the new key, move the old one
to `IAMKIT_ENCRYPTION_KEYS_OLD`, restart, then re-seal what can be re-sealed
and only then drop the old key:

- SSO client secrets and LDAP bind passwords: `PATCH …/federation-connections/:id`
  with `client_secret`.
- Email secret: `PUT …/delivery` with the password or API key, or `iam delivery set`.
- SMS secret: `PUT …/sms` or `iam sms set`.
- Event webhook and action target secrets: `POST …/rotate-secret` (receivers get
  a new secret; the previous one, still under the old key, keeps signing during
  the 24-hour overlap while that key is available and is skipped once it is not).
- Signing keys: [rotate](../guides/signing-keys.md) so the active key is one
  created after the restart, and retire the older ones.

TOTP secrets cannot be re-saved: keep the old key in `IAMKIT_ENCRYPTION_KEYS_OLD`
while factors sealed with it are in use. Anything still sealed with a dropped
key fails closed: email and SMS answer `stored credential could not be
decrypted`, webhook tests and deliveries `the subscription secret cannot be
opened`, action calls `the target secret cannot be opened`, LDAP sign-in 422,
and an environment whose active signing key cannot be opened stops signing.
Each sealed value starts `v1:<key id>:`, where the key id is the first 8 hex
digits of the SHA-256 of the key, so a query shows what still uses the old key. See the
[configuration reference](../reference/configuration.md#encryption-key).

## Deployment details

Use 0600 private files readable only by the runtime identity; use platform secret
mounts where available. Explicit CLI bootstrap writes a new private credential
file. Automatic bootstrap currently logs a credential: restrict logs, move the
key to storage and revoke it after provisioning. Changing bootstrap password
variables on an existing workspace does not reset the operator password.

See [incident response](incident-response.md) and [CLI recovery](../reference/cli.md).
