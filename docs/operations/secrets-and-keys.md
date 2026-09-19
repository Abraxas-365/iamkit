# Secrets and key lifecycle

Inventory owners, storage location, consumers, expiry and rotation procedure for:
PostgreSQL credentials, RSA signing key, OAuth HMAC secret, operator/management
credentials, service/SCIM credentials, provider secrets and email webhook token.
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

Only one private signing key is configured. Do not assume an overlap/automatic
rotation protocol. Schedule a change, back up current material securely, determine
which sessions/tokens must be invalidated, replace the mount atomically, restart
all signers consistently and refresh consumers' JWKS caches. Expect old tokens
not to verify against a key set containing only the replacement. Test re-login,
issuer/audience checks and failure behavior in staging first.

Restoring an old key can re-enable verification of old signatures; evaluate
revocation and compromise implications before rollback. A stolen signing key
requires incident containment, not merely routine restart.

## Deployment details

Use 0600 private files readable only by the runtime identity; use platform secret
mounts where available. Explicit CLI bootstrap writes a new private credential
file. Automatic bootstrap currently logs a credential: restrict logs, move the
key to storage and revoke it after provisioning. Changing bootstrap password
variables on an existing workspace does not reset the operator password.

See [incident response](incident-response.md) and [CLI recovery](../reference/cli.md).
