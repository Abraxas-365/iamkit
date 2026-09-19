# Incident response and owner recovery

## Suspected credential compromise

1. Identify credential family/scope, affected consumers and time window; restrict
   traffic if needed without destroying evidence.
2. Revoke management/service/SCIM credentials by ID, or revoke affected sessions.
   Disable a provider connection when its trust is compromised.
3. Issue replacement credentials through a trusted path and deploy securely.
4. Test rejection of the predecessor and expected access with replacement.
5. Investigate audit/application/platform logs without copying secrets into tickets.

Offline JWT consumers may accept a previously issued token until expiry. For
urgent containment use online validation or temporarily block affected traffic.
Signing-key compromise requires a coordinated trust-key change and cache handling;
see [secrets](secrets-and-keys.md). Removing an external identity link alone is not
proof every existing session has ended.

## Lost owner credential

Requires trusted database/host access, not a public recovery endpoint. Recovery
requires the email of an **existing active owner**. It revokes that owner's keys
and console sessions in the workspace and clears their password; warn affected
automation consumers before proceeding. Other operators are unaffected. Record
the workspace UUID, then execute the compatible image's CLI:

```sh
iamkit recover-owner --email owner@example.com --workspace WORKSPACE_UUID \
  --output /secure/new-owner.json
```

Replace the UUID and ensure the output does not exist. The CLI writes a 0600 file
and a 24-hour credential. Move it into secret storage, verify `/management/v1/me`
with `X-API-Key`, re-establish the operator password for console access, issue an
operational key and revoke temporary credentials. Update automation that used
the revoked keys. Review other operators' credentials separately.

If database state itself is compromised, preserve evidence and use the
[restore runbook](backup-and-restore.md), reconciling resurrected sessions and
credentials. Record actions, verification and follow-up controls after recovery.
