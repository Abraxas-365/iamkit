# Backup and restore

Back up **both database state and trust material**: PostgreSQL, RSA signing key,
issuer/configuration, OAuth HMAC, provider/webhook credentials and recovery access.
Use encrypted storage with access controls, retention, integrity checks and an
owner. Database backups contain personal data and credential hashes; treat them
as sensitive even when raw passwords are absent.

## Backup procedure

1. Record image digest/schema version and recovery objectives (RPO/RTO).
2. Use your PostgreSQL provider's consistent snapshot/PITR or `pg_dump` custom
   format with a PostgreSQL-compatible client. Keep DB credentials out of command
   histories; use a protected service/password file.
3. Store secret material in a separately controlled secret backup.
4. Verify backup completion, checksum and ability to list/read the archive.
5. Alert on missed backups and periodically rehearse restore.

Example command shape, using a preconfigured private PostgreSQL service:

```sh
pg_dump 'service=iamkit-backup' --format=custom --file=/secure/backup/iamkit.dump
pg_restore --list /secure/backup/iamkit.dump
```

These commands require your service definition and an existing restricted output
directory. Do not place database passwords in the URI shown in shell history.

## Restore rehearsal

1. Create a **new isolated database**, not the running production target.
2. Restore using `pg_restore --exit-on-error --dbname='service=iamkit-restore' /secure/backup/iamkit.dump`
   with a role capable of recreating the schema; verify extensions/ownership for your platform.
3. Mount matching signing material and use the compatible recorded image.
4. Keep restored mail/federation/SCIM integrations isolated to prevent real sends.
5. Verify health, user/membership/grant counts, test login, current token checking
   and denied tenant access. Record actual recovery duration/data-loss window.
6. Revoke/reconcile restored sessions and credentials according to incident policy:
   a historical backup can resurrect state that was revoked after the snapshot.

For a real cutover, stop/quiesce writes, approve the data-loss window, switch the
connection target, verify again and retain the previous system read-only for
investigation. A successful `pg_restore` alone is not service recovery.
