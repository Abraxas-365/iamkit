# Upgrades and rollback

Pin the current and target image digest. Review route/configuration/SDK changes,
migrations and secret-format changes before touching traffic. There is no implied
compatibility between arbitrary commits.

## Upgrade

1. Back up database and matching trust/configuration material.
2. Restore a representative copy in isolation and run the exact target migration.
3. Test password, refresh, authorization denial, console, and enabled provider/SCIM
   flows. Check pagination/SDK decoding when upgrading clients too.
4. Determine whether old/new binaries can share the migrated schema. If not,
   schedule a maintenance window rather than an untested rolling deployment.
5. Quiesce traffic if required, apply migrations, start target, verify health and
   functional checks, then admit traffic gradually.
6. Monitor errors, latency, credential failures and database locks.

## Rollback decision

If schema-compatible, redeploy the recorded old digest/configuration and recheck.
If incompatible, a container rollback is insufficient: restore the approved
backup to a separate database and plan cutover/data reconciliation. Never run
invented down migrations or erase checksum history.

Record tested version pair, outage window, validation results and approver in the
release record. A code build does not establish an upgrade/restore procedure.
See [database operations](database-and-migrations.md) and
[backup/restore](backup-and-restore.md).
