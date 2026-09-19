# Database and migrations

IAMKit embeds SQL migrations in the binary/image and applies them at startup.
`iamkit migrate` applies them without serving HTTP. Use a dedicated managed schema;
initialization refuses an unmanaged non-empty database. Applied migration
checksums detect changed migration content.

## Before an upgrade

Record current image digest and migration history, back up the database and
signing/configuration material, verify backup readability, and identify whether
all deployed replicas can use the target schema. Never edit an already-applied
migration to repair a deployment: ship a reviewed forward migration.

## Apply and verify

1. Quiesce writers or follow a tested release-specific compatibility sequence.
2. Run the target image's `iamkit migrate` with the target DATABASE_URL.
3. Start one target backend and verify health, login, introspection and an
   authorization-denial test.
4. Roll out remaining replicas only after success.

The normal startup path also migrates. Coordinate rollout and do not infer that
concurrent migration safety implies mixed-version application compatibility.
If a migration fails, retain the error and inspect database state before retry.
Do not delete history rows or bypass checksums to force startup.

## Rollback

There is no universal down-migration command in this CLI. Rolling back an image
is safe only when the previous binary is compatible with the resulting schema.
Otherwise recover a verified backup into a separate database and account for
writes since that backup. See [upgrades](upgrades-and-rollback.md).

Test databases must be disposable and unrelated to development/production data.
Run the migration integration tests before release; they are not a replacement
for rehearsing the actual release-pair upgrade with representative data.
