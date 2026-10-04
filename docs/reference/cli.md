# CLI reference

The container entrypoint is `iamkit`. The CLI connects to `DATABASE_URL` before
handling commands; a reachable configured database is required even for command
parsing. Errors go to stderr and exit nonzero.

| Command | Effect |
| --- | --- |
| `iamkit` | Apply embedded migrations, optionally auto-bootstrap, start HTTP server |
| `iamkit migrate` | Apply migrations and exit |
| `iamkit bootstrap --email EMAIL --workspace NAME --output PATH` | Initialize workspace/owner and write credential JSON |
| `iamkit recover-owner --email EMAIL --workspace UUID --output PATH` | Recover owner authority for an existing workspace |

The command line is checked before any connection to the database: `--email`,
`--workspace` and `--output` are all required, the email must be valid, and
`recover-owner` needs a workspace UUID. A mistake exits 1 naming the flag; an
unknown flag prints the usage and exits 2; `--help` exits 0 without a database.

`--workspace` is a **name** for bootstrap and a **UUID** for recovery. `--output`
is mandatory and must not exist; its parent directory must be writable. Files
are exclusively created with mode 0600 and contain `management_key`. Credentials
expire in 24h. Protect the file and verify it through `GET /management/v1/me` with
`X-API-Key`. Never use a publicly mounted directory or overwrite an old file.

Recovery requires an existing active owner and revokes their workspace management
keys and console sessions, then clears their password. Warn affected automation
consumers and re-establish the password for console login. Other operators'
credentials are unaffected.

The explicit CLI does not set an operator password and ignores
`IAMKIT_BOOTSTRAP_PASSWORD` (it warns when that variable is set); set it through management
`POST /password` after authenticating. Automatic bootstrap instead optionally
uses `IAMKIT_BOOTSTRAP_PASSWORD` as a temporary password (replaced at the
first console sign-in) and currently logs its management key. Omit
automatic bootstrap when credential logging is unacceptable. A
`IAMKIT_BOOTSTRAP_PASSWORD` outside 12-72 characters stops start-up before the
workspace is created.

Normal shutdown handles SIGINT/SIGTERM and allows 10 seconds for HTTP shutdown.
Do not use process restarts as migration rollback. See
[database operations](../operations/database-and-migrations.md) and
[incident response](../operations/incident-response.md).
