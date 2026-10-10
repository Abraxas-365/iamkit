# Permissions as code

Keep the permissions of each of your APIs in **one manifest file in your
application's repository**. Generate the constants your code checks from it,
fail tests when code and manifest disagree, and sync IAMKit from it with one
idempotent script. Permission strings then stop drifting between route guards,
frontend checks, seed scripts and tests.

This guide is about *permissions*: the resource catalog that becomes the
`permissions` claim of access tokens (see [authorization](../../concepts/authorization.md)).
OAuth *scopes* (`scope=`, claim `scp`) are a different mechanism. Don't call
permissions scopes.

## Name permissions consistently

Use `<prefix>:<entity>:<action>`, lowercase, with `-` inside words:

```text
invoices:invoices:read      invoices:invoices:review
invoices:reports:export     invoices:supplier-users:write
```

- `prefix` is the resource prefix. IAMKit rejects catalog entries without it,
  and it can't be changed after the resource is created. Neither can the
  resource `audience`.
- `entity` is the plural noun for what is guarded.
- `action` comes from a short fixed set: `read`, `write` (create, update,
  delete), `review` (approve, reject), `export`. Add a verb only when none fits.
- Permissions are exact strings. There are no wildcards, so make every route's
  check explicit.
- If another kind of principal acts on its own data (for example external
  partners next to staff), give it its own entity namespace, such as
  `<prefix>:self:*`. Keep it in roles of its own.

## Keep one manifest

Commit a single file, for example `iam/permissions.json`. The
[example manifest](../../examples/permissions/permissions.json):

```json
{
  "resource": {"name": "Invoices API", "prefix": "invoices"},
  "permissions": [
    {"name": "invoices:invoices:read", "label": "View invoices"},
    {"name": "invoices:invoices:write", "label": "Create and edit invoices"}
  ],
  "roles": [
    {"name": "Viewer", "permissions": ["invoices:invoices:read"]}
  ]
}
```

- `permissions` is the resource catalog. Labels are user-facing text for role
  editors and permission pickers, in your application's language.
- `roles` are the roles your application defines on that resource.
  Organizations may add their own, and the sync leaves those alone.
- Add what your project needs, for example a role `kind`, or the `iam:*`
  permissions of your backend's service account. Everything else reads this
  file: route guards, the frontend, provisioning and end-to-end tests.

## Generate the constants your code checks

Generate code from the manifest instead of writing strings by hand, and commit
the generated files:

- **Backend**: one constant per permission, plus the full list and the roles.
  Route guards use the constant
  (`RequirePermissions(permission.InvoicesRead)` with the Go SDK), so a typo or
  a permission missing from the manifest doesn't compile.
- **Frontend (TypeScript)**: a `const` array and a union type derived from it.
  Type the permission parameter of your `can()` helper, route guards and
  navigation with it, so `can('invoices:invoice:read')` fails the type check:

  ```ts
  export const permissions = ['invoices:invoices:read', 'invoices:invoices:write'] as const
  export type Permission = (typeof permissions)[number]
  ```

The generator should refuse an inconsistent manifest before it writes
anything:

- a wrong prefix or name format
- duplicates and empty labels
- role permissions missing from the catalog
- two names that produce the same identifier

With Go, a `//go:generate` directive plus a `make gen` target is enough.

## Test for drift

Cheap tests catch every way the manifest and the code can disagree:

| Test | Fails when |
| --- | --- |
| Generate again and compare with the committed files | the manifest changed without regenerating |
| Scan the backend for `"<prefix>:…"` string literals | a check bypasses the constants |
| Every manifest permission is referenced by backend code | a permission no route checks (an orphan) |
| Role permissions are a subset of the catalog | a role names a permission that doesn't exist |
| End-to-end tests provision IAMKit from the generated lists | tests and the real catalog disagree |

## Sync IAMKit with one idempotent script

Use one script for every environment, local included, instead of separate
"seed" and "sync" scripts. It finds the resource by prefix and roles by name,
creates what is missing and updates what changed. The
[example script](../../examples/permissions/sync.sh) does this for the catalog
and roles of one resource:

```sh
IAMKIT_URL=https://iam.example.com MGMT=ik_mgmt_… ENVIRONMENT=<environment id> \
AUDIENCE=https://api.example.com bash docs/examples/permissions/sync.sh --dry-run
```

Three rules make it safe:

- **`--dry-run` first.** It prints every change (`catalog: +a -b`,
  `role Viewer: +c`) and writes nothing.
- **Additions are applied; removals are not.** Updating a resource's catalog
  (`PUT /resources/:id`) silently removes every dropped permission from all
  roles, grants and service accounts of that resource, in the same
  transaction. So a permission that left the manifest stays in the catalog and
  in the roles holding it, and the script reports it as kept.
- **`--prune` removes them**, only when you ask, once no running version of
  your code checks them.

Service accounts have no route for changing their permissions. If your
manifest changes a service account's permissions, revoke it and create it
again, which issues a new secret.

## Order changes around deployments

- **Add a permission:**
  1. Edit the manifest, regenerate, use the constant, then commit.
  2. Sync **before** deploying code that checks it. Otherwise nobody holds it
     and the route answers 403.
  3. Users receive it with their next access token.
- **Remove a permission:**
  1. Delete it from the manifest and the code, then deploy.
  2. Run the sync with `--prune` **after** no running version checks it.
- **Rename a permission.** Never remove and add in one sync, because the old
  name would vanish from every role and grant before the new code runs:
  1. Add the new name to the manifest, move the roles to it, and switch the
     code to its constant.
  2. Sync. The old name is kept, so running code still works.
  3. Deploy.
  4. Sync with `--prune`. The old name leaves the catalog and the roles.

  Direct grants of the old name are not moved for you. If users hold it
  directly, grant them the new name before pruning.

## Checklist

1. `iam/permissions.json` with the resource, permissions (with labels) and roles.
2. A generator for backend and frontend constants, with its output committed.
3. Route guards and frontend checks use only the generated constants and types.
4. Drift tests in CI.
5. One idempotent sync script with `--dry-run` and `--prune`, used for every
   environment.
6. The deploy order above, written down in your repository's contributor notes.
