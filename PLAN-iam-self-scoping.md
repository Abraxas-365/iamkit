# IAM Self-Scoping: System `iam` Resource + Membership Simplification

## Overview

IAM should dogfood its own permission system. Every environment gets a built-in `iam` resource with standard scopes. The hardcoded membership `role` column (`owner/admin/member`) is dropped — org governance is handled through grants/roles on the `iam` resource like everything else.

---

## Phase 1: Backend — System `iam` Resource

### 1.1 Remove reserved prefix blocks

**Files:**
- `internal/identity/model.go`

**Changes:**
- In `ValidatePermissions()` (line 54): remove the checks for `v == "iam"`, `strings.HasPrefix(v, "iam:")`, `v == "management"`, `strings.HasPrefix(v, "management:")`. These are now valid because `iam` becomes a real resource.
- In `ValidatePrefix()` (line 79–80): remove the block that rejects `p == "iam" || p == "management"`.

**Tests:**
- `internal/identity/model_test.go`: update `TestPermissionBoundary` — `"iam:users:write"` and `"management:keys:write"` should now be **accepted** (remove them from the rejected list). Add them to a valid-permissions test case. Keep rejecting `"iam:*"` (wildcards still banned) and bare `"iam"` (still invalid — it has no colon action).

Wait — bare `"iam"` without a colon: the existing check `v == "iam"` was a reserved-word block, not a format check. After removing it, `"iam"` alone would pass validation. But with prefix enforcement, resources with prefix `iam` require `iam:something`, so bare `"iam"` would be rejected at the prefix level. For resources WITHOUT a prefix (backward compat when prefix is empty string), `"iam"` alone is technically a valid scope name. This is fine — no resource will have prefix="" going forward since it's required.

Actually, let me re-examine: `ValidatePermissions` also blocks `strings.ContainsAny(v, "* \t\r\n")` which already rejects wildcards. The `iam:*` case is caught by the `*` character ban. So removing the `iam` prefix block is safe. Remove both `iam` and `management` reserved checks from both functions.

### 1.2 Auto-create `iam` resource on environment creation

**File:** `internal/iam/management/adapters/mgmtpg/control.go`

**Current** `CreateEnvironment` (line 120–133):
```go
func (r *Repository) CreateEnvironment(ctx context.Context, workspace, project, id, name string) error {
    res, err := r.db.ExecContext(ctx, `INSERT INTO environments(id,project_id,name) SELECT $1,id,$2 FROM projects WHERE id=$3 AND workspace_id=$4`, id, name, project, workspace)
    ...
}
```

**Change:** After the environment INSERT succeeds (after the `n == 0` check), insert the system `iam` resource:

```go
iamResourceID := uuid.NewString()  // import "github.com/google/uuid" at package level
iamPermissions := pq.Array([]string{
    "iam:users:read", "iam:users:write",
    "iam:orgs:read", "iam:orgs:write",
    "iam:members:read", "iam:members:write",
    "iam:apps:read", "iam:apps:write",
    "iam:resources:read", "iam:resources:write",
    "iam:roles:read", "iam:roles:write",
    "iam:grants:read", "iam:grants:write",
    "iam:service-accounts:read", "iam:service-accounts:write",
})
_, err = r.db.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,prefix,audience,permissions) VALUES($1,$2,'IAM',$3,$4,$5)`,
    iamResourceID, id, "iam", "urn:iamkit:environment:"+id, iamPermissions)
if err != nil {
    return failure(err)
}
```

Add imports: `"github.com/google/uuid"` and `"github.com/lib/pq"`.

**Important:** This means every NEW environment gets an `iam` resource. For EXISTING environments, the migration handles it (see Phase 3).

### 1.3 Prevent deletion/prefix-change of system `iam` resource

**File:** `internal/iam/authorization/authzsvc/service.go`

The `iam` resource should not be deletable. Currently there is no delete endpoint for resources (check `authzhttp/handler.go` — only POST, GET, PUT, no DELETE). Good — no change needed for deletion.

The prefix is already immutable (not in the `Catalog` struct used for PUT). Good — no change needed.

The `UpdateCatalog` should still work — operators can add/remove scopes from the iam resource's catalog. This is intentional — they might want to add custom `iam:*` scopes.

---

## Phase 2: Backend — Drop Membership Role

### 2.1 Migration

**File:** `migrations/014_drop_membership_role.up.sql` (new)

```sql
-- Drop the membership role column. Org governance now uses iam:* grants.
-- First drop the constraint check, then the column.
-- The trigger on role changes also needs updating.
DROP TRIGGER IF EXISTS membership_changed ON memberships;

-- Recreate trigger without role reference
CREATE OR REPLACE FUNCTION invalidate_identity_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='users' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND user_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='organizations' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND organization_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='applications' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND application_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='roles' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND resource_id=OLD.resource_id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='memberships' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND organization_id=OLD.organization_id AND user_id=OLD.user_id AND revoked_at IS NULL;
 END IF;
 RETURN NULL;
END $$;

CREATE TRIGGER membership_changed AFTER UPDATE ON memberships FOR EACH ROW WHEN ((OLD.active) IS DISTINCT FROM (NEW.active)) EXECUTE FUNCTION invalidate_identity_sessions();

ALTER TABLE memberships DROP COLUMN role;
```

**WARNING:** Check `migrations/005_identity_security.up.sql` lines 5-10 — it already recreated this trigger with `WHEN ((OLD.active,OLD.role) IS DISTINCT FROM (NEW.active,NEW.role))`. Our new migration drops and recreates it without `OLD.role`.

### 2.2 Organization domain model

**File:** `internal/iam/organization/organization.go`

Find the Member struct (around line 24):
```go
type Member struct {
    ...
    Role string `json:"role"`
    ...
}
```
Remove the `Role` field.

**File:** `internal/iam/organization/ports.go` (line 7):
```go
type MemberInput struct {
    ...
    Role string `json:"role"`
}
```
Remove the `Role` field.

### 2.3 Organization repository

**File:** `internal/iam/organization/adapters/orgpg/repository.go`

Line 89 — `AddMember`:
```go
// BEFORE:
_, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id,role) VALUES($1,$2,$3,$4)`, environment, input.Organization, input.User, input.Role)
// AFTER:
_, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)`, environment, input.Organization, input.User)
```

Lines 97-102 — Member list query: remove `role` from SELECT and the struct:
```go
// BEFORE:
type row struct {
    UserID string `db:"user_id"`
    Role   string `db:"role"`
    Active bool   `db:"active"`
}
// query: SELECT user_id,role,active FROM memberships ...

// AFTER:
type row struct {
    UserID string `db:"user_id"`
    Active bool   `db:"active"`
}
// query: SELECT user_id,active FROM memberships ...
```

**File:** `internal/iam/organization/adapters/orgpg/structure.go` (line 20):
```go
// BEFORE:
organization.Members: `SELECT coalesce(json_agg(t),'[]') FROM (SELECT user_id,role,active,org_unit_id,manager_id FROM memberships ...`
// AFTER:
organization.Members: `SELECT coalesce(json_agg(t),'[]') FROM (SELECT user_id,active,org_unit_id,manager_id FROM memberships ...`
```

### 2.4 Authentication — AddMember

**File:** `internal/iam/authentication/adapters/authpg/tokens.go`

Line 67 — The `AddMember` SQL currently checks `role IN ('owner','admin')`:
```go
// BEFORE:
res, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id,role) SELECT $1,$2,$3,'member' FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$4 AND active AND role IN ('owner','admin')`, ...)
```

**New approach:** Instead of checking the membership role, check that the calling user has an `iam:members:write` grant. This requires joining `effective_grants`:

```go
// AFTER:
res, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id)
SELECT $1,$2,$3 FROM effective_grants
WHERE environment_id=$1 AND organization_id=$2 AND user_id=$4
AND 'iam:members:write' = ANY(permissions)`, t.EnvironmentID, t.OrganizationID, user, t.Subject)
```

This means: "insert this membership ONLY IF the requesting user has `iam:members:write` permission in this org+environment via any resource." The `effective_grants` view already unions direct grants and role assignments.

**Wait — `effective_grants` is scoped to a specific resource_id.** We need to check if the user has `iam:members:write` on ANY resource (specifically the `iam` resource). Let me refine:

```go
res, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id)
SELECT $1,$2,$3 WHERE EXISTS(
  SELECT 1 FROM effective_grants eg
  JOIN resources r ON r.id=eg.resource_id AND r.environment_id=eg.environment_id AND r.prefix='iam'
  WHERE eg.environment_id=$1 AND eg.organization_id=$2 AND eg.user_id=$4
  AND 'iam:members:write' = ANY(eg.permissions)
)`, t.EnvironmentID, t.OrganizationID, user, t.Subject)
```

### 2.5 Authentication — Organizations response

**File:** `internal/iam/authentication/adapters/authpg/tokens.go`

Line 59 — Organizations query returns `m.role`:
```go
// BEFORE:
err := r.db.SelectContext(ctx, &out, `SELECT o.id,o.name,m.role,m.org_unit_id,m.manager_id FROM organizations o JOIN memberships m ...`)
// AFTER:
err := r.db.SelectContext(ctx, &out, `SELECT o.id,o.name,m.org_unit_id,m.manager_id FROM organizations o JOIN memberships m ...`)
```

**File:** `internal/iam/authentication/token.go`

Line 31-37 — Organization struct:
```go
// BEFORE:
type Organization struct {
    ID      string  `json:"id" db:"id"`
    Name    string  `json:"name" db:"name"`
    Role    string  `json:"role" db:"role"`
    Unit    *string `json:"org_unit_id" db:"org_unit_id"`
    Manager *string `json:"manager_id" db:"manager_id"`
}
// AFTER: remove Role field
type Organization struct {
    ID      string  `json:"id" db:"id"`
    Name    string  `json:"name" db:"name"`
    Unit    *string `json:"org_unit_id" db:"org_unit_id"`
    Manager *string `json:"manager_id" db:"manager_id"`
}
```

### 2.6 SCIM provisioning

**File:** `internal/iam/provisioning/adapters/provpg/repository.go`

Line 101 — hardcodes `'member'` role:
```go
// BEFORE:
{`INSERT INTO memberships(environment_id,organization_id,user_id,role,active) VALUES($1,$2,$3,'member',$4)`, ...}
// AFTER:
{`INSERT INTO memberships(environment_id,organization_id,user_id,active) VALUES($1,$2,$3,$4)`, ...}
```

Remove `role` from all membership INSERT/UPDATE statements in this file. Grep for `role` within this file to catch all.

### 2.7 E2E tests

**File:** `tests/e2e/identity_test.go`

Lines 112, 114 — test membership creation with `"role": "owner"`:
```go
// BEFORE:
call("POST", base+"/memberships", owner, fiber.Map{"organization_id": orgA, "user_id": devuser, "role": "owner"}, 409)
call("POST", base+"/memberships", owner, fiber.Map{"organization_id": org, "user_id": user, "role": "owner"}, 201)
// AFTER: remove the "role" key
call("POST", base+"/memberships", owner, fiber.Map{"organization_id": orgA, "user_id": devuser}, 409)
call("POST", base+"/memberships", owner, fiber.Map{"organization_id": org, "user_id": user}, 201)
```

---

## Phase 3: Migration for Existing Environments

**File:** `migrations/014_drop_membership_role.up.sql` (append to the migration from 2.1, OR make it `015`)

Actually, let's split into TWO migrations for ordering:

**File:** `migrations/014_system_iam_resource.up.sql` (new)
```sql
-- Auto-create the system iam resource for every existing environment that lacks one.
INSERT INTO resources (id, environment_id, name, prefix, audience, permissions)
SELECT
  gen_random_uuid(),
  e.id,
  'IAM',
  'iam',
  'urn:iamkit:environment:' || e.id,
  ARRAY[
    'iam:users:read', 'iam:users:write',
    'iam:orgs:read', 'iam:orgs:write',
    'iam:members:read', 'iam:members:write',
    'iam:apps:read', 'iam:apps:write',
    'iam:resources:read', 'iam:resources:write',
    'iam:roles:read', 'iam:roles:write',
    'iam:grants:read', 'iam:grants:write',
    'iam:service-accounts:read', 'iam:service-accounts:write'
  ]
FROM environments e
WHERE NOT EXISTS (
  SELECT 1 FROM resources r WHERE r.environment_id = e.id AND r.prefix = 'iam'
);
```

**File:** `migrations/015_drop_membership_role.up.sql` (new)
```sql
-- (contents from Phase 2.1 above — trigger recreation + ALTER TABLE DROP COLUMN)
```

---

## Phase 4: Frontend

### 4.1 Remove membership role from Add Member dialog

**File:** `frontend/src/pages/entities.tsx`

Lines 245-249 — the `extraConfig` for organizations:
```typescript
// BEFORE:
kind === 'organizations' ? { title: 'Add member', path: '/memberships', fields: [
  { name: 'organization_id', label: 'Organization', type: 'select' as const, selectPath: `${base}/organizations`, selectMap: named },
  { name: 'user_id', label: 'User', type: 'select' as const, selectPath: `${base}/users`, selectMap: named },
  { name: 'role', label: 'Membership role', value: 'member', hint: 'owner, admin, or member' },
] } :

// AFTER:
kind === 'organizations' ? { title: 'Add member', path: '/memberships', fields: [
  { name: 'organization_id', label: 'Organization', type: 'select' as const, selectPath: `${base}/organizations`, selectMap: named },
  { name: 'user_id', label: 'User', type: 'select' as const, selectPath: `${base}/users`, selectMap: named },
] } :
```

### 4.2 Remove role from Members dialog

**File:** `frontend/src/pages/entities.tsx`

In `MembersDialog` (around line 168-192), the `DataTable` shows a "Role" column:
```typescript
// BEFORE:
<DataTable columns={['User', 'Role', 'Status', ...(canWrite ? ['Actions'] : [])]} ...rows={members.map(m => {
  const cells: React.ReactNode[] = [<ID value={m.user_id} />, <span className="capitalize">{m.role}</span>, <Status active={m.active} />]
  ...

// AFTER:
<DataTable columns={['User', 'Status', ...(canWrite ? ['Actions'] : [])]} ...rows={members.map(m => {
  const cells: React.ReactNode[] = [<ID value={m.user_id} />, <Status active={m.active} />]
  ...
```

Also update the `Member` interface (line 20):
```typescript
// BEFORE:
interface Member { user_id: string; role: string; active: boolean }
// AFTER:
interface Member { user_id: string; active: boolean }
```

### 4.3 Mark IAM resource as system in the UI

**File:** `frontend/src/pages/entities.tsx`

In the resource table rows (around line 270), add a visual indicator for the system resource:
```typescript
// In the resources row rendering, after the identity column:
kind === 'resources' ? [
  <div className="space-y-1">
    <p className="font-medium">{row.name}{row.prefix === 'iam' && <span className="ml-2 inline-block rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">System</span>}</p>
    <ID value={row.id} />
  </div>,
  ...
```

Optionally: hide the Delete button for the `iam` resource (check `row.prefix !== 'iam'` before rendering the delete action). Currently resources don't have a delete button, so this is not needed yet.

---

## Phase 5: Frontend Test Updates

**File:** `frontend/src/App.test.tsx`

The test mock at line 24 returns grant data. No changes needed for the grant test since it doesn't test memberships.

If there's a test for the Members dialog that checks the Role column, remove that assertion. Currently there isn't one — the only tests are: deep-link, sidebar toggle, mismatch, viewer, and grant edit.

---

## Verification Checklist

After all changes:

1. `go build ./...` — must pass
2. `go test ./...` — must pass  
3. `go vet ./...` — must pass
4. Run migrations: `go run ./cmd/iamkit migrate`
5. Restart backend
6. `npm run build` — must pass (frontend)
7. `npm test` — must pass (frontend)
8. `npm run lint` — must pass (frontend)
9. **Live verification in browser:**
   - Create a new environment → verify `iam` resource auto-appears in Resources list with `iam` prefix and all `iam:*` scopes
   - Edit the `iam` resource → can add/remove scopes (e.g. add `iam:federation:read`)
   - Open Organizations → "Add member" dialog should NOT show "Membership role" field
   - View members of an org → should NOT show "Role" column
   - Create a role on the `iam` resource → should see `iam:users:read`, `iam:members:write`, etc. as checkboxes
   - Create a grant with `iam:members:write` → user can now add members via the user API
10. Verify existing data wasn't broken — the Invoices API resource and its roles/grants should still work

---

## File Change Summary

| File | Action |
|------|--------|
| `internal/identity/model.go` | Remove `iam`/`management` reserved blocks from both functions |
| `internal/identity/model_test.go` | Update test cases |
| `internal/iam/management/adapters/mgmtpg/control.go` | Auto-create `iam` resource in `CreateEnvironment` |
| `internal/iam/organization/organization.go` | Remove `Role` from Member struct |
| `internal/iam/organization/ports.go` | Remove `Role` from MemberInput |
| `internal/iam/organization/adapters/orgpg/repository.go` | Remove `role` from INSERT and SELECT |
| `internal/iam/organization/adapters/orgpg/structure.go` | Remove `role` from Members query |
| `internal/iam/authentication/token.go` | Remove `Role` from Organization struct |
| `internal/iam/authentication/adapters/authpg/tokens.go` | Fix AddMember to check `iam:members:write` grant; remove `role` from Organizations query |
| `internal/iam/provisioning/adapters/provpg/repository.go` | Remove `role` from membership INSERT |
| `tests/e2e/identity_test.go` | Remove `"role"` from membership test payloads |
| `migrations/014_system_iam_resource.up.sql` | Backfill `iam` resource for existing environments |
| `migrations/015_drop_membership_role.up.sql` | Drop trigger, recreate without role, drop column |
| `frontend/src/pages/entities.tsx` | Remove role from Add Member fields, Members dialog, Member interface; add System badge to iam resource |
