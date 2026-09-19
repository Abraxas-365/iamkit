# Plan: Paginated Response Wrapper + DB-Level Pagination & Filters

## Goal

Two-step refactor:

1. **Response shape change** — replace raw `[]T` + `X-Total-Count` header with a
   structured `{ items, page }` JSON envelope. Pagination still happens in memory.
2. **DB-level pagination & filters** — introduce `httpx.Pagination` struct and
   per-query filter structs. `LIMIT`/`OFFSET`/`WHERE` clauses move into SQL.
   `COUNT(*)` provides the total. The in-memory `NewPaginated` helper becomes a
   thin wrapper for endpoints that haven't migrated yet.

---

## Step 1: Backend — rewrite `internal/httpx/paginate.go`

**File:** `internal/httpx/paginate.go`

Replace the entire file with:

```go
// Package httpx provides small HTTP handler helpers.
package httpx

import "github.com/gofiber/fiber/v2"

// Page carries pagination metadata in API responses.
type Page struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// Paginated is the standard list response envelope.
type Paginated[T any] struct {
	Items []T  `json:"items"`
	Page  Page `json:"page"`
}

// Pagination holds limit/offset parsed from query params.
// Used by repository methods that paginate at the DB level.
type Pagination struct {
	Limit  int
	Offset int
}

// PaginationFromCtx reads ?limit= and ?offset= from the request.
// When limit is 0 a default of 50 is used. Max limit is 200.
func PaginationFromCtx(c *fiber.Ctx) Pagination {
	limit := c.QueryInt("limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := c.QueryInt("offset", 0)
	if offset < 0 {
		offset = 0
	}
	return Pagination{Limit: limit, Offset: offset}
}

// NewPaginated creates a paginated response, slicing items in memory.
// Use for endpoints that haven't migrated to DB-level pagination yet.
// When limit is 0 the full slice (from offset) is returned.
func NewPaginated[T any](c *fiber.Ctx, items []T) Paginated[T] {
	total := len(items)
	limit := c.QueryInt("limit", 0)
	offset := c.QueryInt("offset", 0)
	if offset > len(items) {
		offset = len(items)
	}
	items = items[offset:]
	if limit > 0 && limit < len(items) {
		items = items[:limit]
	}
	if items == nil {
		items = []T{}
	}
	return Paginated[T]{
		Items: items,
		Page:  Page{Total: total, Limit: limit, Offset: offset},
	}
}

// NewPaginatedDB creates a paginated response from pre-sliced DB results.
// total comes from a COUNT(*) query; items are already LIMIT/OFFSET'd.
func NewPaginatedDB[T any](items []T, total int, p Pagination) Paginated[T] {
	if items == nil {
		items = []T{}
	}
	return Paginated[T]{
		Items: items,
		Page:  Page{Total: total, Limit: p.Limit, Offset: p.Offset},
	}
}
```

Key changes vs current file:
- Drop the `X-Total-Count` header — metadata is in the JSON body.
- `Paginate` renamed → `NewPaginated` (returns struct, not slice).
- New `Pagination` struct + `PaginationFromCtx` for DB-level pagination.
- New `NewPaginatedDB` constructor for endpoints that paginate in SQL.

---

## Step 2: Backend — update all 13 in-memory call sites

Every existing call site changes from `httpx.Paginate(c, out)` to
`httpx.NewPaginated(c, out)`. This is a mechanical rename — no logic changes.

| File | Call sites |
|------|-----------|
| `internal/iam/user/adapters/userhttp/handler.go` | line 54 (1) |
| `internal/iam/organization/adapters/orghttp/handler.go` | lines 46, 81 (2) |
| `internal/iam/application/adapters/apphttp/handler.go` | line 41 (1) |
| `internal/iam/authorization/adapters/authzhttp/handler.go` | lines 44, 88 (2) |
| `internal/iam/authorization/adapters/authzhttp/grants.go` | lines 44, 54, 115 (3) |
| `internal/iam/serviceaccount/adapters/saccthttp/handler.go` | line 39 (1) |
| `internal/iam/federation/adapters/fedhttp/handler.go` | line 72 (1) |
| `internal/iam/oauth/adapters/oauthhttp/handler.go` | line 62 (1) |

Each change is identical:
```go
// Before
return c.JSON(httpx.Paginate(c, out))
// After
return c.JSON(httpx.NewPaginated(c, out))
```

**Not changed** (return raw `c.JSON(out)` without any pagination wrapper):
- `internal/iam/management/adapters/mgmthttp/handler.go` — keys, operators,
  projects, environments
- `internal/iam/management/adapters/mgmthttp/activity.go` — sessions,
  audit-events

---

## Step 3: Frontend — update response parsing

### 3a. `frontend/src/lib/api.ts`

Replace the `requestList` function body. Keep the `ListResult<T>` interface
and the `api.list` binding unchanged.

```ts
export async function requestList<T>(path: string, signal?: AbortSignal): Promise<ListResult<T>> {
  const response = await fetch(`/management/v1${path}`, {
    signal, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-IAMKit-Console': '1' },
  })
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') window.dispatchEvent(new Event('session-expired'))
    const body = await response.json().catch(() => null)
    throw new ApiError(response.status, body?.error?.message || response.statusText, body?.error?.code)
  }
  const text = await response.text()
  if (!text) return { data: [], total: 0 }
  const json = JSON.parse(text)
  // Support both new envelope { items, page } and legacy raw arrays
  if (Array.isArray(json)) {
    return { data: json as T[], total: json.length }
  }
  return { data: (json.items ?? []) as T[], total: json.page?.total ?? 0 }
}
```

The `Array.isArray` fallback handles management endpoints that still return
raw `[]T`. Remove once those are wrapped too.

### 3b. `frontend/src/hooks/use-list.ts`

**No changes.** Already consumes `ListResult<T>` from `api.list()`.

### 3c. `frontend/src/components/ui/search-select.tsx`

`SearchSelect` uses `api.get()` (not `api.list()`). After Step 2 the
paginated endpoints return `{ items, page }` instead of `[...]`, which
breaks `SearchSelect` silently.

Change the fetch `useEffect` (around line 31):

```ts
  useEffect(() => {
    const controller = new AbortController()
    api.get<unknown>(path, controller.signal)
      .then(raw => {
        if (!controller.signal.aborted) {
          // Support both paginated envelope { items: [...] } and raw arrays
          const data = Array.isArray(raw) ? raw : ((raw as any)?.items ?? [])
          setOptions(data.map(mapItem))
          setLoading(false)
        }
      })
      .catch(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [path])
```

---

## Step 4: Verify Steps 1-3

```bash
cd /Users/abraxas/Desktop/Proyectos/iam

# Backend compiles
go build ./...

# Tests pass
go test ./internal/... -count=1 -short

# Frontend type-checks
cd frontend && npx tsc --noEmit
```

Restart backend, verify in browser:
1. Any list page (Users, Applications, etc.) loads data correctly
2. `SearchSelect` dropdowns work (e.g. service account creation → resource picker)
3. Pagination controls still work where used

---

## Step 5: DB-level pagination & filters for role-assignments

This is the first endpoint migrated to DB-level. It serves as the pattern
for future endpoints.

### 5a. Add filter struct — `internal/iam/authorization/grant.go`

Add after the existing `RoleAssignmentView` struct (around line 94):

```go
// RoleAssignmentFilter holds optional filters for listing role assignments.
// Empty string fields are ignored (match all).
type RoleAssignmentFilter struct {
	RoleID         string
	OrganizationID string
	UserID         string
	ResourceID     string
	Search         string // free-text match on names/email
}
```

### 5b. Update interfaces

**File:** `internal/iam/authorization/ports.go`

Change `GrantQueries`:
```go
// Before
RoleAssignments(ctx context.Context, environment string) ([]RoleAssignmentView, error)

// After
RoleAssignments(ctx context.Context, environment string, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
```

This adds an import of `"github.com/Abraxas-365/iamkit/internal/httpx"` to
`ports.go`.

Change `Grants` (repository interface):
```go
// Before
RoleAssignments(ctx context.Context, environment string) ([]RoleAssignmentView, error)

// After
RoleAssignments(ctx context.Context, environment string, filter RoleAssignmentFilter, page httpx.Pagination) ([]RoleAssignmentView, int, error)
```

### 5c. Update repository — `internal/iam/authorization/adapters/authzpg/grants.go`

Replace the `RoleAssignments` method (currently lines 109-125).

Add `"github.com/Abraxas-365/iamkit/internal/httpx"` to imports.

```go
func (r *Repository) RoleAssignments(ctx context.Context, environment string, filter authorization.RoleAssignmentFilter, page httpx.Pagination) ([]authorization.RoleAssignmentView, int, error) {
	base := `FROM role_assignments a
		JOIN organizations o ON o.id=a.organization_id
		JOIN users u ON u.id=a.user_id
		JOIN resources res ON res.id=a.resource_id
		JOIN roles ro ON ro.id=a.role_id
		WHERE a.environment_id=$1`
	args := []any{environment}
	n := 1

	if filter.RoleID != "" {
		n++
		base += fmt.Sprintf(" AND a.role_id=$%d", n)
		args = append(args, filter.RoleID)
	}
	if filter.OrganizationID != "" {
		n++
		base += fmt.Sprintf(" AND a.organization_id=$%d", n)
		args = append(args, filter.OrganizationID)
	}
	if filter.UserID != "" {
		n++
		base += fmt.Sprintf(" AND a.user_id=$%d", n)
		args = append(args, filter.UserID)
	}
	if filter.ResourceID != "" {
		n++
		base += fmt.Sprintf(" AND a.resource_id=$%d", n)
		args = append(args, filter.ResourceID)
	}
	if filter.Search != "" {
		n++
		like := "%" + filter.Search + "%"
		base += fmt.Sprintf(" AND (ro.name ILIKE $%d OR o.name ILIKE $%d OR u.name ILIKE $%d OR u.email ILIKE $%d OR res.name ILIKE $%d)", n, n, n, n, n)
		args = append(args, like)
	}

	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT COUNT(*) "+base, args...); err != nil {
		return nil, 0, failure(err)
	}

	query := fmt.Sprintf("SELECT a.organization_id, o.name AS organization_name, a.user_id, u.name AS user_name, u.email AS user_email, a.resource_id, res.name AS resource_name, a.role_id, ro.name AS role_name %s ORDER BY ro.name LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	rows := []authorization.RoleAssignmentView{}
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, 0, failure(err)
	}
	return rows, total, nil
}
```

Add `"fmt"` to the file's imports.

### 5d. Update service — `internal/iam/authorization/authzsvc/grants.go`

Add `"github.com/Abraxas-365/iamkit/internal/httpx"` to imports.

```go
// Before
func (s *Grants) RoleAssignments(ctx context.Context, environment string) ([]authorization.RoleAssignmentView, error) {
	return s.repository.RoleAssignments(ctx, environment)
}

// After
func (s *Grants) RoleAssignments(ctx context.Context, environment string, filter authorization.RoleAssignmentFilter, page httpx.Pagination) ([]authorization.RoleAssignmentView, int, error) {
	return s.repository.RoleAssignments(ctx, environment, filter, page)
}
```

### 5e. Update HTTP handler — `internal/iam/authorization/adapters/authzhttp/grants.go`

Replace the `roleAssignments` method (currently lines 110-116):

```go
func (h *Grants) roleAssignments(c *fiber.Ctx) error {
	filter := authorization.RoleAssignmentFilter{
		RoleID:         c.Query("role_id"),
		OrganizationID: c.Query("organization_id"),
		UserID:         c.Query("user_id"),
		ResourceID:     c.Query("resource_id"),
		Search:         c.Query("search"),
	}
	page := httpx.PaginationFromCtx(c)
	items, total, err := h.queries.RoleAssignments(c.Context(), c.Params("environment"), filter, page)
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginatedDB(items, total, page))
}
```

This endpoint no longer goes through the in-memory `NewPaginated` path — it
uses `NewPaginatedDB` with the `COUNT(*)` total from the DB.

### 5f. Update frontend — `frontend/src/pages/role-assignments.tsx`

Full rewrite. The page now sends filter query params to the backend instead of
filtering client-side.

Key changes:
- `useList` path includes query params: `${base}/role-assignments?role_id=${filters.role}&...&limit=50&offset=${offset}`
- Remove client-side `filtered` computation and the `useMemo` that derives
  dropdown options from `list.data`
- Filter dropdowns need their own data source — load options via separate
  lightweight fetches using `useList`:
  - Roles: `useList` from `${base}/roles`
  - Organizations: `useList` from `${base}/organizations`
  - Users: `useList` from `${base}/users`
  - Resources: `useList` from `${base}/resources`
- `list.total` comes from the API response `page.total` (DB count), not
  `list.data.length`
- Add offset-based pagination controls (Next/Previous buttons, or just
  "Showing X-Y of Z")

```tsx
import { useCallback, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ChevronLeft, ChevronRight, Trash2, X } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, DataTable, ID, PageHeader } from '@/components/library/patterns'

interface RoleAssignment {
  organization_id: string; organization_name: string
  user_id: string; user_name: string; user_email: string
  resource_id: string; resource_name: string
  role_id: string; role_name: string
}
interface Named { id: string; name: string }

interface Filters { role: string; organization: string; user: string; resource: string }
const emptyFilters: Filters = { role: '', organization: '', user: '', resource: '' }
const PAGE_SIZE = 50

export default function RoleAssignmentsPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [search, setSearch] = useState('')
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [offset, setOffset] = useState(0)
  const [removing, setRemoving] = useState<RoleAssignment | null>(null)

  // Build query string for role-assignments endpoint
  const queryParams = useMemo(() => {
    const params = new URLSearchParams()
    if (filters.role) params.set('role_id', filters.role)
    if (filters.organization) params.set('organization_id', filters.organization)
    if (filters.user) params.set('user_id', filters.user)
    if (filters.resource) params.set('resource_id', filters.resource)
    if (search) params.set('search', search)
    params.set('limit', String(PAGE_SIZE))
    params.set('offset', String(offset))
    return params.toString()
  }, [filters, search, offset])

  const list = useList<RoleAssignment>(`${base}/role-assignments?${queryParams}`)

  // Load filter options from existing entity lists
  const roles = useList<Named>(`${base}/roles`)
  const orgs = useList<Named>(`${base}/organizations`)
  const users = useList<Named>(`${base}/users`)
  const resources = useList<Named>(`${base}/resources`)

  const hasFilters = Object.values(filters).some(Boolean) || search !== ''
  const rolesPath = `/projects/${project}/environments/${environment}/roles`

  // Reset offset when filters/search change
  const updateFilter = useCallback((patch: Partial<Filters>) => {
    setFilters(f => ({ ...f, ...patch }))
    setOffset(0)
  }, [])
  const updateSearch = useCallback((value: string) => {
    setSearch(value)
    setOffset(0)
  }, [])

  const showingFrom = list.total === 0 ? 0 : offset + 1
  const showingTo = Math.min(offset + PAGE_SIZE, list.total)

  return <div className="space-y-6">
    <div className="space-y-3">
      <Link to={rolesPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to roles
      </Link>
      <PageHeader
        title="Role assignments"
        description="All role assignments in this environment."
      />
    </div>

    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <Input
          aria-label="Search role assignments"
          className="max-w-sm"
          placeholder="Search assignments…"
          value={search}
          onChange={e => updateSearch(e.target.value)}
        />
        <span className="shrink-0 text-xs text-muted-foreground">
          {list.total === 0 ? '0 assignments' : `${showingFrom}–${showingTo} of ${list.total} assignments`}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <FilterSelect label="Role" value={filters.role} options={roles.data.map(r => [r.id, r.name] as [string, string])} onChange={v => updateFilter({ role: v })} />
        <FilterSelect label="Organization" value={filters.organization} options={orgs.data.map(o => [o.id, o.name] as [string, string])} onChange={v => updateFilter({ organization: v })} />
        <FilterSelect label="User" value={filters.user} options={users.data.map(u => [u.id, u.name] as [string, string])} onChange={v => updateFilter({ user: v })} />
        <FilterSelect label="Resource" value={filters.resource} options={resources.data.map(r => [r.id, r.name] as [string, string])} onChange={v => updateFilter({ resource: v })} />
        {hasFilters && <Button variant="ghost" size="sm" onClick={() => { setFilters(emptyFilters); setSearch(''); setOffset(0) }}><X className="size-3.5" /> Clear</Button>}
      </div>
    </div>

    <DataTable
      columns={['Role', 'Organization', 'User', 'Resource', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rows={list.data.map(a => {
        const cells: React.ReactNode[] = [
          <div className="space-y-1">
            <p className="font-medium">{a.role_name}</p>
            <ID value={a.role_id} />
          </div>,
          <div className="space-y-1">
            <p className="text-sm">{a.organization_name}</p>
            <ID value={a.organization_id} />
          </div>,
          <div className="space-y-1">
            <p className="text-sm">{a.user_name}</p>
            <p className="text-xs text-muted-foreground">{a.user_email}</p>
            <ID value={a.user_id} />
          </div>,
          <div className="space-y-1">
            <p className="text-sm">{a.resource_name}</p>
            <ID value={a.resource_id} />
          </div>,
        ]
        if (canWrite) cells.push(
          <Button variant="ghost" size="icon" aria-label="Unassign" onClick={() => setRemoving(a)}>
            <Trash2 className="size-4" />
          </Button>,
        )
        return cells
      })}
    />

    {/* Pagination controls */}
    {list.total > PAGE_SIZE && (
      <div className="flex items-center justify-end gap-2">
        <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(o => Math.max(0, o - PAGE_SIZE))}>
          <ChevronLeft className="size-4" /> Previous
        </Button>
        <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= list.total} onClick={() => setOffset(o => o + PAGE_SIZE)}>
          Next <ChevronRight className="size-4" />
        </Button>
      </div>
    )}

    {removing && (
      <ConfirmDialog
        title="Unassign role?"
        description={`Remove "${removing.role_name}" from ${removing.user_name || removing.user_id} in ${removing.organization_name || removing.organization_id}.`}
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/role-assignments/${removing.role_id}/${removing.organization_id}/${removing.user_id}`)
          list.reload()
        }}
      />
    )}
  </div>
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: [string, string][]; onChange: (v: string) => void }) {
  return <select
    aria-label={`Filter by ${label}`}
    value={value}
    onChange={e => onChange(e.target.value)}
    className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
  >
    <option value="">All {label.toLowerCase()}s</option>
    {options.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
  </select>
}
```

Key differences from the current file:
- `useList` path includes `?role_id=&organization_id=&...&limit=50&offset=0`
- No more `useMemo` building filter options from role-assignment data
- Filter options come from `useList` on `/roles`, `/organizations`, `/users`,
  `/resources` (separate API calls — these are small entity lists)
- `offset` state + Previous/Next pagination buttons
- `list.total` is the DB `COUNT(*)` total, not `list.data.length`
- `updateFilter` / `updateSearch` reset offset to 0

### 5g. Frontend — debounce search input

The `search` state triggers a re-fetch on every keystroke. Add a debounce
to `useList` path construction. The simplest approach: debounce the `search`
value with a `useEffect` + `setTimeout`:

Add this inside the component before the `queryParams` memo:

```tsx
const [debouncedSearch, setDebouncedSearch] = useState('')
useEffect(() => {
  const id = setTimeout(() => setDebouncedSearch(search), 300)
  return () => clearTimeout(id)
}, [search])
```

Then use `debouncedSearch` instead of `search` in the `queryParams` memo and
in the `hasFilters` check. The `<Input>` still binds to `search` for
immediate visual feedback.

---

## Step 6: Verify everything

```bash
cd /Users/abraxas/Desktop/Proyectos/iam

# Backend compiles
go build ./...

# Tests pass
go test ./internal/... -count=1 -short

# Go vet
go vet ./...

# Frontend type-checks
cd frontend && npx tsc --noEmit
```

Then restart backend and verify in browser:
1. All list pages load data correctly (response shape change)
2. `SearchSelect` dropdowns work (envelope handling)
3. Role assignments page: filters send query params, pagination works,
   Previous/Next buttons appear when > 50 results, search debounces

---

## Complete file manifest

| # | File | Change type |
|---|------|-------------|
| 1 | `internal/httpx/paginate.go` | Full rewrite — add `Pagination`, `PaginationFromCtx`, `NewPaginatedDB` |
| 2 | `internal/iam/user/adapters/userhttp/handler.go` | `Paginate` → `NewPaginated` (1 site) |
| 3 | `internal/iam/organization/adapters/orghttp/handler.go` | `Paginate` → `NewPaginated` (2 sites) |
| 4 | `internal/iam/application/adapters/apphttp/handler.go` | `Paginate` → `NewPaginated` (1 site) |
| 5 | `internal/iam/authorization/adapters/authzhttp/handler.go` | `Paginate` → `NewPaginated` (2 sites) |
| 6 | `internal/iam/authorization/adapters/authzhttp/grants.go` | Rewrite `roleAssignments` handler to use DB pagination + filters; other 2 sites: `Paginate` → `NewPaginated` |
| 7 | `internal/iam/serviceaccount/adapters/saccthttp/handler.go` | `Paginate` → `NewPaginated` (1 site) |
| 8 | `internal/iam/federation/adapters/fedhttp/handler.go` | `Paginate` → `NewPaginated` (1 site) |
| 9 | `internal/iam/oauth/adapters/oauthhttp/handler.go` | `Paginate` → `NewPaginated` (1 site) |
| 10 | `internal/iam/authorization/grant.go` | Add `RoleAssignmentFilter` struct |
| 11 | `internal/iam/authorization/ports.go` | Update `GrantQueries.RoleAssignments` and `Grants.RoleAssignments` signatures — add `filter`, `page` params, return `int` total |
| 12 | `internal/iam/authorization/adapters/authzpg/grants.go` | Rewrite `RoleAssignments` — dynamic WHERE + COUNT(*) + LIMIT/OFFSET |
| 13 | `internal/iam/authorization/authzsvc/grants.go` | Update `RoleAssignments` — pass through filter + page |
| 14 | `frontend/src/lib/api.ts` | Rewrite `requestList` — read `{ items, page }` envelope |
| 15 | `frontend/src/components/ui/search-select.tsx` | Handle envelope in fetch useEffect |
| 16 | `frontend/src/pages/role-assignments.tsx` | Full rewrite — server-side filters + pagination |

## What is NOT changed

- **Other list endpoints** stay in-memory paginated via `NewPaginated` — migrate
  them to DB-level one at a time as needed using the same pattern (add filter
  struct, update interface/repo/service/handler).
- **Management endpoints** (keys, operators, projects, environments, sessions,
  audit) still return raw `[]T` — frontend handles via `Array.isArray` fallback.
- **`use-list.ts`** — untouched, consumes `ListResult<T>` from `api.list()`.
- **`request()` / `api.get()`** — untouched.
- **DB indexes** — not added in this plan. If `role_assignments` queries become
  slow at scale, add composite indexes on `(environment_id, role_id)`,
  `(environment_id, organization_id)`, etc. as a follow-up.
