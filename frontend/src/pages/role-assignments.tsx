import { useCallback, useEffect, useMemo, useState } from 'react'
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
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [offset, setOffset] = useState(0)
  const [removing, setRemoving] = useState<RoleAssignment | null>(null)

  useEffect(() => {
    const id = setTimeout(() => setDebouncedSearch(search), 300)
    return () => clearTimeout(id)
  }, [search])

  // Build query string for role-assignments endpoint
  const queryParams = useMemo(() => {
    const params = new URLSearchParams()
    if (filters.role) params.set('role_id', filters.role)
    if (filters.organization) params.set('organization_id', filters.organization)
    if (filters.user) params.set('user_id', filters.user)
    if (filters.resource) params.set('resource_id', filters.resource)
    if (debouncedSearch) params.set('search', debouncedSearch)
    params.set('limit', String(PAGE_SIZE))
    params.set('offset', String(offset))
    return params.toString()
  }, [filters, debouncedSearch, offset])

  const list = useList<RoleAssignment>(`${base}/role-assignments?${queryParams}`)

  // Load filter options from existing entity lists (independent of the paginated result set)
  const roles = useList<Named>(`${base}/roles`)
  const orgs = useList<Named>(`${base}/organizations`)
  const users = useList<Named>(`${base}/users`)
  const resources = useList<Named>(`${base}/resources`)

  const hasFilters = Object.values(filters).some(Boolean) || search !== ''
  const rolesPath = `/projects/${project}/environments/${environment}/roles`

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
