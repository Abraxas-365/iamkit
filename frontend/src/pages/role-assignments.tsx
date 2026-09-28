import { useCallback, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Tags, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { BackLink, ConfirmDialog, DataTable, EmptyState, EntityRef, PageHeader } from '@/components/library/patterns'
import { RowActions } from '@/components/ui/menu'

interface RoleAssignment {
  organization_id: string; organization_name: string
  user_id: string; user_name: string; user_email: string
  resource_id: string; resource_name: string
  role_id: string; role_name: string
}
interface Named { id: string; name: string; active?: boolean }

interface Filters { role: string; organization: string; user: string; resource: string }
const emptyFilters: Filters = { role: '', organization: '', user: '', resource: '' }

export default function RoleAssignmentsPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [removing, setRemoving] = useState<RoleAssignment | null>(null)

  const extraParams = useMemo(() => {
    const p: Record<string, string> = {}
    if (filters.role) p.role_id = filters.role
    if (filters.organization) p.organization_id = filters.organization
    if (filters.user) p.user_id = filters.user
    if (filters.resource) p.resource_id = filters.resource
    return p
  }, [filters])

  const list = usePaginatedList<RoleAssignment>(`${base}/role-assignments`, { extraParams })

  // Filter dropdown options — use high limit to load all for small enumerable sets
  const roles = usePaginatedList<Named>(`${base}/roles`, { limit: 200 })
  const orgs = usePaginatedList<Named>(`${base}/organizations`, { limit: 200 })
  const users = usePaginatedList<Named>(`${base}/users`, { limit: 200 })
  const resources = usePaginatedList<Named>(`${base}/resources`, { limit: 200 })

  const hasFilters = Object.values(filters).some(Boolean) || list.rawSearch !== ''
  const envBase = `/projects/${project}/environments/${environment}`
  const rolesPath = `${envBase}/roles`

  const updateFilter = useCallback((patch: Partial<Filters>) => {
    setFilters(f => ({ ...f, ...patch }))
  }, [])

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={rolesPath}>Roles</BackLink>
      <PageHeader
        title="Role assignments"
        description="Who holds which role, in which organization. Roles granted through groups are shown on each organization's Groups tab."
      />
    </div>

    <div className="space-y-3">
      <PaginationBar state={list} noun="assignments" />

      <div className="flex flex-wrap items-center gap-2">
        <FilterSelect label="Role" value={filters.role} options={roles.data.map(r => [r.id, r.name] as [string, string])} onChange={v => updateFilter({ role: v })} />
        <FilterSelect label="Organization" value={filters.organization} options={orgs.data.map(o => [o.id, o.name] as [string, string])} onChange={v => updateFilter({ organization: v })} />
        <FilterSelect label="User" value={filters.user} options={users.data.map(u => [u.id, u.name + (u.active === false ? ' (inactive)' : '')] as [string, string])} onChange={v => updateFilter({ user: v })} />
        <FilterSelect label="Resource" value={filters.resource} options={resources.data.map(r => [r.id, r.name] as [string, string])} onChange={v => updateFilter({ resource: v })} />
        {hasFilters && <Button variant="ghost" size="sm" onClick={() => { setFilters(emptyFilters); list.setSearch('') }}><X className="size-3.5" /> Clear</Button>}
      </div>
    </div>

    <DataTable
      columns={['User', 'Role', { header: 'Organization', hideBelow: 'md' }, ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={hasFilters ? <EmptyState title="No assignments match these filters" /> : <EmptyState icon={<Tags />} title="No roles assigned yet" description="Assign roles from a user's page, or with “Assign role” on the Roles page." />}
      rows={list.data.map(a => [
        <EntityRef name={a.user_name || a.user_email} id={a.user_id} to={`${envBase}/users/${a.user_id}`} secondary={a.user_name ? a.user_email : undefined} />,
        <span className="block"><span className="font-medium">{a.role_name}</span><span className="block text-xs text-muted-foreground">{a.resource_name}</span></span>,
        <Link to={`${envBase}/organizations/${a.organization_id}`} className="text-sm hover:text-primary hover:underline">{a.organization_name}</Link>,
        ...(canWrite ? [<RowActions label={`Actions for ${a.user_name} as ${a.role_name}`} actions={[{ label: 'Remove role', icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(a) }]} />] : []),
      ])}
    />

    {removing && (
      <ConfirmDialog
        title={`Remove role ${removing.role_name}?`}
        description={`${removing.user_name || removing.user_email} loses this role in ${removing.organization_name} at their next token. Roles from groups are not affected.`}
        confirmLabel="Remove role"
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/role-assignments/${removing.role_id}/${removing.organization_id}/${removing.user_id}`)
          toast.success('Role removed')
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
