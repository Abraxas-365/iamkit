import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ShieldCheck, Tags, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { BackLink, ConfirmDialog, DataTable, EmptyState, EntityRef, PageHeader } from '@/components/library/patterns'
import { AssignRoleDialog, type AssignTarget } from '@/components/library/assign-role'
import { RowActions } from '@/components/ui/menu'

interface RoleAssignment {
  organization_id: string; organization_name: string
  user_id: string; user_name: string; user_email: string
  resource_id: string; resource_name: string
  role_id: string; role_name: string
}
interface GroupRoleAssignment {
  organization_id: string; organization_name: string
  group_id: string; group_name: string
  resource_id: string; resource_name: string
  role_id: string; role_name: string
}
interface Named { id: string; name: string; active?: boolean }

interface Filters { role: string; organization: string; user: string; resource: string }
const emptyFilters: Filters = { role: '', organization: '', user: '', resource: '' }

/** RoleAssignmentsPage lists who holds which role: users directly, or every
 * member of a group through the group (tab chosen by `?type=groups`). */
export default function RoleAssignmentsPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const envBase = `/projects/${project}/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [params, setParams] = useSearchParams()
  const type: AssignTarget = params.get('type') === 'groups' ? 'group' : 'user'
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [assigning, setAssigning] = useState(false)
  const [version, setVersion] = useState(0)

  const show = (next: AssignTarget) => setParams(p => { if (next === 'group') p.set('type', 'groups'); else p.delete('type'); return p }, { replace: true })
  const updateFilter = useCallback((patch: Partial<Filters>) => setFilters(f => ({ ...f, ...patch })), [])

  // Filter options — small enumerable sets, loaded once.
  const roles = usePaginatedList<Named>(`${base}/roles`, { limit: 100 })
  const orgs = usePaginatedList<Named>(`${base}/organizations`, { limit: 100 })
  const resources = usePaginatedList<Named>(`${base}/resources`, { limit: 100 })

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={`${envBase}/roles`}>Roles</BackLink>
      <PageHeader
        title="Role assignments"
        description="Who holds which role, in which organization: users directly, or every member of a group through the group."
        actions={canWrite && <Button onClick={() => setAssigning(true)}><ShieldCheck /> Assign role</Button>}
      />
    </div>

    <div role="tablist" aria-label="Assigned to" className="inline-flex rounded-lg border p-0.5">
      {tabs.map(([value, label], i) => <button
        key={value} id={`assignments-tab-${value}`} type="button" role="tab" aria-selected={type === value} aria-controls="assignments-panel"
        tabIndex={type === value ? 0 : -1}
        className={cn('h-7 rounded-md px-3 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50', type === value ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground')}
        onClick={() => show(value)}
        onKeyDown={e => {
          const step = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key]
          if (step === undefined) return
          e.preventDefault()
          const [next] = tabs[(i + step + tabs.length) % tabs.length]
          show(next)
          document.getElementById(`assignments-tab-${next}`)?.focus()
        }}
      >{label}</button>)}
    </div>

    <div className="flex flex-wrap items-center gap-2">
      <FilterSelect label="Role" value={filters.role} options={roles.data.map(r => [r.id, r.name])} onChange={v => updateFilter({ role: v })} />
      <FilterSelect label="Organization" value={filters.organization} options={orgs.data.map(o => [o.id, o.name])} onChange={v => updateFilter({ organization: v })} />
      <FilterSelect label="Resource" value={filters.resource} options={resources.data.map(r => [r.id, r.name])} onChange={v => updateFilter({ resource: v })} />
      {type === 'user' && <UserFilter base={base} value={filters.user} onChange={v => updateFilter({ user: v })} />}
    </div>

    <div id="assignments-panel" role="tabpanel" aria-labelledby={`assignments-tab-${type}`}>
      {type === 'user'
        ? <UserAssignments version={version} base={base} envBase={envBase} canWrite={canWrite} filters={filters} clear={() => setFilters(emptyFilters)} />
        : <GroupAssignments version={version} base={base} envBase={envBase} canWrite={canWrite} filters={filters} clear={() => setFilters(emptyFilters)} />}
    </div>

    {assigning && <AssignRoleDialog base={base} target={type} onClose={() => setAssigning(false)} onAssigned={t => { show(t); setVersion(v => v + 1) }} />}
  </div>
}

const tabs = [['user', 'Users'], ['group', 'Groups']] as const

/** UserFilter narrows by one user, searched on the server (any number of users). */
function UserFilter({ base, value, onChange }: { base: string; value: string; onChange: (v: string) => void }) {
  // Clearing remounts the combobox so it forgets its selection.
  const [reset, setReset] = useState(0)
  const cleared = useRef(value)
  useEffect(() => { if (!value && cleared.current) setReset(r => r + 1); cleared.current = value }, [value])
  return <div className="flex items-center gap-1">
    <label htmlFor="filter-user" className="sr-only">Filter by user</label>
    <div className="w-56"><SearchSelect key={reset} id="filter-user" name="user_filter" path={`${base}/users`} placeholder="All users" mapItem={user} onChange={onChange} /></div>
    {value && <Button variant="ghost" size="icon" className="size-7" aria-label="Clear user filter" onClick={() => onChange('')}><X className="size-3.5" /></Button>}
  </div>
}

const user = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email), inactive: item.active === false })

/** useReloadOn reloads list whenever version changes after mount, keeping its
 * search and page (a remount would reset them). */
function useReloadOn(version: number, reload: () => void) {
  const first = useRef(version)
  useEffect(() => { if (version !== first.current) reload() }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
}

function UserAssignments({ version, base, envBase, canWrite, filters, clear }: { version: number; base: string; envBase: string; canWrite: boolean; filters: Filters; clear: () => void }) {
  const [removing, setRemoving] = useState<RoleAssignment | null>(null)
  const extraParams = useMemo(() => ({ role_id: filters.role, organization_id: filters.organization, user_id: filters.user, resource_id: filters.resource }), [filters])
  const list = usePaginatedList<RoleAssignment>(`${base}/role-assignments`, { extraParams })
  useReloadOn(version, list.reload)
  const filtered = Object.values(filters).some(Boolean) || list.rawSearch !== ''

  return <div className="space-y-3">
    <Toolbar list={list} filtered={filtered} clear={() => { clear(); list.setSearch('') }} placeholder="Search users, roles, organizations…" />
    <DataTable
      columns={['User', 'Role', { header: 'Organization', hideBelow: 'md' }, ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={filtered ? <EmptyState title="No assignments match these filters" /> : <EmptyState icon={<Tags />} title="No roles assigned to users yet" description="Assign roles here, from a user's page, or to a whole group on the Groups tab." />}
      rows={list.data.map(a => [
        <EntityRef name={a.user_name || a.user_email} id={a.user_id} to={`${envBase}/users/${a.user_id}`} secondary={a.user_name ? a.user_email : undefined} />,
        <RoleCell name={a.role_name} resource={a.resource_name} />,
        <Link to={`${envBase}/organizations/${a.organization_id}`} className="text-sm hover:text-primary hover:underline">{a.organization_name}</Link>,
        ...(canWrite ? [<RowActions label={`Actions for ${a.user_name} as ${a.role_name}`} actions={[{ label: 'Remove role', icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(a) }]} />] : []),
      ])}
    />
    {removing && <ConfirmDialog
      title={`Remove role ${removing.role_name}?`}
      description={`${removing.user_name || removing.user_email} loses this role in ${removing.organization_name} at their next token. Roles from groups are not affected.`}
      confirmLabel="Remove role"
      onClose={() => setRemoving(null)}
      confirm={async () => {
        await api.delete(`${base}/role-assignments/${removing.role_id}/${removing.organization_id}/${removing.user_id}`)
        toast.success('Role removed')
        list.reload()
      }}
    />}
  </div>
}

function GroupAssignments({ version, base, envBase, canWrite, filters, clear }: { version: number; base: string; envBase: string; canWrite: boolean; filters: Filters; clear: () => void }) {
  const [removing, setRemoving] = useState<GroupRoleAssignment | null>(null)
  const extraParams = useMemo(() => ({ role_id: filters.role, organization_id: filters.organization, resource_id: filters.resource }), [filters])
  const list = usePaginatedList<GroupRoleAssignment>(`${base}/group-role-assignments`, { extraParams })
  useReloadOn(version, list.reload)
  const filtered = !!(filters.role || filters.organization || filters.resource) || list.rawSearch !== ''
  const groupPath = (a: GroupRoleAssignment) => `${envBase}/organizations/${a.organization_id}/groups/${a.group_id}`

  return <div className="space-y-3">
    <Toolbar list={list} filtered={filtered} clear={() => { clear(); list.setSearch('') }} placeholder="Search groups, roles, organizations…" />
    <DataTable
      columns={['Group', 'Role', { header: 'Organization', hideBelow: 'md' }, ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={filtered ? <EmptyState title="No assignments match these filters" /> : <EmptyState icon={<Tags />} title="No roles assigned to groups yet" description="Every member of a group holds the group's roles. Create groups on an organization's Groups tab." />}
      rows={list.data.map(a => [
        <EntityRef name={a.group_name} id={a.group_id} to={groupPath(a)} />,
        <RoleCell name={a.role_name} resource={a.resource_name} />,
        <Link to={`${envBase}/organizations/${a.organization_id}`} className="text-sm hover:text-primary hover:underline">{a.organization_name}</Link>,
        ...(canWrite ? [<RowActions label={`Actions for ${a.group_name} as ${a.role_name}`} actions={[{ label: 'Unassign role', icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(a) }]} />] : []),
      ])}
    />
    {removing && <ConfirmDialog
      title={`Unassign ${removing.role_name} from ${removing.group_name}?`}
      description={`Members of ${removing.group_name} lose this role in ${removing.organization_name} at their next token, unless they hold it directly or through another group.`}
      confirmLabel="Unassign"
      onClose={() => setRemoving(null)}
      confirm={async () => {
        await api.delete(`${base}/group-role-assignments/${removing.role_id}/${removing.organization_id}/${removing.group_id}`)
        toast.success('Role unassigned')
        list.reload()
      }}
    />}
  </div>
}

function RoleCell({ name, resource }: { name: string; resource: string }) {
  return <span className="block"><span className="font-medium">{name}</span><span className="block text-xs text-muted-foreground">{resource}</span></span>
}

function Toolbar({ list, filtered, clear, placeholder }: { list: Parameters<typeof PaginationBar>[0]['state']; filtered: boolean; clear: () => void; placeholder: string }) {
  return <div className="flex flex-wrap items-center gap-2">
    <div className="min-w-0 flex-1"><PaginationBar state={list} noun="assignments" placeholder={placeholder} /></div>
    {filtered && <Button variant="ghost" size="sm" onClick={clear}><X className="size-3.5" /> Clear filters</Button>}
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
