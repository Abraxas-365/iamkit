import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, UserMinus, Users, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { ConfirmDialog, DataTable, ID, PageHeader, Status } from '@/components/library/patterns'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'

interface Member {
  user_id: string; user_name: string; user_email: string; active: boolean
  manager_id: string | null; manager_name: string | null
}

const memberOption = (item: Record<string, unknown>) => ({
  id: String(item.user_id ?? item.id),
  label: String(item.user_name ?? item.name ?? item.id),
  inactive: item.active === false,
})

export default function MembersPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/members`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [removing, setRemoving] = useState<Member | null>(null)
  const [settingManager, setSettingManager] = useState<Member | null>(null)
  const [orgName, setOrgName] = useState('')
  const [managerFilter, setManagerFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const extraParams = useMemo(() => {
    const p: Record<string, string> = {}
    if (managerFilter) p.manager_id = managerFilter
    if (statusFilter) p.active = statusFilter
    return p
  }, [managerFilter, statusFilter])

  const list = usePaginatedList<Member>(path, { extraParams })

  useEffect(() => {
    if (!environment || !orgId) return
    api.get<{ id: string; name: string }>(`${base}/organizations/${orgId}`)
      .then(org => setOrgName(org.name))
      .catch(() => {})
  }, [environment, orgId, base])

  const orgsPath = `/projects/${project}/environments/${environment}/organizations`
  const hasFilters = !!managerFilter || !!statusFilter

  function clearFilters() { setManagerFilter(''); setStatusFilter('') }

  return <div className="space-y-6">
    <div className="space-y-3">
      <Link to={orgsPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to organizations
      </Link>
      <PageHeader
        title={orgName ? `Members of ${orgName}` : 'Members'}
        description={orgId}
      />
    </div>

    <PaginationBar state={list} noun="members" />

    <div className="flex flex-wrap items-center gap-2">
      <div className="w-64">
        <SearchSelect
          key={managerFilter || '__empty__'}
          name="manager_filter"
          path={path}
          mapItem={memberOption}
          defaultValue={managerFilter}
          placeholder="Filter by manager…"
          onChange={v => setManagerFilter(v)}
        />
      </div>
      <select
        aria-label="Filter by status"
        value={statusFilter}
        onChange={e => setStatusFilter(e.target.value)}
        className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
      >
        <option value="">All statuses</option>
        <option value="true">Active</option>
        <option value="false">Inactive</option>
      </select>
      {hasFilters && <Button variant="ghost" size="sm" onClick={clearFilters}><X className="size-3.5" /> Clear</Button>}
    </div>

    <DataTable
      columns={['User', 'Email', 'Manager', 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rows={list.data.map(m => {
        const cells: React.ReactNode[] = [
          <div className="space-y-1">
            <p className="font-medium">{m.user_name}</p>
            <ID value={m.user_id} />
          </div>,
          <span className="text-sm">{m.user_email}</span>,
          m.manager_name
            ? <button type="button" className="text-left text-sm text-primary hover:underline" onClick={() => setManagerFilter(m.manager_id!)}>{m.manager_name}</button>
            : <span className="text-xs text-muted-foreground">—</span>,
          <Status active={m.active} />,
        ]
        if (canWrite) cells.push(
          <div className="flex items-center gap-1">
            {m.active && <Button variant="ghost" size="icon" aria-label={`Set manager for ${m.user_name}`} onClick={() => setSettingManager(m)}>
              <Users className="size-4" />
            </Button>}
            {m.active && <Button variant="ghost" size="icon" aria-label={`Remove ${m.user_name}`} onClick={() => setRemoving(m)}>
              <UserMinus className="size-4" />
            </Button>}
          </div>,
        )
        return cells
      })}
    />

    {removing && (
      <ConfirmDialog
        title="Remove member?"
        description={`${removing.user_name || removing.user_id} will be deactivated in ${orgName || 'this organization'}.`}
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/organizations/${orgId}/members/${removing.user_id}`)
          list.reload()
        }}
      />
    )}

    {settingManager && (
      <SetManagerDialog
        member={settingManager}
        membersPath={path}
        profilePath={`${base}/organizations/${orgId}/members/${settingManager.user_id}/profile`}
        onClose={() => setSettingManager(null)}
        onSaved={() => { setSettingManager(null); list.reload() }}
      />
    )}
  </div>
}

function SetManagerDialog({ member, membersPath, profilePath, onClose, onSaved }: {
  member: Member
  membersPath: string
  profilePath: string
  onClose: () => void
  onSaved: () => void
}) {
  const [managerId, setManagerId] = useState(member.manager_id ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">Set manager</DialogTitle>
      <DialogDescription className="text-muted-foreground">
        Choose a manager for <strong>{member.user_name}</strong> in this organization. Leave empty to remove the current manager.
      </DialogDescription>
      <div className="space-y-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">Manager</label>
          <SearchSelect
            name="manager_id"
            path={membersPath}
            mapItem={memberOption}
            defaultValue={managerId}
            disabled={busy}
            placeholder="Search members…"
            onChange={setManagerId}
          />
          {managerId && <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => setManagerId('')}>
            Clear manager
          </button>}
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button disabled={busy} onClick={async () => {
            setBusy(true); setError('')
            try {
              await api.put(profilePath, {
                manager_id: managerId || null,
              })
              toast.success('Manager updated')
              onSaved()
            } catch (e) { setError(message(e)) } finally { setBusy(false) }
          }}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
}
