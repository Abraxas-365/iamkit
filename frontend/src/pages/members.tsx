import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { KeyRound, MailPlus, ShieldCheck, UserMinus, UserPlus, Users, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { ConfirmDialog, DataTable, EmptyState, EntityRef, ErrorState, FormDialog, Status } from '@/components/library/patterns'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { RowActions } from '@/components/ui/menu'
import { useOrganization } from './organization-layout'

interface Member {
  user_id: string; user_name: string; user_email: string; active: boolean
  manager_id: string | null; manager_name: string | null
  sso_bypass?: boolean
}

const memberOption = (item: Record<string, unknown>) => ({
  id: String(item.user_id ?? item.id),
  label: String(item.user_name ?? item.name ?? item.id),
  inactive: item.active === false,
})

const userOption = (item: Record<string, unknown>) => ({ id: String(item.id), label: item.email ? `${item.name} (${item.email})` : String(item.name ?? item.id), inactive: item.active === false })

export default function MembersPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/members`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [removing, setRemoving] = useState<Member | null>(null)
  const [inspecting, setInspecting] = useState<Member | null>(null)
  const [settingManager, setSettingManager] = useState<Member | null>(null)
  const [bypassing, setBypassing] = useState<Member | null>(null)
  const [adding, setAdding] = useState(false)
  const { org } = useOrganization()
  const orgName = org.name
  const [managerFilter, setManagerFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const extraParams = useMemo(() => {
    const p: Record<string, string> = {}
    if (managerFilter) p.manager_id = managerFilter
    if (statusFilter) p.active = statusFilter
    return p
  }, [managerFilter, statusFilter])

  const list = usePaginatedList<Member>(path, { extraParams })

  const envBase = `/projects/${project}/environments/${environment}`
  const orgsPath = `${envBase}/organizations`
  const hasFilters = !!managerFilter || !!statusFilter

  function clearFilters() { setManagerFilter(''); setStatusFilter('') }

  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold">Members of {org.name}</h2>
        <p className="text-sm text-muted-foreground">People who can sign in to this organization.</p>
      </div>
      {canWrite && <div className="flex flex-wrap gap-2">
        <Link to={`${orgsPath}/${orgId}/invitations`} className={buttonVariants({ variant: 'outline' })}><MailPlus className="size-4" /> Invite by email</Link>
        <Button onClick={() => setAdding(true)}><UserPlus /> Add existing user</Button>
      </div>}
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
      columns={['User', { header: 'Manager', hideBelow: 'md' }, 'Status', 'Actions']}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={<EmptyState icon={<Users />} title={hasFilters ? 'No members match these filters' : 'No members yet'} description={hasFilters ? undefined : `Invite people by email, add an existing user, or connect ${orgName}'s directory with SCIM.`} />}
      rows={list.data.map(m => [
        <EntityRef name={m.user_name} id={m.user_id} to={`${envBase}/users/${m.user_id}`} secondary={m.user_email} />,
        m.manager_name
          ? <button type="button" className="text-left text-sm text-primary hover:underline" title="Show this manager's reports" onClick={() => setManagerFilter(m.manager_id!)}>{m.manager_name}</button>
          : <span className="text-xs text-muted-foreground">—</span>,
        <div className="flex flex-wrap items-center gap-1">
          <Status active={m.active} />
          {m.sso_bypass && <Badge variant="outline" title="May sign in with a password even when SSO is enforced">SSO bypass</Badge>}
        </div>,
        <RowActions label={`Actions for ${m.user_name}`} actions={[
          { label: 'View access', icon: <ShieldCheck />, onSelect: () => setInspecting(m) },
          ...(canWrite && m.active ? [
            { label: 'Set manager', icon: <Users />, onSelect: () => setSettingManager(m) },
            { label: m.sso_bypass ? 'Revoke SSO bypass' : 'Allow password sign-in (SSO bypass)', icon: <KeyRound />, onSelect: () => setBypassing(m) },
            { label: 'Remove from organization', icon: <UserMinus />, destructive: true, onSelect: () => setRemoving(m) },
          ] : []),
        ]} />,
      ])}
    />

    {adding && <FormDialog title={`Add a user to ${orgName}`} description="The user can sign in to this organization right away. Give them roles or grants afterwards." submitLabel="Add member" success="Member added" fields={[
      { name: 'user_id', label: 'User', type: 'select', selectPath: `${base}/users`, selectMap: userOption },
    ]} onClose={() => setAdding(false)} submit={async values => { await api.post(`${base}/memberships`, { organization_id: orgId, user_id: values.user_id }); list.reload() }} />}

    {inspecting && <MemberAccessDialog
      member={inspecting}
      base={base}
      orgId={orgId!}
      groupsPath={`${orgsPath}/${orgId}/groups`}
      onClose={() => setInspecting(null)}
    />}

    {removing && (
      <ConfirmDialog
        title={`Remove ${removing.user_name || 'member'} from ${orgName}?`}
        description={`${removing.user_name || removing.user_id} can no longer sign in to ${orgName}. Their user account is kept.`}
        confirmLabel="Remove member"
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/organizations/${orgId}/members/${removing.user_id}`)
          toast.success('Member removed')
          list.reload()
        }}
      />
    )}

    {bypassing && (
      <ConfirmDialog
        title={`${bypassing.sso_bypass ? 'Revoke' : 'Grant'} SSO bypass for ${bypassing.user_name || 'this member'}?`}
        confirmLabel={bypassing.sso_bypass ? 'Revoke bypass' : 'Grant bypass'}
        description={bypassing.sso_bypass
          ? `${bypassing.user_name || bypassing.user_id} will have to sign in through SSO when it is enforced.`
          : `${bypassing.user_name || bypassing.user_id} will be able to sign in with a password even when SSO is enforced. Use for break-glass administrators only.`}
        onClose={() => setBypassing(null)}
        confirm={async () => {
          await api.patch(`${base}/organizations/${orgId}/members/${bypassing.user_id}`, { sso_bypass: !bypassing.sso_bypass })
          toast.success(bypassing.sso_bypass ? 'SSO bypass revoked' : 'SSO bypass granted')
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

interface EffectiveRole {
  role_id: string; role_name: string; resource_id: string; resource_name: string
  source: 'direct' | 'group'; group_id?: string; group_name?: string
}
interface MemberGroup { id: string; name: string; connection_id: string | null }

/** Shows why a member holds each role: directly or through a group. */
function MemberAccessDialog({ member, base, orgId, groupsPath, onClose }: {
  member: Member; base: string; orgId: string; groupsPath: string; onClose: () => void
}) {
  const [roles, setRoles] = useState<EffectiveRole[] | null>(null)
  const [groups, setGroups] = useState<MemberGroup[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    const q = new URLSearchParams({ organization_id: orgId, user_id: member.user_id })
    Promise.all([
      api.list<EffectiveRole>(`${base}/effective-roles?${q}`, controller.signal),
      api.list<MemberGroup>(`${base}/organizations/${orgId}/members/${member.user_id}/groups?limit=100`, controller.signal),
    ]).then(([r, g]) => { setRoles(r.data); setGroups(g.data) })
      .catch(e => { if (!controller.signal.aborted) setError(message(e)) })
    return () => controller.abort()
  }, [base, orgId, member.user_id])

  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent className="sm:max-w-lg">
      <DialogTitle className="text-base font-semibold">Access of {member.user_name}</DialogTitle>
      <DialogDescription className="text-muted-foreground">
        Effective roles in this organization: direct assignments plus roles inherited from groups. Grants are not shown.
      </DialogDescription>
      {error ? <ErrorState error={error} /> : roles === null ? <p role="status" className="text-sm text-muted-foreground">Loading…</p> : <div className="space-y-4">
        <div className="space-y-2">
          <h3 className="text-sm font-medium">Roles</h3>
          {roles.length === 0 ? <p className="text-sm text-muted-foreground">No roles.</p> : <ul className="divide-y rounded-lg border">
            {roles.map(r => <li key={`${r.role_id}:${r.source}:${r.group_id ?? ''}`} className="flex items-center justify-between gap-3 px-3 py-2">
              <div className="min-w-0">
                <p className="truncate font-medium">{r.role_name}</p>
                <p className="truncate text-xs text-muted-foreground">{r.resource_name}</p>
              </div>
              {r.source === 'group'
                ? <Link to={`${groupsPath}/${r.group_id}`} className="shrink-0"><Badge variant="secondary" className="bg-primary/10 text-primary">via {r.group_name}</Badge></Link>
                : <Badge variant="secondary" className="shrink-0">Direct</Badge>}
            </li>)}
          </ul>}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-medium">Groups</h3>
          {groups.length === 0 ? <p className="text-sm text-muted-foreground">Not in any group.</p> : <div className="flex flex-wrap gap-2">
            {groups.map(g => <Link key={g.id} to={`${groupsPath}/${g.id}`}><Badge variant="outline">{g.name}{g.connection_id ? ' · Directory' : ''}</Badge></Link>)}
          </div>}
        </div>
      </div>}
    </DialogContent>
  </Dialog>
}
