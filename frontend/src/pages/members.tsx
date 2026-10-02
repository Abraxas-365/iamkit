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
import { rich, t } from '@/lib/i18n'

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
        <h2 className="text-lg font-semibold">{t('Members of {{name}}', { name: org.name })}</h2>
        <p className="text-sm text-muted-foreground">{t('People who can sign in to this organization.')}</p>
      </div>
      {canWrite && <div className="flex flex-wrap gap-2">
        <Link to={`${orgsPath}/${orgId}/invitations`} className={buttonVariants({ variant: 'outline' })}><MailPlus className="size-4" /> {t('Invite by email')}</Link>
        <Button onClick={() => setAdding(true)}><UserPlus /> {t('Add existing user')}</Button>
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
          placeholder={t('Filter by manager…')}
          onChange={v => setManagerFilter(v)}
        />
      </div>
      <select
        aria-label={t('Filter by status')}
        value={statusFilter}
        onChange={e => setStatusFilter(e.target.value)}
        className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
      >
        <option value="">{t('All statuses')}</option>
        <option value="true">{t('Active')}</option>
        <option value="false">{t('Inactive')}</option>
      </select>
      {hasFilters && <Button variant="ghost" size="sm" onClick={clearFilters}><X className="size-3.5" /> {t('Clear')}</Button>}
    </div>

    <DataTable
      columns={[t('User'), { header: t('Manager'), hideBelow: 'md' }, t('Status'), t('Actions')]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={<EmptyState icon={<Users />} title={hasFilters ? t('No members match these filters') : t('No members yet')} description={hasFilters ? undefined : t('Invite people by email, add an existing user, or connect {{orgName}}\'s directory with SCIM.', { orgName })} />}
      rows={list.data.map(m => [
        <EntityRef name={m.user_name} id={m.user_id} to={`${envBase}/users/${m.user_id}`} secondary={m.user_email} />,
        m.manager_name
          ? <button type="button" className="text-left text-sm text-primary hover:underline" title={t('Show this manager\'s reports')} onClick={() => setManagerFilter(m.manager_id!)}>{m.manager_name}</button>
          : <span className="text-xs text-muted-foreground">—</span>,
        <div className="flex flex-wrap items-center gap-1">
          <Status active={m.active} />
          {m.sso_bypass && <Badge variant="outline" title={t('May sign in with a password even when SSO is enforced')}>{t('SSO bypass')}</Badge>}
        </div>,
        <RowActions label={t('Actions for {{user_name}}', { user_name: m.user_name })} actions={[
          { label: t('View access'), icon: <ShieldCheck />, onSelect: () => setInspecting(m) },
          ...(canWrite && m.active ? [
            { label: t('Set manager'), icon: <Users />, onSelect: () => setSettingManager(m) },
            { label: m.sso_bypass ? t('Revoke SSO bypass') : t('Allow password sign-in (SSO bypass)'), icon: <KeyRound />, onSelect: () => setBypassing(m) },
            { label: t('Remove from organization'), icon: <UserMinus />, destructive: true, onSelect: () => setRemoving(m) },
          ] : []),
        ]} />,
      ])}
    />

    {adding && <FormDialog title={t('Add a user to {{orgName}}', { orgName })} description={t('The user can sign in to this organization right away. Give them roles or grants afterwards.')} submitLabel={t('Add member')} success={t('Member added')} fields={[
      { name: 'user_id', label: t('User'), type: 'select', selectPath: `${base}/users`, selectMap: userOption },
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
        title={t('Remove {{member}} from {{organization}}?', { member: removing.user_name || t('member'), organization: orgName })}
        description={t('{{value}} can no longer sign in to {{orgName}}. Their user account is kept.', { value: removing.user_name || removing.user_id, orgName })}
        confirmLabel={t('Remove member')}
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/organizations/${orgId}/members/${removing.user_id}`)
          toast.success(t('Member removed'))
          list.reload()
        }}
      />
    )}

    {bypassing && (
      <ConfirmDialog
        title={bypassing.sso_bypass ? t('Revoke SSO bypass for {{member}}?', { member: bypassing.user_name || t('this member') }) : t('Grant SSO bypass for {{member}}?', { member: bypassing.user_name || t('this member') })}
        confirmLabel={bypassing.sso_bypass ? t('Revoke bypass') : t('Grant bypass')}
        description={bypassing.sso_bypass
          ? t('{{value}} will have to sign in through SSO when it is enforced.', { value: bypassing.user_name || bypassing.user_id })
          : t('{{value}} will be able to sign in with a password even when SSO is enforced. Use for break-glass administrators only.', { value: bypassing.user_name || bypassing.user_id })}
        onClose={() => setBypassing(null)}
        confirm={async () => {
          await api.patch(`${base}/organizations/${orgId}/members/${bypassing.user_id}`, { sso_bypass: !bypassing.sso_bypass })
          toast.success(bypassing.sso_bypass ? t('SSO bypass revoked') : t('SSO bypass granted'))
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
      <DialogTitle className="text-base font-semibold">{t('Set manager')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{rich('Choose a manager for {{strong}} in this organization. Leave empty to remove the current manager.', { strong: <strong>{member.user_name}</strong> })}</DialogDescription>
      <div className="space-y-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{t('Manager')}</label>
          <SearchSelect
            name="manager_id"
            path={membersPath}
            mapItem={memberOption}
            defaultValue={managerId}
            disabled={busy}
            placeholder={t('Search members…')}
            onChange={setManagerId}
          />
          {managerId && <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => setManagerId('')}>
            {t('Clear manager')}
          </button>}
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button disabled={busy} onClick={async () => {
            setBusy(true); setError('')
            try {
              await api.put(profilePath, {
                manager_id: managerId || null,
              })
              toast.success(t('Manager updated'))
              onSaved()
            } catch (e) { setError(message(e)) } finally { setBusy(false) }
          }}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
}

interface EffectiveRole {
  role_id: string; role_name: string; resource_id: string; resource_name: string
  source: 'direct' | 'group'; granted: boolean; group_id?: string; group_name?: string
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
      <DialogTitle className="text-base font-semibold">{t('Access of {{user_name}}', { user_name: member.user_name })}</DialogTitle>
      <DialogDescription className="text-muted-foreground">
        {t('Effective roles in this organization: direct assignments plus roles inherited from groups. Grants are not shown.')}
      </DialogDescription>
      {error ? <ErrorState error={error} /> : roles === null ? <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p> : <div className="space-y-4">
        <div className="space-y-2">
          <h3 className="text-sm font-medium">{t('Roles')}</h3>
          {roles.length === 0 ? <p className="text-sm text-muted-foreground">{t('No roles.')}</p> : <ul className="divide-y rounded-lg border">
            {roles.map(r => <li key={`${r.role_id}:${r.source}:${r.group_id ?? ''}`} className="flex items-center justify-between gap-3 px-3 py-2">
              <div className="min-w-0">
                <p className="truncate font-medium">{r.role_name}{!r.granted && <Badge variant="outline" className="ml-1.5 border-amber-500/50 text-amber-700 dark:text-amber-400" title={t('The resource requires a grant this organization does not have for this role, so the role adds no permissions to tokens.')}>{t('Not granted')}</Badge>}</p>
                <p className="truncate text-xs text-muted-foreground">{r.resource_name}</p>
              </div>
              {r.source === 'group'
                ? <Link to={`${groupsPath}/${r.group_id}`} className="shrink-0"><Badge variant="secondary" className="bg-primary/10 text-primary">{t('via {{group}}', { group: r.group_name })}</Badge></Link>
                : <Badge variant="secondary" className="shrink-0">{t('Direct')}</Badge>}
            </li>)}
          </ul>}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-medium">{t('Groups')}</h3>
          {groups.length === 0 ? <p className="text-sm text-muted-foreground">{t('Not in any group.')}</p> : <div className="flex flex-wrap gap-2">
            {groups.map(g => <Link key={g.id} to={`${groupsPath}/${g.id}`}><Badge variant="outline">{g.name}{g.connection_id ? (' ' + t('· Directory')) : ''}</Badge></Link>)}
          </div>}
        </div>
      </div>}
    </DialogContent>
  </Dialog>
}
