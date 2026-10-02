import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Ban, Bot, Building2, Home, KeyRound, LockOpen, Pencil, Plus, RotateCcw, ShieldCheck, Smartphone, Trash2, UserX } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { Skeleton } from '@/components/ui/skeleton'
import { BackLink, ConfirmDialog, CopyText, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, FormDialog, Properties, Time } from '@/components/library/patterns'
import { AssignRoleDialog } from '@/components/library/assign-role'
import { UserState } from '@/components/library/user-state'
import { Avatar } from '@/components/library/avatar'
import { MetadataEditor, ProfileAttributes } from '@/components/library/metadata-editor'
import { AccessTokens } from './machine-tokens'
import { UserKeys } from './machine-keys'
import { HistorySection } from './history'
import { rich, t } from '@/lib/i18n'

interface User { id: string; kind?: string; name: string; email: string; username?: string; avatar_url?: string; active: boolean; email_verified?: boolean; otp_enabled?: boolean; phone?: string; phone_verified?: boolean; metadata?: Record<string, unknown> | null; profile?: Record<string, unknown> | null; failed_logins?: number; locked_until?: string | null; state?: string; last_signed_in_at?: string | null; home_organization_id?: string | null }
interface Org { id: string; name: string; active: boolean }
interface Factor { id: string; kind: string; name?: string; passkey?: boolean; phone?: string; confirmed_at: string | null; last_used_at: string | null; created_at: string }
interface Factors { factors: Factor[]; recovery_codes_remaining: number }
interface Session { id: string; organization_name: string; application_id: string; application_name: string; resource_name: string; expires_at: string; revoked_at: string | null }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id), inactive: item.active === false })

/** UserDetailPage gathers everything about one end user: profile,
 * organizations, roles, second factors, sessions and account actions. */
export default function UserDetailPage() {
  const { project, environment, userId } = useParams()
  const navigate = useNavigate()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/users/${userId}`
  const [user, setUser] = useState<User | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [suspend, setSuspend] = useState(false)
  const [purge, setPurge] = useState(false)
  const [unlock, setUnlock] = useState(false)
  const load = useCallback(() => { setError(''); api.get<User>(path).then(setUser).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])

  if (error) return <div className="space-y-4"><BackLink to={`${console}/users`}>{t('All users')}</BackLink><ErrorState error={error} retry={load} /></div>
  if (!user) return <div role="status" className="space-y-4"><Skeleton className="h-9 w-64" /><Skeleton className="h-40" /><span className="sr-only">{t('Loading user…')}</span></div>
  const label = user.name || user.email
  const machine = user.kind === 'machine'

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={`${console}/users`}>{t('All users')}</BackLink>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Avatar src={user.avatar_url} name={label} className="size-10 text-sm" />
        <h1 className="font-mono text-2xl font-bold tracking-tight">{label}</h1>
        <UserState state={user.state} active={user.active} />
        {machine && <Badge variant="outline" className="gap-1" title={t('Signs in only with personal access tokens')}><Bot className="size-3" /> {t('Machine user')}</Badge>}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 text-sm text-muted-foreground">{!machine && <span>{user.email}</span>}<CopyText value={user.id} short label={t('Copy user ID')} /></div>
    </div>

    {user.locked_until && <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-destructive/30 p-4 text-sm">
      <div><p className="font-medium">{t('Locked after {{failed_logins}} wrong passwords', { failed_logins: user.failed_logins })}</p><p className="text-muted-foreground">{rich('Password sign-in is refused until {{time}}. A password reset also unlocks the account.', { time: <Time value={user.locked_until} /> })}</p></div>
      {canWrite && <Button variant="outline" onClick={() => setUnlock(true)}><LockOpen /> {t('Unlock')}</Button>}
    </div>}

    <DetailSection title={t('Profile')} actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>}>
      <Properties items={machine ? [
        [t('Name'), user.name],
        [t('Kind'), t('Machine user: no email, password or second factor')],
        [t('Last token use'), user.last_signed_in_at ? <Time value={user.last_signed_in_at} /> : <span className="text-muted-foreground">{t('Never')}</span>],
      ] : [
        [t('Name'), user.name],
        [t('Username'), user.username ? <span className="font-mono">{user.username}</span> : <span className="text-muted-foreground">{t('None')}</span>],
        [t('Email'), <span className="inline-flex flex-wrap items-center gap-2">{user.email}{user.email_verified ? <Badge variant="secondary" className="bg-success/10 text-success">{t('Verified')}</Badge> : <Badge variant="secondary">{t('Not verified')}</Badge>}</span>],
        [t('Email code sign-in'), user.otp_enabled ? t('Allowed') : t('Off')],
        [t('Last sign-in'), user.last_signed_in_at ? <Time value={user.last_signed_in_at} /> : <span className="text-muted-foreground">{t('Never')}</span>],
        [t('Phone'), user.phone ? <span className="inline-flex flex-wrap items-center gap-2">{user.phone}{user.phone_verified ? <Badge variant="secondary" className="bg-success/10 text-success">{t('Verified')}</Badge> : <Badge variant="secondary">{t('Not verified')}</Badge>}</span> : <span className="text-muted-foreground">{t('None')}</span>],
      ]} />
    </DetailSection>

    <ProfileAttributes path={path} profile={user.profile} canWrite={canWrite} reload={load} />
    <MetadataEditor path={path} metadata={user.metadata} canWrite={canWrite} reload={load} />

    <Organizations base={base} console={console} user={user} canWrite={canWrite} reload={load} />
    {machine
      ? <>
        <AccessTokens base={base} console={console} user={{ id: user.id, name: label }} canWrite={canWrite} />
        <UserKeys base={base} user={{ id: user.id, name: label }} canWrite={canWrite} />
      </>
      : <SecondFactors path={path} user={user} canWrite={canWrite} />}
    <Sessions base={base} console={console} user={user} canWrite={canWrite} />
    <HistorySection path={path} refresh={user} />

    {canWrite && <DetailSection danger title={t('Danger zone')}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm"><p className="font-medium">{user.active ? t('Suspend user') : t('Reactivate user')}</p><p className="text-muted-foreground">{user.active ? t('Blocks sign-in everywhere and stops their sessions from refreshing. Nothing is deleted.') : t('Lets the user sign in again with their existing access.')}</p></div>
          <Button variant="outline" onClick={() => setSuspend(true)}>{user.active ? <><UserX /> {t('Suspend')}</> : <><RotateCcw /> {t('Reactivate')}</>}</Button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <div className="text-sm"><p className="font-medium">{t('Delete permanently')}</p><p className="text-muted-foreground">{t('Erases the user with their memberships, roles, grants, sessions and linked identities. Use for erasure requests.')}</p></div>
          <Button variant="destructive" onClick={() => setPurge(true)}><Trash2 /> {t('Delete permanently')}</Button>
        </div>
      </div>
    </DetailSection>}

    {editing && <FormDialog title={t('Edit user')} description={machine ? t('Change the machine user\'s name and picture.') : t('Change the profile and sign-in options.')} fields={machine ? [
      { name: 'name', label: t('Name'), value: user.name },
      { name: 'avatar_url', label: t('Avatar URL'), optional: true, value: user.avatar_url ?? '', hint: t('An https link to a picture.') },
    ] : [
      { name: 'name', label: t('Name'), value: user.name },
      { name: 'username', label: t('Username'), optional: true, value: user.username ?? '', hint: t('Signs in like the email. Lowercase letters, digits, dots, dashes or underscores. Leave blank to remove it.') },
      { name: 'otp_enabled', label: t('Allow sign-in with an email code'), type: 'checkbox', value: !!user.otp_enabled },
      { name: 'phone', label: t('Phone'), optional: true, value: user.phone ?? '', hint: t('International format, e.g. +14155550100. Changing it clears verification; an enrolled SMS factor keeps its number.') },
      { name: 'phone_verified', label: t('Phone number verified'), type: 'checkbox', value: !!user.phone_verified, hint: t('Mark the number as confirmed without texting a code (recorded in the audit log). A new number starts unverified.') },
      { name: 'avatar_url', label: t('Avatar URL'), optional: true, value: user.avatar_url ?? '', hint: t('An https link to their picture. Users can change it themselves, and a social sign-in fills it when empty.') },
    ]} onClose={() => setEditing(false)} submit={async values => {
      if (machine) { await api.patch(path, { name: values.name, avatar_url: String(values.avatar_url ?? '').trim() }); load(); return }
      const phone = String(values.phone ?? '').trim()
      const phoneChanged = phone !== (user.phone ?? '')
      const verified = !!values.phone_verified && phone !== ''
      await api.patch(path, { name: values.name, otp_enabled: values.otp_enabled, phone, ...(verified !== (!phoneChanged && !!user.phone_verified) ? { phone_verified: verified } : {}), avatar_url: String(values.avatar_url ?? '').trim(), username: String(values.username ?? '').trim() }); load()
    }} />}
    {suspend && (user.active
      ? <ConfirmDialog title={t('Suspend {{label}}?', { label })} description={t('They can no longer sign in and their sessions stop refreshing. You can reactivate them later.')} confirmLabel={t('Suspend')} onClose={() => setSuspend(false)} confirm={async () => { await api.post(`${path}/deactivate`); toast.success(t('User suspended')); load() }} />
      : <ConfirmDialog title={t('Reactivate {{label}}?', { label })} description={t('They can sign in again with their existing memberships and roles.')} confirmLabel={t('Reactivate')} onClose={() => setSuspend(false)} confirm={async () => { await api.post(`${path}/reactivate`); toast.success(t('User reactivated')); load() }} />)}
    {unlock && <ConfirmDialog title={t('Unlock {{label}}?', { label })} description={t('Clears the wrong-password count so they can sign in with their password again.')} confirmLabel={t('Unlock')} onClose={() => setUnlock(false)} confirm={async () => { await api.post(`${path}/unlock`); toast.success(t('User unlocked')); load() }} />}
    {purge && <ConfirmDialog title={t('Permanently delete user?')} description={t('This erases {{label}} and every session, membership, grant, role assignment, and linked identity for them in this environment. This cannot be undone.', { label })} confirmLabel={t('Delete permanently')} confirmationText={label} onClose={() => setPurge(false)} confirm={async () => { await api.delete(`${path}/permanent`); toast.success(t('User deleted')); navigate(`${console}/users`) }} />}
  </div>
}

function Organizations({ base, console, user, canWrite, reload }: { base: string; console: string; user: User; canWrite: boolean; reload: () => void }) {
  const params = useMemo(() => ({ user_id: user.id }), [user.id])
  const orgs = usePaginatedList<Org>(`${base}/organizations`, { extraParams: params, limit: 100 })
  const roles = useEffectiveRoles(base, user.id)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Org | null>(null)
  const [assigning, setAssigning] = useState<Org | null>(null)
  const [unassigning, setUnassigning] = useState<{ role: EffectiveRole; org: Org } | null>(null)
  const byOrg = (org: string) => roles.data.filter(r => r.organization_id === org)
  const add = canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> {t('Add to organization')}</Button>
  const setHome = async (org: string) => { await api.patch(`${base}/users/${user.id}`, { home_organization_id: org }); toast.success(org ? t('Home organization set') : t('Home organization cleared')); reload() }
  return <DetailSection title={t('Organizations & roles')} description={t('Where this user can sign in, and the roles they hold there: directly, or through a group. The home organization owns the record: its administrators may edit the user.')} actions={orgs.data.length > 0 && add}>
    {roles.error && <ErrorState error={t('Roles could not be loaded: {{error}}', { error: roles.error })} retry={roles.reload} />}
    <DataTable
      columns={[t('Organization'), t('Roles'), ...(canWrite ? [t('Actions')] : [])]}
      loading={orgs.loading} error={orgs.error} retry={orgs.reload}
      empty={<EmptyState icon={<Building2 />} title={t('Not a member of any organization')} description={t('Users need a membership to sign in to an organization.')} action={add} />}
      rows={orgs.data.map(o => [
        <span className="flex flex-wrap items-center gap-2"><EntityRef name={o.name} id={o.id} to={`${console}/organizations/${o.id}/members`} secondary={!o.active ? t('Organization inactive') : undefined} />{user.home_organization_id === o.id && <Badge variant="secondary" title={t('Its administrators may edit this user')}>{t('Home')}</Badge>}</span>,
        roles.loading ? <span className="text-sm text-muted-foreground">{t('Loading…')}</span>
          : roles.error ? <span className="text-sm text-muted-foreground">{t('Unavailable')}</span>
            : <OrgRoles console={console} org={o} roles={byOrg(o.id)} onRemove={canWrite ? role => setUnassigning({ role, org: o }) : undefined} />,
        ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: o.name })} actions={[
          { label: t('Assign role'), icon: <ShieldCheck />, onSelect: () => setAssigning(o) },
          user.home_organization_id === o.id
            ? { label: t('Clear home organization'), icon: <Home />, onSelect: () => { setHome('').catch(e => toast.error(message(e))) } }
            : { label: t('Make home organization'), icon: <Home />, onSelect: () => { setHome(o.id).catch(e => toast.error(message(e))) } },
          { label: t('Remove from organization'), icon: <Ban />, destructive: true, onSelect: () => setRemoving(o) },
        ]} />] : []),
      ])} />
    {adding && <FormDialog title={t('Add {{value}} to an organization', { value: user.name || user.email })} description={t('The user can sign in to it right away. Assign roles afterwards.')} submitLabel={t('Add')} success={t('Added to organization')} fields={[
      { name: 'organization_id', label: t('Organization'), type: 'select', selectPath: `${base}/organizations`, selectMap: named },
    ]} onClose={() => setAdding(false)} submit={async values => { await api.post(`${base}/memberships`, { organization_id: values.organization_id, user_id: user.id }); orgs.reload() }} />}
    {assigning && <AssignRoleDialog base={base} organization={assigning} user={{ id: user.id, name: user.name || user.email }} onClose={() => setAssigning(null)} onAssigned={roles.reload} />}
    {unassigning && <ConfirmDialog title={t('Remove role {{role_name}}?', { role_name: unassigning.role.role_name })} description={t('{{value}} loses this role in {{name}}. Roles from groups are not affected.', { value: user.name || user.email, name: unassigning.org.name })} confirmLabel={t('Remove role')} onClose={() => setUnassigning(null)} confirm={async () => { await api.delete(`${base}/role-assignments/${unassigning.role.role_id}/${unassigning.org.id}/${user.id}`); toast.success(t('Role removed')); roles.reload() }} />}
    {removing && <ConfirmDialog title={t('Remove from {{name}}?', { name: removing.name })} description={t('{{value}} can no longer sign in to {{name}}. Their account is kept.', { value: user.name || user.email, name: removing.name })} confirmLabel={t('Remove')} onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${base}/organizations/${removing.id}/members/${user.id}`); toast.success(t('Removed from organization')); orgs.reload(); roles.reload() }} />}
  </DetailSection>
}

interface EffectiveRole { organization_id: string; role_id: string; role_name: string; resource_name: string; source: 'direct' | 'group'; granted: boolean; group_id?: string; group_name?: string }

/** notGranted says why a held role adds nothing to tokens. */
const notGranted = () => t('The resource requires a grant this organization does not have for this role, so the role adds no permissions to tokens.')

/** useEffectiveRoles loads every role the user holds, in all organizations,
 * with its source (direct or a group), in one request. */
function useEffectiveRoles(base: string, user: string) {
  const [state, setState] = useState<{ data: EffectiveRole[]; loading: boolean; error: string }>({ data: [], loading: true, error: '' })
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setState(s => ({ ...s, loading: true, error: '' }))
    api.list<EffectiveRole>(`${base}/effective-roles?user_id=${user}`, controller.signal)
      .then(r => setState({ data: r.data, loading: false, error: '' }))
      .catch(e => { if (!controller.signal.aborted) setState({ data: [], loading: false, error: message(e) }) })
    return () => controller.abort()
  }, [base, user, version])
  return { ...state, reload: () => setVersion(v => v + 1) }
}

/** OrgRoles lists a user's roles in one organization: direct ones (removable
 * here) and those inherited from groups (managed on the group). */
function OrgRoles({ console, org, roles, onRemove }: { console: string; org: Org; roles: EffectiveRole[]; onRemove?: (role: EffectiveRole) => void }) {
  if (!roles.length) return <span className="text-sm text-muted-foreground">{t('No roles')}</span>
  return <span className="flex flex-wrap gap-1">
    {roles.filter(r => r.source === 'direct').map(r => <Badge key={r.role_id} variant="secondary" title={r.granted ? r.resource_name : `${r.resource_name}: ${notGranted()}`} className="gap-1">{r.role_name}{!r.granted && <span className="text-amber-700 dark:text-amber-400">{t('Not granted')}</span>}{onRemove && <button type="button" className="-mr-1 rounded-sm px-0.5 text-muted-foreground hover:text-destructive" aria-label={t('Remove role {{role_name}} in {{name}}', { role_name: r.role_name, name: org.name })} onClick={() => onRemove(r)}>×</button>}</Badge>)}
    {roles.filter(r => r.source === 'group').map(r => <Link key={`${r.group_id}:${r.role_id}`} to={`${console}/organizations/${org.id}/groups/${r.group_id}`} title={(r.granted ? '' : notGranted() + ' ') + t('{{resource_name}}: inherited from the group {{group_name}}; manage it on the group', { resource_name: r.resource_name, group_name: r.group_name })}>
      <Badge variant="outline" className="gap-1 hover:border-primary">{r.role_name}<span className="text-muted-foreground">{t('via {{group}}', { group: r.group_name })}</span>{!r.granted && <span className="text-amber-700 dark:text-amber-400">{t('Not granted')}</span>}</Badge>
    </Link>)}
  </span>
}

function factorLabel(f: Factor) {
  switch (f.kind) {
    case 'totp': return t('Authenticator app (TOTP)')
    case 'email': return t('Email code')
    case 'sms': return `${t('SMS code')}${f.phone ? ` · ${f.phone}` : ''}`
    case 'webauthn': return `${f.passkey ? t('Passkey') : t('Security key')}${f.name ? ` · ${f.name}` : ''}`
    default: return f.kind
  }
}

function SecondFactors({ path, user, canWrite }: { path: string; user: User; canWrite: boolean }) {
  const [data, setData] = useState<Factors | null>(null)
  const [error, setError] = useState('')
  const [reset, setReset] = useState(false)
  const load = useCallback(() => { setError(''); api.get<Factors>(`${path}/factors`).then(setData, e => setError(message(e))) }, [path])
  useEffect(load, [load])
  const any = !!data && (data.factors.length > 0 || data.recovery_codes_remaining > 0)
  return <DetailSection title={t('Second factors')} description={t('Authenticators used for multi-factor sign-in. Secrets are never shown.')} actions={canWrite && any && <Button variant="outline" size="sm" onClick={() => setReset(true)}>{t('Reset factors')}</Button>}>
    {error ? <ErrorState error={error} retry={load} /> : !data ? <Skeleton className="h-12" /> : <div className="space-y-3 text-sm">
      {data.factors.length === 0 ? <p className="text-muted-foreground">{t('No second factor enrolled.')}</p> : <ul className="space-y-2">{data.factors.map(f => <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border p-3">
        <Smartphone className="size-4 text-muted-foreground" />
        <span className="font-medium">{factorLabel(f)}</span>
        {!f.confirmed_at && <Badge variant="secondary">{t('Pending confirmation')}</Badge>}
        <span className="text-xs text-muted-foreground">{rich('Added {{time}} · Last used', { time: <Time value={f.created_at} /> })} <Time value={f.last_used_at} /></span>
      </li>)}</ul>}
      <p>{rich('Recovery codes remaining: {{strong}}', { strong: <strong>{data.recovery_codes_remaining}</strong> })}</p>
    </div>}
    {reset && <ConfirmDialog title={t('Reset second factors?')} description={t('This removes every authenticator and recovery code of {{value}} (for a lost device). If their organization requires MFA they will enroll again at the next sign-in.', { value: user.name || user.email })} confirmLabel={t('Reset')} onClose={() => setReset(false)} confirm={async () => { await api.delete(`${path}/factors`); toast.success(t('Second factors reset')); load() }} />}
  </DetailSection>
}

function Sessions({ base, console, user, canWrite }: { base: string; console: string; user: User; canWrite: boolean }) {
  const params = useMemo(() => ({ user_id: user.id }), [user.id])
  const list = usePaginatedList<Session>(`${base}/sessions`, { extraParams: params, limit: 20 })
  const [revoke, setRevoke] = useState<Session | null>(null)
  const state = (s: Session) => s.revoked_at ? [t('Revoked'), 'bg-destructive/10 text-destructive'] : Date.parse(s.expires_at) <= Date.now() ? [t('Expired'), 'bg-muted text-muted-foreground'] : [t('Active'), 'bg-success/10 text-success']
  return <DetailSection title={t('Recent sessions')} description={t('Sign-ins to your applications, newest first.')} actions={<Link to={`${console}/sessions`} className="text-sm text-primary hover:underline">{t('All sessions')}</Link>}>
    <DataTable
      columns={[t('Application'), { header: t('Organization'), hideBelow: 'md' }, { header: t('Expires'), nowrap: true }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title={t('No sessions')} description={t('Sessions appear when this user signs in to an application.')} />}
      rows={list.data.map(s => {
        const [label, tone] = state(s)
        return [
          <EntityRef name={s.application_name} id={s.application_id} to={`${console}/applications/${s.application_id}`} secondary={s.resource_name} />,
          s.organization_name || '—',
          <Time value={s.expires_at} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          ...(canWrite ? [!s.revoked_at && <RowActions label={t('Actions for session in {{application_name}}', { application_name: s.application_name })} actions={[{ label: t('Revoke session'), icon: <Ban />, destructive: true, onSelect: () => setRevoke(s) }]} />] : []),
        ]
      })} />
    {revoke && <ConfirmDialog title={t('Revoke this session?')} description={t('{{user}} is signed out of {{application}} and must sign in again.', { user: user.email, application: revoke.application_name || t('the application') })} confirmLabel={t('Revoke session')} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${base}/sessions/${revoke.id}`); toast.success(t('Session revoked')); list.reload() }} />}
  </DetailSection>
}
