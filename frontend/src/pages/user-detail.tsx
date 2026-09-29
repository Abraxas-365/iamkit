import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Ban, Building2, KeyRound, LockOpen, Pencil, Plus, RotateCcw, ShieldCheck, Smartphone, Trash2, UserX } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { Skeleton } from '@/components/ui/skeleton'
import { BackLink, ConfirmDialog, CopyText, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, FormDialog, Properties, Status, Time } from '@/components/library/patterns'
import { AssignRoleDialog } from '@/components/library/assign-role'

interface User { id: string; name: string; email: string; active: boolean; email_verified?: boolean; otp_enabled?: boolean; phone?: string; phone_verified?: boolean; metadata?: Record<string, unknown> | null; failed_logins?: number; locked_until?: string | null }
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

  if (error) return <div className="space-y-4"><BackLink to={`${console}/users`}>All users</BackLink><ErrorState error={error} retry={load} /></div>
  if (!user) return <div role="status" className="space-y-4"><Skeleton className="h-9 w-64" /><Skeleton className="h-40" /><span className="sr-only">Loading user…</span></div>
  const label = user.name || user.email
  const metadata = user.metadata && Object.keys(user.metadata).length ? JSON.stringify(user.metadata, null, 2) : ''

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={`${console}/users`}>All users</BackLink>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h1 className="font-mono text-2xl font-bold tracking-tight">{label}</h1>
        <Status active={user.active} label={user.active ? 'Active' : 'Suspended'} />
        {user.locked_until && <Badge variant="secondary" className="bg-destructive/10 text-destructive">Locked</Badge>}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 text-sm text-muted-foreground"><span>{user.email}</span><CopyText value={user.id} short label="Copy user ID" /></div>
    </div>

    {user.locked_until && <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-destructive/30 p-4 text-sm">
      <div><p className="font-medium">Locked after {user.failed_logins} wrong passwords</p><p className="text-muted-foreground">Password sign-in is refused until <Time value={user.locked_until} />. A password reset also unlocks the account.</p></div>
      {canWrite && <Button variant="outline" onClick={() => setUnlock(true)}><LockOpen /> Unlock</Button>}
    </div>}

    <DetailSection title="Profile" actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      <Properties items={[
        ['Name', user.name],
        ['Email', <span className="inline-flex flex-wrap items-center gap-2">{user.email}{user.email_verified ? <Badge variant="secondary" className="bg-success/10 text-success">Verified</Badge> : <Badge variant="secondary">Not verified</Badge>}</span>],
        ['Email code sign-in', user.otp_enabled ? 'Allowed' : 'Off'],
        ['Phone', user.phone ? <span className="inline-flex flex-wrap items-center gap-2">{user.phone}{user.phone_verified ? <Badge variant="secondary" className="bg-success/10 text-success">Verified</Badge> : <Badge variant="secondary">Not verified</Badge>}</span> : <span className="text-muted-foreground">None</span>],
        ['Metadata', metadata ? <pre className="max-h-48 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-xs">{metadata}</pre> : <span className="text-muted-foreground">None</span>],
      ]} />
    </DetailSection>

    <Organizations base={base} console={console} user={user} canWrite={canWrite} />
    <SecondFactors path={path} user={user} canWrite={canWrite} />
    <Sessions base={base} console={console} user={user} canWrite={canWrite} />

    {canWrite && <DetailSection danger title="Danger zone">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm"><p className="font-medium">{user.active ? 'Suspend user' : 'Reactivate user'}</p><p className="text-muted-foreground">{user.active ? 'Blocks sign-in everywhere and stops their sessions from refreshing. Nothing is deleted.' : 'Lets the user sign in again with their existing access.'}</p></div>
          <Button variant="outline" onClick={() => setSuspend(true)}>{user.active ? <><UserX /> Suspend</> : <><RotateCcw /> Reactivate</>}</Button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <div className="text-sm"><p className="font-medium">Delete permanently</p><p className="text-muted-foreground">Erases the user with their memberships, roles, grants, sessions and linked identities. Use for erasure requests.</p></div>
          <Button variant="destructive" onClick={() => setPurge(true)}><Trash2 /> Delete permanently</Button>
        </div>
      </div>
    </DetailSection>}

    {editing && <FormDialog title="Edit user" description="Change the profile and sign-in options." fields={[
      { name: 'name', label: 'Name', value: user.name },
      { name: 'otp_enabled', label: 'Allow sign-in with an email code', type: 'checkbox', value: !!user.otp_enabled },
      { name: 'phone', label: 'Phone', optional: true, value: user.phone ?? '', hint: 'International format, e.g. +14155550100. Changing it clears verification; an enrolled SMS factor keeps its number.' },
      { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: user.metadata ? JSON.stringify(user.metadata) : '', hint: 'Arbitrary JSON object, e.g. {"team":"billing"}' },
    ]} onClose={() => setEditing(false)} submit={async values => {
      const body: Record<string, unknown> = { name: values.name, otp_enabled: values.otp_enabled, phone: String(values.phone ?? '') }
      if (values.metadata) {
        try { body.metadata = JSON.parse(String(values.metadata)) } catch { throw new Error('Metadata must be valid JSON') }
      } else body.metadata = {}
      await api.patch(path, body); load()
    }} />}
    {suspend && (user.active
      ? <ConfirmDialog title={`Suspend ${label}?`} description="They can no longer sign in and their sessions stop refreshing. You can reactivate them later." confirmLabel="Suspend" onClose={() => setSuspend(false)} confirm={async () => { await api.delete(path); toast.success('User suspended'); load() }} />
      : <ConfirmDialog title={`Reactivate ${label}?`} description="They can sign in again with their existing memberships and roles." confirmLabel="Reactivate" onClose={() => setSuspend(false)} confirm={async () => { await api.patch(path, { active: true }); toast.success('User reactivated'); load() }} />)}
    {unlock && <ConfirmDialog title={`Unlock ${label}?`} description="Clears the wrong-password count so they can sign in with their password again." confirmLabel="Unlock" onClose={() => setUnlock(false)} confirm={async () => { await api.post(`${path}/unlock`); toast.success('User unlocked'); load() }} />}
    {purge && <ConfirmDialog title="Permanently delete user?" description={`This erases ${label} and every session, membership, grant, role assignment, and linked identity for them in this environment. This cannot be undone.`} confirmLabel="Delete permanently" confirmationText={label} onClose={() => setPurge(false)} confirm={async () => { await api.delete(`${path}/permanent`); toast.success('User deleted'); navigate(`${console}/users`) }} />}
  </div>
}

function Organizations({ base, console, user, canWrite }: { base: string; console: string; user: User; canWrite: boolean }) {
  const params = useMemo(() => ({ user_id: user.id }), [user.id])
  const orgs = usePaginatedList<Org>(`${base}/organizations`, { extraParams: params, limit: 100 })
  const roles = useEffectiveRoles(base, user.id)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Org | null>(null)
  const [assigning, setAssigning] = useState<Org | null>(null)
  const [unassigning, setUnassigning] = useState<{ role: EffectiveRole; org: Org } | null>(null)
  const byOrg = (org: string) => roles.data.filter(r => r.organization_id === org)
  const add = canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> Add to organization</Button>
  return <DetailSection title="Organizations & roles" description="Where this user can sign in, and the roles they hold there: directly, or through a group. Grants are listed on each organization." actions={orgs.data.length > 0 && add}>
    {roles.error && <ErrorState error={`Roles could not be loaded: ${roles.error}`} retry={roles.reload} />}
    <DataTable
      columns={['Organization', 'Roles', ...(canWrite ? ['Actions'] : [])]}
      loading={orgs.loading} error={orgs.error} retry={orgs.reload}
      empty={<EmptyState icon={<Building2 />} title="Not a member of any organization" description="Users need a membership to sign in to an organization." action={add} />}
      rows={orgs.data.map(o => [
        <EntityRef name={o.name} id={o.id} to={`${console}/organizations/${o.id}/members`} secondary={!o.active ? 'Organization inactive' : undefined} />,
        roles.loading ? <span className="text-sm text-muted-foreground">Loading…</span>
          : roles.error ? <span className="text-sm text-muted-foreground">Unavailable</span>
            : <OrgRoles console={console} org={o} roles={byOrg(o.id)} onRemove={canWrite ? role => setUnassigning({ role, org: o }) : undefined} />,
        ...(canWrite ? [<RowActions label={`Actions for ${o.name}`} actions={[
          { label: 'Assign role', icon: <ShieldCheck />, onSelect: () => setAssigning(o) },
          { label: 'Remove from organization', icon: <Ban />, destructive: true, onSelect: () => setRemoving(o) },
        ]} />] : []),
      ])} />
    {adding && <FormDialog title={`Add ${user.name || user.email} to an organization`} description="The user can sign in to it right away. Assign roles afterwards." submitLabel="Add" success="Added to organization" fields={[
      { name: 'organization_id', label: 'Organization', type: 'select', selectPath: `${base}/organizations`, selectMap: named },
    ]} onClose={() => setAdding(false)} submit={async values => { await api.post(`${base}/memberships`, { organization_id: values.organization_id, user_id: user.id }); orgs.reload() }} />}
    {assigning && <AssignRoleDialog base={base} organization={assigning} user={{ id: user.id, name: user.name || user.email }} onClose={() => setAssigning(null)} onAssigned={roles.reload} />}
    {unassigning && <ConfirmDialog title={`Remove role ${unassigning.role.role_name}?`} description={`${user.name || user.email} loses this role in ${unassigning.org.name}. Roles from groups are not affected.`} confirmLabel="Remove role" onClose={() => setUnassigning(null)} confirm={async () => { await api.delete(`${base}/role-assignments/${unassigning.role.role_id}/${unassigning.org.id}/${user.id}`); toast.success('Role removed'); roles.reload() }} />}
    {removing && <ConfirmDialog title={`Remove from ${removing.name}?`} description={`${user.name || user.email} can no longer sign in to ${removing.name}. Their account is kept.`} confirmLabel="Remove" onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${base}/organizations/${removing.id}/members/${user.id}`); toast.success('Removed from organization'); orgs.reload(); roles.reload() }} />}
  </DetailSection>
}

interface EffectiveRole { organization_id: string; role_id: string; role_name: string; resource_name: string; source: 'direct' | 'group'; group_id?: string; group_name?: string }

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
  if (!roles.length) return <span className="text-sm text-muted-foreground">No roles</span>
  return <span className="flex flex-wrap gap-1">
    {roles.filter(r => r.source === 'direct').map(r => <Badge key={r.role_id} variant="secondary" title={r.resource_name} className="gap-1">{r.role_name}{onRemove && <button type="button" className="-mr-1 rounded-sm px-0.5 text-muted-foreground hover:text-destructive" aria-label={`Remove role ${r.role_name} in ${org.name}`} onClick={() => onRemove(r)}>×</button>}</Badge>)}
    {roles.filter(r => r.source === 'group').map(r => <Link key={`${r.group_id}:${r.role_id}`} to={`${console}/organizations/${org.id}/groups/${r.group_id}`} title={`${r.resource_name}: inherited from the group ${r.group_name}; manage it on the group`}>
      <Badge variant="outline" className="gap-1 hover:border-primary">{r.role_name}<span className="text-muted-foreground">via {r.group_name}</span></Badge>
    </Link>)}
  </span>
}

function factorLabel(f: Factor) {
  switch (f.kind) {
    case 'totp': return 'Authenticator app (TOTP)'
    case 'email': return 'Email code'
    case 'sms': return `SMS code${f.phone ? ` · ${f.phone}` : ''}`
    case 'webauthn': return `${f.passkey ? 'Passkey' : 'Security key'}${f.name ? ` · ${f.name}` : ''}`
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
  return <DetailSection title="Second factors" description="Authenticators used for multi-factor sign-in. Secrets are never shown." actions={canWrite && any && <Button variant="outline" size="sm" onClick={() => setReset(true)}>Reset factors</Button>}>
    {error ? <ErrorState error={error} retry={load} /> : !data ? <Skeleton className="h-12" /> : <div className="space-y-3 text-sm">
      {data.factors.length === 0 ? <p className="text-muted-foreground">No second factor enrolled.</p> : <ul className="space-y-2">{data.factors.map(f => <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border p-3">
        <Smartphone className="size-4 text-muted-foreground" />
        <span className="font-medium">{factorLabel(f)}</span>
        {!f.confirmed_at && <Badge variant="secondary">Pending confirmation</Badge>}
        <span className="text-xs text-muted-foreground">Added <Time value={f.created_at} /> · Last used <Time value={f.last_used_at} /></span>
      </li>)}</ul>}
      <p>Recovery codes remaining: <strong>{data.recovery_codes_remaining}</strong></p>
    </div>}
    {reset && <ConfirmDialog title="Reset second factors?" description={`This removes every authenticator and recovery code of ${user.name || user.email} (for a lost device). If their organization requires MFA they will enroll again at the next sign-in.`} confirmLabel="Reset" onClose={() => setReset(false)} confirm={async () => { await api.delete(`${path}/factors`); toast.success('Second factors reset'); load() }} />}
  </DetailSection>
}

function Sessions({ base, console, user, canWrite }: { base: string; console: string; user: User; canWrite: boolean }) {
  const params = useMemo(() => ({ user_id: user.id }), [user.id])
  const list = usePaginatedList<Session>(`${base}/sessions`, { extraParams: params, limit: 20 })
  const [revoke, setRevoke] = useState<Session | null>(null)
  const state = (s: Session) => s.revoked_at ? ['Revoked', 'bg-destructive/10 text-destructive'] : Date.parse(s.expires_at) <= Date.now() ? ['Expired', 'bg-muted text-muted-foreground'] : ['Active', 'bg-success/10 text-success']
  return <DetailSection title="Recent sessions" description="Sign-ins to your applications, newest first." actions={<Link to={`${console}/sessions`} className="text-sm text-primary hover:underline">All sessions</Link>}>
    <DataTable
      columns={['Application', { header: 'Organization', hideBelow: 'md' }, { header: 'Expires', nowrap: true }, 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title="No sessions" description="Sessions appear when this user signs in to an application." />}
      rows={list.data.map(s => {
        const [label, tone] = state(s)
        return [
          <EntityRef name={s.application_name} id={s.application_id} to={`${console}/applications/${s.application_id}`} secondary={s.resource_name} />,
          s.organization_name || '—',
          <Time value={s.expires_at} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          ...(canWrite ? [!s.revoked_at && <RowActions label={`Actions for session in ${s.application_name}`} actions={[{ label: 'Revoke session', icon: <Ban />, destructive: true, onSelect: () => setRevoke(s) }]} />] : []),
        ]
      })} />
    {revoke && <ConfirmDialog title="Revoke this session?" description={`${user.email} is signed out of ${revoke.application_name || 'the application'} and must sign in again.`} confirmLabel="Revoke session" onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${base}/sessions/${revoke.id}`); toast.success('Session revoked'); list.reload() }} />}
  </DetailSection>
}
