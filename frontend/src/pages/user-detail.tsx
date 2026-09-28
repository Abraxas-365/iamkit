import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Ban, Building2, KeyRound, Pencil, Plus, RotateCcw, ShieldCheck, Smartphone, Trash2, UserX } from 'lucide-react'
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

interface User { id: string; name: string; email: string; active: boolean; email_verified?: boolean; otp_enabled?: boolean; metadata?: Record<string, unknown> | null }
interface Org { id: string; name: string; active: boolean }
interface Assignment { organization_id: string; organization_name: string; resource_id: string; resource_name: string; role_id: string; role_name: string }
interface Factor { id: string; kind: string; confirmed_at: string | null; last_used_at: string | null; created_at: string }
interface Factors { factors: Factor[]; recovery_codes_remaining: number }
interface Session { id: string; organization_name: string; application_id: string; application_name: string; resource_name: string; expires_at: string; revoked_at: string | null }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id), inactive: item.active === false })
const roleOption = (item: Record<string, unknown>) => ({ id: String(item.id), label: item.resource_name ? `${item.name} · ${item.resource_name}` : String(item.name ?? item.id) })

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
      </div>
      <div className="flex flex-wrap items-center gap-x-3 text-sm text-muted-foreground"><span>{user.email}</span><CopyText value={user.id} short label="Copy user ID" /></div>
    </div>

    <DetailSection title="Profile" actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      <Properties items={[
        ['Name', user.name],
        ['Email', <span className="inline-flex flex-wrap items-center gap-2">{user.email}{user.email_verified ? <Badge variant="secondary" className="bg-success/10 text-success">Verified</Badge> : <Badge variant="secondary">Not verified</Badge>}</span>],
        ['Email code sign-in', user.otp_enabled ? 'Allowed' : 'Off'],
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
      { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: user.metadata ? JSON.stringify(user.metadata) : '', hint: 'Arbitrary JSON object, e.g. {"team":"billing"}' },
    ]} onClose={() => setEditing(false)} submit={async values => {
      const body: Record<string, unknown> = { name: values.name, otp_enabled: values.otp_enabled }
      if (values.metadata) {
        try { body.metadata = JSON.parse(String(values.metadata)) } catch { throw new Error('Metadata must be valid JSON') }
      } else body.metadata = {}
      await api.patch(path, body); load()
    }} />}
    {suspend && (user.active
      ? <ConfirmDialog title={`Suspend ${label}?`} description="They can no longer sign in and their sessions stop refreshing. You can reactivate them later." confirmLabel="Suspend" onClose={() => setSuspend(false)} confirm={async () => { await api.delete(path); toast.success('User suspended'); load() }} />
      : <ConfirmDialog title={`Reactivate ${label}?`} description="They can sign in again with their existing memberships and roles." confirmLabel="Reactivate" onClose={() => setSuspend(false)} confirm={async () => { await api.patch(path, { active: true }); toast.success('User reactivated'); load() }} />)}
    {purge && <ConfirmDialog title="Permanently delete user?" description={`This erases ${label} and every session, membership, grant, role assignment, and linked identity for them in this environment. This cannot be undone.`} confirmLabel="Delete permanently" confirmationText={label} onClose={() => setPurge(false)} confirm={async () => { await api.delete(`${path}/permanent`); toast.success('User deleted'); navigate(`${console}/users`) }} />}
  </div>
}

function Organizations({ base, console, user, canWrite }: { base: string; console: string; user: User; canWrite: boolean }) {
  const params = useMemo(() => ({ user_id: user.id }), [user.id])
  const orgs = usePaginatedList<Org>(`${base}/organizations`, { extraParams: params, limit: 100 })
  const roles = usePaginatedList<Assignment>(`${base}/role-assignments`, { extraParams: params, limit: 200 })
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Org | null>(null)
  const [assigning, setAssigning] = useState<Org | null>(null)
  const [unassigning, setUnassigning] = useState<Assignment | null>(null)
  const byOrg = (org: string) => roles.data.filter(r => r.organization_id === org)
  const add = canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> Add to organization</Button>
  return <DetailSection title="Organizations & roles" description="Where this user can sign in, and the roles they hold directly. Group roles and grants are listed on each organization." actions={orgs.data.length > 0 && add}>
    <DataTable
      columns={['Organization', 'Roles', ...(canWrite ? ['Actions'] : [])]}
      loading={orgs.loading} error={orgs.error} retry={orgs.reload}
      empty={<EmptyState icon={<Building2 />} title="Not a member of any organization" description="Users need a membership to sign in to an organization." action={add} />}
      rows={orgs.data.map(o => [
        <EntityRef name={o.name} id={o.id} to={`${console}/organizations/${o.id}/members`} secondary={!o.active ? 'Organization inactive' : undefined} />,
        byOrg(o.id).length ? <span className="flex flex-wrap gap-1">{byOrg(o.id).map(r => <Badge key={r.role_id} variant="secondary" title={r.resource_name} className="gap-1">{r.role_name}{canWrite && <button type="button" className="-mr-1 rounded-sm px-0.5 text-muted-foreground hover:text-destructive" aria-label={`Remove role ${r.role_name} in ${o.name}`} onClick={() => setUnassigning(r)}>×</button>}</Badge>)}</span> : <span className="text-sm text-muted-foreground">No direct roles</span>,
        ...(canWrite ? [<RowActions label={`Actions for ${o.name}`} actions={[
          { label: 'Assign role', icon: <ShieldCheck />, onSelect: () => setAssigning(o) },
          { label: 'Remove from organization', icon: <Ban />, destructive: true, onSelect: () => setRemoving(o) },
        ]} />] : []),
      ])} />
    {adding && <FormDialog title={`Add ${user.name || user.email} to an organization`} description="The user can sign in to it right away. Assign roles afterwards." submitLabel="Add" success="Added to organization" fields={[
      { name: 'organization_id', label: 'Organization', type: 'select', selectPath: `${base}/organizations`, selectMap: named },
    ]} onClose={() => setAdding(false)} submit={async values => { await api.post(`${base}/memberships`, { organization_id: values.organization_id, user_id: user.id }); orgs.reload() }} />}
    {assigning && <FormDialog title={`Assign a role in ${assigning.name}`} description={`${user.name || user.email} gets the role's permissions when signing in to ${assigning.name}.`} submitLabel="Assign role" success="Role assigned" fields={[
      { name: 'role_id', label: 'Role', type: 'select', selectPath: `${base}/roles`, selectMap: roleOption },
    ]} onClose={() => setAssigning(null)} submit={async values => { await api.post(`${base}/role-assignments`, { organization_id: assigning.id, user_id: user.id, role_id: values.role_id }); roles.reload() }} />}
    {unassigning && <ConfirmDialog title={`Remove role ${unassigning.role_name}?`} description={`${user.name || user.email} loses this role in ${unassigning.organization_name}. Roles from groups are not affected.`} confirmLabel="Remove role" onClose={() => setUnassigning(null)} confirm={async () => { await api.delete(`${base}/role-assignments/${unassigning.role_id}/${unassigning.organization_id}/${user.id}`); toast.success('Role removed'); roles.reload() }} />}
    {removing && <ConfirmDialog title={`Remove from ${removing.name}?`} description={`${user.name || user.email} can no longer sign in to ${removing.name}. Their account is kept.`} confirmLabel="Remove" onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${base}/organizations/${removing.id}/members/${user.id}`); toast.success('Removed from organization'); orgs.reload() }} />}
  </DetailSection>
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
        <span className="font-medium">{f.kind === 'totp' ? 'Authenticator app (TOTP)' : f.kind}</span>
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
