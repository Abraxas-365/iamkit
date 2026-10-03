import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Ban, CheckCircle2, Globe, KeyRound, Mail, Plus, RotateCcw, Share2, Trash2, Unlock, UserPlus, Users } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Avatar } from '@/components/library/avatar'
import { UserState } from '@/components/library/user-state'
import { ConfirmDialog, CopyField, DataTable, DetailSection, EmptyState, ErrorState, FormDialog, PageHeader, Status, SwitchField, Time } from '@/components/library/patterns'
import { describeAction } from '@/pages/activity'
import { CreateConnectionDialog, providerLabel, type ConnectionTransport } from '@/pages/federation-connection-form'
import { OrganizationPasswordRequirements, type PasswordRequirements, type RequirementsStore } from '@/pages/organization-password'
import { message } from '@/lib/utils'
import { useAdmin } from './context'
import type { Page } from './session'
import { rich, t } from '@/lib/i18n'

// Wire shapes of /organizations/:organization/admin (see
// docs/guides/organization-administration.md).
interface Organization { id: string; name: string; mfa_required: boolean; mfa_for_federated: boolean; allow_password: boolean; allow_email_code: boolean; allow_social: boolean; allow_passkey: boolean }
interface Member { user_id: string; user_name: string; user_email: string; active: boolean; sso_bypass: boolean }
interface User { id: string; name: string; email: string; username: string; avatar_url: string; state: string; active: boolean; phone: string }
interface Role { id: string; name: string; resource_id: string; resource_name: string; permissions: string[]; system_role?: string }
interface Assignment { role_id: string; role_name: string; resource_name: string }
interface Invitation { id: string; email: string; inviter: string; status: string; expires_at: string; created_at: string }
interface Issued extends Invitation { link?: string; delivery: string }
interface Domain { id: string; domain: string; verified: boolean; verification: { name: string; value: string } }
interface Connection { id: string; name: string; provider: string; enforcement: string; active: boolean; linked: number }
interface Resource { id: string; name: string; prefix: string; require_grant: boolean }
interface ResourceGrant { id: string; resource_id: string; resource_name: string; organization_id: string; organization_name: string; role_ids: string[] | null; created_at: string }
interface Event { id: string; actor_id: string; actor_kind: string; actor_label: string; action: string; target_id: string; created_at: string }
interface Overrides { display_name: string | null; logo_url: string | null; accent_color: string | null; theme: unknown; locale?: string | null; updated_at?: string }

/** usePortalList pages through an /admin list with the portal's client. */
function usePortalList<T>(path: string | null, extra: Record<string, string> = {}) {
  const { client } = useAdmin()
  const [rawSearch, setSearch] = useState('')
  const [search, setDebounced] = useState('')
  const [offset, setOffset] = useState(0)
  const [version, setVersion] = useState(0)
  const [state, setState] = useState<{ data: T[]; total: number; loading: boolean; error: string }>({ data: [], total: 0, loading: true, error: '' })
  const limit = 50
  const extraKey = JSON.stringify(extra)
  useEffect(() => { const timer = setTimeout(() => { setDebounced(rawSearch); setOffset(0) }, 300); return () => clearTimeout(timer) }, [rawSearch])
  useEffect(() => {
    if (path === null) return
    const ctrl = new AbortController()
    const q = new URLSearchParams({ limit: String(limit), offset: String(offset), ...JSON.parse(extraKey) })
    if (search) q.set('search', search)
    setState(s => ({ ...s, loading: true, error: '' }))
    client.get<Page<T>>(`${path}?${q}`, ctrl.signal)
      .then(r => { if (!ctrl.signal.aborted) setState({ data: r.items ?? [], total: r.page?.total ?? 0, loading: false, error: '' }) })
      .catch(e => { if (!ctrl.signal.aborted) setState({ data: [], total: 0, loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [client, path, offset, search, version, extraKey])
  return {
    ...state, rawSearch, setSearch, from: state.total ? offset + 1 : 0, to: Math.min(offset + limit, state.total),
    hasPrev: offset > 0, hasNext: offset + limit < state.total,
    nextPage: () => setOffset(o => o + limit), prevPage: () => setOffset(o => Math.max(0, o - limit)),
    reload: useCallback(() => setVersion(v => v + 1), []),
  }
}

function useResource<T>(path: string) {
  const { client } = useAdmin()
  const [state, setState] = useState<{ data?: T; error: string }>({ error: '' })
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const ctrl = new AbortController()
    client.get<T>(path, ctrl.signal).then(data => setState({ data, error: '' })).catch(e => { if (!ctrl.signal.aborted) setState({ error: message(e) }) })
    return () => ctrl.abort()
  }, [client, path, version])
  return { ...state, reload: () => setVersion(v => v + 1) }
}

const Loading = () => <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p>

export function OverviewPage() {
  const { client, can } = useAdmin()
  const org = useResource<Organization>('')
  const [draft, setDraft] = useState<Organization | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (org.data) setDraft(org.data) }, [org.data])
  if (org.error) return <ErrorState error={org.error} retry={org.reload} />
  if (!org.data || !draft) return <Loading />
  const write = can('iam:org:settings:write')
  const changed = JSON.stringify(draft) !== JSON.stringify(org.data)
  const flag = (key: keyof Organization, label: string, hint: string) => <SwitchField label={label} hint={hint} checked={draft[key] as boolean} disabled={!write || busy} onCheckedChange={v => setDraft({ ...draft, [key]: v })} />
  return <>
    <PageHeader title={org.data.name} description={t('Your organization\'s settings. Sign-in methods only narrow what the application allows.')} />
    <DetailSection title={t('Settings')}>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); setBusy(true)
        try {
          await client.patch('', { name: draft.name.trim(), mfa_required: draft.mfa_required, mfa_for_federated: draft.mfa_for_federated, allow_password: draft.allow_password, allow_email_code: draft.allow_email_code, allow_social: draft.allow_social, allow_passkey: draft.allow_passkey })
          toast.success(t('Settings saved')); org.reload()
        } catch (err) { toast.error(message(err)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5"><label htmlFor="org-name" className="text-sm font-medium">{t('Name')}</label><Input id="org-name" value={draft.name} disabled={!write || busy} required onChange={e => setDraft({ ...draft, name: e.target.value })} /></div>
        {flag('mfa_required', t('Require two-step verification'), t('Password and email-code sign-ins need a second factor.'))}
        {flag('mfa_for_federated', t('Also for single sign-on'), t('SSO sign-ins follow the same rule instead of trusting the identity provider.'))}
        {flag('allow_password', t('Allow passwords'), t('Members may sign in with a password.'))}
        {flag('allow_email_code', t('Allow email codes'), t('Members may sign in with a code sent by email.'))}
        {flag('allow_social', t('Allow social login'), t('Members may use the application\'s social login providers.'))}
        {flag('allow_passkey', t('Allow passkeys'), t('Members may sign in with a passkey.'))}
        {write && <div className="flex gap-2"><Button type="submit" disabled={busy || !changed}>{busy ? t('Saving…') : t('Save settings')}</Button>{changed && <Button type="button" variant="outline" onClick={() => setDraft(org.data!)}>{t('Discard')}</Button>}</div>}
      </form>
    </DetailSection>
  </>
}

export function MembersPage() {
  const { client, can } = useAdmin()
  const list = usePortalList<Member>('/members')
  const [removing, setRemoving] = useState<Member | null>(null)
  const [roles, setRoles] = useState<Member | null>(null)
  return <>
    <PageHeader title={t('Members')} description={t('Everyone who belongs to your organization.')} />
    <PaginationBar state={list} placeholder={t('Search members…')} label={t('Search members')} noun="members" />
    <DataTable columns={[t('Member'), { header: t('Status'), hideBelow: 'sm' }, { header: t('SSO bypass'), hideBelow: 'md' }, t('Actions')]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Users />} title={t('No members yet')} />}
      rows={list.data.map(m => [
        <span className="block min-w-0"><span className="block font-medium">{m.user_name || m.user_email}</span><span className="block truncate text-xs text-muted-foreground">{m.user_email}</span></span>,
        <Status active={m.active} />,
        m.sso_bypass ? <Badge variant="secondary">{t('Bypass')}</Badge> : <span className="text-sm text-muted-foreground">—</span>,
        <RowActions label={t('Actions for {{user_email}}', { user_email: m.user_email })} actions={[
          ...(can('iam:org:roles:read') ? [{ label: t('Roles'), icon: <KeyRound />, onSelect: () => setRoles(m) }] : []),
          ...(can('iam:org:members:write') ? [
            { label: m.sso_bypass ? t('Require SSO') : t('Allow password despite SSO'), onSelect: async () => { try { await client.patch(`/members/${m.user_id}`, { sso_bypass: !m.sso_bypass }); toast.success(t('Member updated')); list.reload() } catch (e) { toast.error(message(e)) } } },
            { label: t('Remove from organization'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(m) },
          ] : []),
        ]} />,
      ])} />
    {removing && <ConfirmDialog title={t('Remove {{user_email}}?', { user_email: removing.user_email })} description={t('They lose access to your organization and its sessions end.')} confirmLabel={t('Remove')} onClose={() => setRemoving(null)}
      confirm={async () => { await client.delete(`/members/${removing.user_id}`); toast.success(t('Member removed')); list.reload() }} />}
    {roles && <MemberRoles member={roles} onClose={() => setRoles(null)} />}
  </>
}

function MemberRoles({ member, onClose }: { member: Member; onClose: () => void }) {
  const { client, can } = useAdmin()
  const assigned = usePortalList<Assignment>(`/members/${member.user_id}/roles`)
  const available = usePortalList<Role>('/roles')
  const [role, setRole] = useState('')
  const assign = can('iam:org:roles:assign')
  const held = new Set(assigned.data.map(a => a.role_id))
  return <DetailSection title={t('Roles of {{value}}', { value: member.user_name || member.user_email })} actions={<Button variant="outline" size="sm" onClick={onClose}>{t('Close')}</Button>}>
    <DataTable columns={[t('Role'), { header: t('Resource'), hideBelow: 'sm' }, t('Actions')]} loading={assigned.loading} error={assigned.error} retry={assigned.reload}
      empty={<EmptyState title={t('No roles')} />}
      rows={assigned.data.map(a => [a.role_name, a.resource_name, assign ? <Button variant="ghost" size="sm" aria-label={t('Remove {{role_name}}', { role_name: a.role_name })} onClick={async () => {
        try { await client.delete(`/role-assignments/${member.user_id}/${a.role_id}`); toast.success(t('Role removed')); assigned.reload() } catch (e) { toast.error(message(e)) }
      }}><Trash2 /></Button> : null])} />
    {assign && <form className="flex flex-wrap items-end gap-2" onSubmit={async e => {
      e.preventDefault(); if (!role) return
      try { await client.post('/role-assignments', { user_id: member.user_id, role_id: role }); toast.success(t('Role assigned')); setRole(''); assigned.reload() } catch (err) { toast.error(message(err)) }
    }}>
      <label className="sr-only" htmlFor="assign-role">{t('Role')}</label>
      <select id="assign-role" className="h-8 min-w-60 rounded-lg border bg-transparent px-2 text-sm" value={role} onChange={e => setRole(e.target.value)}>
        <option value="">{t('Choose a role…')}</option>
        {available.data.filter(r => !held.has(r.id)).map(r => <option key={r.id} value={r.id}>{r.name} — {r.resource_name}</option>)}
      </select>
      <Button type="submit" size="sm" disabled={!role}><Plus /> {t('Assign')}</Button>
    </form>}
  </DetailSection>
}

export function UsersPage() {
  const { client, can } = useAdmin()
  const list = usePortalList<User>('/users')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const write = can('iam:org:users:write')
  const act = (path: string, done: string) => async () => { try { await client.post(path); toast.success(done); list.reload() } catch (e) { toast.error(message(e)) } }
  return <>
    <PageHeader title={t('Users')} description={t('Accounts your organization owns: you can create, edit and suspend them.')} actions={write && <Button onClick={() => setCreating(true)}><UserPlus /> {t('Create user')}</Button>} />
    <PaginationBar state={list} placeholder={t('Search users…')} label={t('Search users')} noun="users" />
    <DataTable columns={[t('User'), { header: t('State'), hideBelow: 'sm' }, t('Actions')]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<UserPlus />} title={t('No users of your own yet')} description={t('Users you create here belong to your organization.')} />}
      rows={list.data.map(u => [
        <span className="flex min-w-0 items-center gap-3"><Avatar src={u.avatar_url} name={u.name} className="size-8" /><span className="min-w-0"><span className="block font-medium">{u.name || u.email}</span><span className="block truncate text-xs text-muted-foreground">{u.email}{u.username && ` · @${u.username}`}</span></span></span>,
        <UserState state={u.state} active={u.active} />,
        write ? <RowActions label={t('Actions for {{email}}', { email: u.email })} actions={[
          { label: t('Edit'), onSelect: () => setEditing(u) },
          ...(u.state === 'locked' ? [{ label: t('Unlock'), icon: <Unlock />, onSelect: act(`/users/${u.id}/unlock`, t('User unlocked')) }] : []),
          u.active ? { label: t('Suspend'), icon: <Ban />, destructive: true, onSelect: act(`/users/${u.id}/deactivate`, t('User suspended')) } : { label: t('Reactivate'), icon: <RotateCcw />, onSelect: act(`/users/${u.id}/reactivate`, t('User reactivated')) },
        ]} /> : null,
      ])} />
    {creating && <FormDialog title={t('Create user')} description={t('The user joins your organization. Without a password they sign in with an email code or your SSO.')} submitLabel={t('Create')} success={t('User created')} onClose={() => setCreating(false)}
      fields={[{ name: 'email', label: t('Email'), type: 'email' }, { name: 'name', label: t('Name') }, { name: 'username', label: t('Username'), optional: true }, { name: 'password', label: t('Password'), type: 'password', optional: true }]}
      submit={async d => { await client.post('/users', { email: d.email, name: d.name, username: d.username || undefined, password: d.password || undefined }); list.reload() }} />}
    {editing && <FormDialog title={t('Edit {{email}}', { email: editing.email })} description={t('Changes apply everywhere the user signs in.')} onClose={() => setEditing(null)} success={t('User updated')}
      fields={[{ name: 'name', label: t('Name'), value: editing.name }, { name: 'username', label: t('Username'), value: editing.username, optional: true }, { name: 'avatar_url', label: t('Avatar URL'), value: editing.avatar_url, optional: true, hint: t('An https link to an image.') }]}
      submit={async d => { await client.patch(`/users/${editing.id}`, { name: d.name, username: d.username, avatar_url: d.avatar_url }); list.reload() }} />}
  </>
}

export function InvitationsPage() {
  const { client, can } = useAdmin()
  const list = usePortalList<Invitation>('/invitations')
  const roles = usePortalList<Role>(can('iam:org:roles:assign') ? '/roles' : null)
  const [inviting, setInviting] = useState(false)
  const [issued, setIssued] = useState<Issued | null>(null)
  const write = can('iam:org:invitations:write')
  return <>
    <PageHeader title={t('Invitations')} description={t('Invite people by email; they choose how to sign in when they accept.')} actions={write && <Button onClick={() => setInviting(true)}><Mail /> {t('Invite')}</Button>} />
    {issued?.link && <DetailSection title={t('Invitation for {{email}}', { email: issued.email })} actions={<Button variant="outline" size="sm" onClick={() => setIssued(null)}>{t('Done')}</Button>}>
      <CopyField label={t('Invitation link')} value={issued.link} hint={issued.delivery === 'sent' ? t('We also emailed it.') : t('Send this link yourself: no email was sent.')} />
    </DetailSection>}
    <DataTable columns={[t('Email'), { header: t('Status'), hideBelow: 'sm' }, { header: t('Expires'), hideBelow: 'md', nowrap: true }, t('Actions')]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Mail />} title={t('No invitations')} />}
      rows={list.data.map(i => [
        <span className="block min-w-0"><span className="block font-medium">{i.email}</span><span className="block truncate text-xs text-muted-foreground">{t('by {{inviter}}', { inviter: i.inviter })}</span></span>,
        <Badge variant="secondary">{i.status}</Badge>, <Time value={i.expires_at} />,
        write && i.status === 'pending' ? <RowActions label={t('Actions for {{email}}', { email: i.email })} actions={[
          { label: t('Resend'), icon: <RotateCcw />, onSelect: async () => { try { setIssued(await client.post<Issued>(`/invitations/${i.id}/resend`)); toast.success(t('Invitation sent again')); list.reload() } catch (e) { toast.error(message(e)) } } },
          { label: t('Revoke'), icon: <Trash2 />, destructive: true, onSelect: async () => { try { await client.delete(`/invitations/${i.id}`); toast.success(t('Invitation revoked')); list.reload() } catch (e) { toast.error(message(e)) } } },
        ]} /> : null,
      ])} />
    {inviting && <FormDialog title={t('Invite someone')} description={t('They receive a link to join your organization.')} submitLabel={t('Invite')} success={t('Invitation created')} onClose={() => setInviting(false)}
      fields={[{ name: 'email', label: t('Email'), type: 'email' }, ...(roles.data.length ? [{ name: 'role_id', label: t('Role'), type: 'dropdown' as const, optional: true, options: [{ value: '', label: t('No role') }, ...roles.data.map(r => ({ value: r.id, label: `${r.name} — ${r.resource_name}` }))] }] : [])]}
      submit={async d => { setIssued(await client.post<Issued>('/invitations', { email: d.email, role_ids: d.role_id ? [d.role_id] : [] })); list.reload() }} />}
  </>
}

export function RolesPage() {
  const list = usePortalList<Role>('/roles')
  return <>
    <PageHeader title={t('Roles')} description={t('Roles you can give your members: administration roles and those of applications your organization uses.')} />
    <DataTable columns={[t('Role'), { header: t('Resource'), hideBelow: 'sm' }, { header: t('Permissions'), hideBelow: 'md' }]} loading={list.loading} error={list.error} retry={list.reload}
      rows={list.data.map(r => [
        <span className="flex items-center gap-2 font-medium">{r.name}{r.system_role && <Badge variant="secondary">{t('Built-in')}</Badge>}</span>, r.resource_name,
        <span className="block max-w-md truncate font-mono text-xs text-muted-foreground" title={r.permissions.join(' ')}>{r.permissions.join(' ')}</span>,
      ])} />
  </>
}

export function DomainsPage() {
  const { client, can } = useAdmin()
  const list = usePortalList<Domain>('/domains')
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Domain | null>(null)
  const write = can('iam:org:domains:write')
  return <>
    <PageHeader title={t('Domains')} description={t('Verified domains route your employees to your SSO and brand your sign-in pages.')} actions={write && <Button onClick={() => setAdding(true)}><Globe /> {t('Add domain')}</Button>} />
    <DataTable columns={[t('Domain'), t('Status'), { header: t('Verification record'), hideBelow: 'md' }, t('Actions')]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Globe />} title={t('No domains')} />}
      rows={list.data.map(d => [
        <span className="font-medium">{d.domain}</span>,
        d.verified ? <Badge variant="secondary" className="bg-success/10 text-success">{t('Verified')}</Badge> : <Badge variant="secondary" className="bg-warning/10 text-warning">{t('Pending')}</Badge>,
        d.verified ? <span className="text-sm text-muted-foreground">—</span> : <span className="block max-w-sm text-xs"><span className="block font-mono">TXT {d.verification.name}</span><span className="block break-all font-mono text-muted-foreground">{d.verification.value}</span></span>,
        write ? <RowActions label={t('Actions for {{domain}}', { domain: d.domain })} actions={[
          ...(!d.verified ? [{ label: t('Verify now'), icon: <CheckCircle2 />, onSelect: async () => { try { const out = await client.post<Domain>(`/domains/${d.id}/verify`); toast[out.verified ? 'success' : 'error'](out.verified ? t('Domain verified') : t('The TXT record was not found yet')); list.reload() } catch (e) { toast.error(message(e)) } } }] : []),
          { label: t('Remove'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(d) },
        ]} /> : null,
      ])} />
    {adding && <FormDialog title={t('Add a domain')} description={t('Then publish the TXT record we show and verify it.')} submitLabel={t('Add')} success={t('Domain added')} onClose={() => setAdding(false)}
      fields={[{ name: 'domain', label: t('Domain'), hint: t('For example acme.com') }]} submit={async d => { await client.post('/domains', { domain: d.domain }); list.reload() }} />}
    {removing && <ConfirmDialog title={t('Remove {{domain}}?', { domain: removing.domain })} description={t('Its users are no longer routed to your SSO by email.')} confirmLabel={t('Remove')} onClose={() => setRemoving(null)}
      confirm={async () => { await client.delete(`/domains/${removing.id}`); toast.success(t('Domain removed')); list.reload() }} />}
  </>
}

export function ConnectionsPage() {
  const { client, can, claims } = useAdmin()
  const list = usePortalList<Connection>('/connections')
  const [adding, setAdding] = useState(false)
  const [disabling, setDisabling] = useState<Connection | null>(null)
  const write = can('iam:org:sso:write')
  const transport = useMemo<ConnectionTransport>(() => ({
    domains: signal => client.get<Page<{ domain: string; verified: boolean }>>('/domains?limit=100', signal).then(r => r.items),
    create: body => client.post('/connections', body),
  }), [client])
  return <>
    <PageHeader title={t('Single sign-on')} description={t('Let your employees sign in with your company\'s identity provider.')} actions={write && <Button onClick={() => setAdding(true)}><KeyRound /> {t('Add SSO')}</Button>} />
    <DataTable columns={[t('Connection'), { header: t('Mode'), hideBelow: 'sm' }, { header: t('Linked'), hideBelow: 'md' }, t('Status'), t('Actions')]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title={t('No SSO yet')} description={t('Connect Entra ID, Google Workspace, Okta, SAML or LDAP.')} />}
      rows={list.data.map(c => [
        <span className="block min-w-0"><span className="block font-medium">{c.name}</span><span className="block text-xs text-muted-foreground">{providerLabel(c.provider)}</span></span>,
        c.enforcement === 'enforced' ? <Badge variant="secondary" className="bg-primary/10 text-primary">{t('SSO required')}</Badge> : <span className="text-sm text-muted-foreground">{t('Optional')}</span>,
        <span className="tabular-nums">{c.linked}</span>,
        <Status active={c.active} label={c.active ? t('Active') : t('Disabled')} />,
        write ? <RowActions label={t('Actions for {{name}}', { name: c.name })} actions={c.active ? [
          { label: c.enforcement === 'enforced' ? t('Make optional') : t('Require SSO'), onSelect: async () => { try { await client.patch(`/connections/${c.id}`, { enforcement: c.enforcement === 'enforced' ? 'optional' : 'enforced' }); toast.success(t('Connection updated')); list.reload() } catch (e) { toast.error(message(e)) } } },
          { label: t('Disable'), icon: <Ban />, destructive: true, onSelect: () => setDisabling(c) },
        ] : [
          { label: t('Enable'), icon: <RotateCcw />, onSelect: async () => { try { await client.post(`/connections/${c.id}/enable`); toast.success(t('Connection enabled')); list.reload() } catch (e) { toast.error(message(e)) } } },
        ]} /> : null,
      ])} />
    {adding && <CreateConnectionDialog base="" kind="sso" organization={{ id: claims.organization_id ?? '', name: 'your organization' }} transport={transport} onClose={() => setAdding(false)} onCreated={list.reload} />}
    {disabling && <ConfirmDialog title={t('Disable {{name}}?', { name: disabling.name })} description={t('Its users can no longer sign in with it.')} confirmLabel={t('Disable')} onClose={() => setDisabling(null)}
      confirm={async () => { await client.delete(`/connections/${disabling.id}`); toast.success(t('Connection disabled')); list.reload() }} />}
  </>
}

export function ResourcesPage() {
  const { client, can } = useAdmin()
  const owned = usePortalList<Resource>('/resources')
  const grants = usePortalList<ResourceGrant>('/resource-grants')
  const received = usePortalList<ResourceGrant>('/granted-resources')
  const [granting, setGranting] = useState(false)
  const write = can('iam:org:resources:write')
  return <>
    <PageHeader title={t('Resources')} description={t('APIs your organization owns, who you share them with, and what others share with you.')} actions={write && owned.data.length > 0 && <Button onClick={() => setGranting(true)}><Share2 /> {t('Share a resource')}</Button>} />
    <DetailSection title={t('Owned by your organization')}>
      <DataTable columns={[t('Resource'), { header: t('Prefix'), hideBelow: 'sm' }, t('Access')]} loading={owned.loading} error={owned.error} retry={owned.reload}
        empty={<EmptyState title={t('Your organization owns no resources')} />}
        rows={owned.data.map(r => [<span className="font-medium">{r.name}</span>, <code className="text-xs">{r.prefix}</code>, r.require_grant ? t('Granted organizations only') : t('Every organization')])} />
    </DetailSection>
    <DetailSection title={t('Shared with other organizations')}>
      <DataTable columns={[t('Resource'), t('Organization'), { header: t('Roles'), hideBelow: 'md' }, t('Actions')]} loading={grants.loading} error={grants.error} retry={grants.reload}
        empty={<EmptyState title={t('Not shared')} />}
        rows={grants.data.map(g => [g.resource_name, g.organization_name, g.role_ids === null ? t('All roles') : t('{{count}} roles', { count: g.role_ids.length }),
          write ? <Button variant="ghost" size="sm" aria-label={t('Stop sharing {{resource_name}} with {{organization_name}}', { resource_name: g.resource_name, organization_name: g.organization_name })} onClick={async () => { try { await client.delete(`/resource-grants/${g.id}`); toast.success(t('Grant removed')); grants.reload() } catch (e) { toast.error(message(e)) } }}><Trash2 /></Button> : null])} />
    </DetailSection>
    <DetailSection title={t('Shared with your organization')}>
      <DataTable columns={[t('Resource'), { header: t('Since'), hideBelow: 'sm' }]} loading={received.loading} error={received.error} retry={received.reload}
        empty={<EmptyState title={t('Nothing shared with you')} />}
        rows={received.data.map(g => [g.resource_name, <Time value={g.created_at} />])} />
    </DetailSection>
    {granting && <FormDialog title={t('Share a resource')} description={t('The organization\'s members can then get the resource\'s roles.')} submitLabel={t('Share')} success={t('Resource shared')} onClose={() => setGranting(false)}
      fields={[{ name: 'resource_id', label: t('Resource'), type: 'dropdown', options: owned.data.map(r => ({ value: r.id, label: r.name })) }, { name: 'organization_id', label: t('Organization ID'), hint: t('Ask the other organization for its ID.') }]}
      submit={async d => { await client.put('/resource-grants', { resource_id: d.resource_id, organization_id: d.organization_id }); grants.reload() }} />}
  </>
}

export function BrandingPage() {
  const { client, can } = useAdmin()
  const saved = useResource<Overrides>('/branding')
  const [draft, setDraft] = useState({ display_name: '', logo_url: '', accent_color: '' })
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState(false)
  useEffect(() => { if (saved.data) setDraft({ display_name: saved.data.display_name ?? '', logo_url: saved.data.logo_url ?? '', accent_color: saved.data.accent_color ?? '' }) }, [saved.data])
  if (saved.error) return <ErrorState error={saved.error} retry={saved.reload} />
  if (!saved.data) return <Loading />
  const write = can('iam:org:settings:write')
  const custom = saved.data.display_name !== null || saved.data.logo_url !== null || saved.data.accent_color !== null || saved.data.theme !== null || !!saved.data.locale
  const text = (v: string) => v.trim() ? v.trim() : null
  const field = (key: keyof typeof draft, label: string, hint: string, placeholder?: string) => <div className="space-y-1.5">
    <label htmlFor={`brand-${key}`} className="text-sm font-medium">{label}</label>
    <Input id={`brand-${key}`} value={draft[key]} placeholder={placeholder} disabled={!write || busy} onChange={e => setDraft({ ...draft, [key]: e.target.value })} />
    <p className="text-xs text-muted-foreground">{hint}</p>
  </div>
  return <>
    <PageHeader title={t('Branding')} description={t('How the sign-in and invitation pages look for your organization. Empty fields keep the application\'s look.')} />
    <DetailSection title={t('Sign-in pages')} description={saved.data.updated_at ? <>{rich('Updated {{time}}.', { time: <Time value={saved.data.updated_at} /> })}</> : undefined}>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); setBusy(true)
        try { await client.put('/branding', { display_name: text(draft.display_name), logo_url: text(draft.logo_url), accent_color: text(draft.accent_color), theme: saved.data!.theme ?? null, locale: saved.data!.locale ?? null }); toast.success(t('Branding saved')); saved.reload() }
        catch (err) { toast.error(message(err)) } finally { setBusy(false) }
      }}>
        {field('display_name', t('Display name'), t('Shown instead of the application name.'))}
        {field('logo_url', t('Logo URL'), t('An https link to your logo.'), 'https://')}
        {field('accent_color', t('Accent color'), t('Buttons and links, as a hex color.'), '#4f46e5')}
        {write && <div className="flex flex-wrap gap-2"><Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save branding')}</Button>{custom && <Button type="button" variant="outline" onClick={() => setReset(true)}><Trash2 /> {t('Remove branding')}</Button>}</div>}
      </form>
    </DetailSection>
    {reset && <ConfirmDialog title={t('Remove your branding?')} description={t('Your pages use the application\'s look again.')} confirmLabel={t('Remove')} onClose={() => setReset(false)}
      confirm={async () => { await client.delete('/branding'); toast.success(t('Branding removed')); saved.reload() }} />}
  </>
}

export function PasswordPage() {
  const { client, can, claims } = useAdmin()
  const store = useMemo<RequirementsStore>(() => ({
    get: () => client.get<PasswordRequirements>('/password-policy'),
    put: body => client.put<PasswordRequirements>('/password-policy', body),
    remove: () => client.delete('/password-policy'),
  }), [client])
  return <>
    <PageHeader title={t('Password policy')} description={t('Stricter password rules for your members.')} />
    <OrganizationPasswordRequirements organization={claims.organization_id ?? ''} canWrite={can('iam:org:settings:write')} store={store} />
  </>
}

export function ActivityPage() {
  const [action, setAction] = useState('')
  const list = usePortalList<Event>('/events', action ? { action } : {})
  return <>
    <PageHeader title={t('Activity')} description={t('What happened in your organization, and who did it.')} />
    <div className="flex items-center gap-2"><label htmlFor="action-filter" className="text-sm">{t('Action starts with')}</label><Input id="action-filter" className="max-w-xs" value={action} placeholder="user." onChange={e => setAction(e.target.value)} /></div>
    <DataTable columns={[t('What'), t('Who'), { header: t('When'), nowrap: true }]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState title={t('No activity yet')} />}
      rows={list.data.map(e => [<span className="font-medium">{describeAction(e.action, e.target_id)}</span>, <Actor event={e} />, <Time value={e.created_at} />])} />
    <PaginationBar state={list} placeholder={t('Search…')} label={t('Search activity')} noun="events" />
  </>
}

// Who acted. Operators of the platform have no label here (their emails
// are not the customer's), so they show by kind, never as a bare ID.
const actorKinds: Record<string, string> = { operator: t('Platform administrator'), service_account: t('Service account'), system: t('System'), directory: t('Directory (SCIM)'), user: t('User') }
function Actor({ event: e }: { event: Event }) {
  const kind = actorKinds[e.actor_kind]
  if (e.actor_label) return <span title={kind}>{e.actor_label}</span>
  return <span className="text-muted-foreground">{kind ?? '—'}</span>
}
