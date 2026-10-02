import { useId, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { AppWindow, ArrowRight, Bot, Building2, Eye, KeyRound, Pencil, Plus, ShieldCheck, Tags, Trash2, UserX, Users } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { RowActions, type Action } from '@/components/ui/menu'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { CollapsibleScopes } from '@/components/ui/collapsible-scopes'
import { PermissionPicker } from '@/components/ui/permission-picker'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, CopyText, DataTable, EmptyState, EntityRef, FormDialog, PageHeader, Status, splitList } from '@/components/library/patterns'
import type { Column, Field } from '@/components/library/patterns'
import { AssignRoleDialog } from '@/components/library/assign-role'
import { UserState, userStates } from '@/components/library/user-state'
import { Avatar } from '@/components/library/avatar'
import { RedirectList } from './integrations'
import { rich, t } from '@/lib/i18n'

type Kind = 'users' | 'organizations' | 'applications' | 'resources' | 'roles' | 'grants'

interface Entity {
  id: string; kind?: string; name?: string; email?: string; username?: string; avatar_url?: string; active?: boolean; state?: string; prefix?: string; audience?: string;
  permissions?: string[]; redirect_uris?: string[]; resource_id?: string; resource_name?: string;
  organization_id?: string; organization_name?: string; user_id?: string; user_name?: string;
  otp_enabled?: boolean; metadata?: Record<string, unknown>; mfa_required?: boolean; mfa_for_federated?: boolean;
  system_role?: string; owner_organization_id?: string | null; require_grant?: boolean;
}
const descriptions: Record<Kind, string> = {
  users: t('Manage end-user identities in this environment.'),
  organizations: t('Tenant organizations and their memberships.'),
  applications: t('Applications that authenticate users and request access to resources.'),
  resources: t('API audiences and their permission catalogs (scopes).'),
  roles: t('Reusable sets of resource permissions for organization members.'),
  grants: t('Direct resource permissions granted to users within an organization.'),
}
const usernameField: Field = { name: 'username', label: t('Username'), optional: true, hint: t('Lets them sign in with a name instead of their email. Lowercase letters, digits, dots, dashes or underscores; unique in the environment.') }
const avatarField: Field = { name: 'avatar_url', label: t('Avatar URL'), optional: true, hint: t('An https link to their picture. IAMKit stores the link, not the image.') }
const searches: Record<Kind, string> = { users: t('Search users…'), organizations: t('Search organizations…'), applications: t('Search applications…'), resources: t('Search resources…'), roles: t('Search roles…'), grants: t('Search grants…') }
const titles: Record<Kind, string> = { users: t('Users'), organizations: t('Organizations'), applications: t('Applications'), resources: t('Resources & scopes'), roles: t('Roles'), grants: t('Grants') }
const creates: Record<Kind, string> = { users: t('Create user'), organizations: t('Create organization'), applications: t('Create application'), resources: t('Create resource'), roles: t('Create role'), grants: t('Create grant') }
const copyIds: Record<Kind, string> = { users: t('Copy user ID'), organizations: t('Copy organization ID'), applications: t('Copy application ID'), resources: t('Copy resource ID'), roles: t('Copy role ID'), grants: t('Copy grant ID') }
// Whole sentences per kind: participles agree with the noun in other languages.
const saved: Record<Kind, [created: string, updated: string]> = {
  users: [t('User created'), t('User updated')], organizations: [t('Organization created'), t('Organization updated')],
  applications: [t('Application created'), t('Application updated')], resources: [t('Resource created'), t('Resource updated')],
  roles: [t('Role created'), t('Role updated')], grants: [t('Grant created'), t('Grant updated')],
}
const icons: Record<Kind, ReactNode> = { users: <Users />, organizations: <Building2 />, applications: <AppWindow />, resources: <KeyRound />, roles: <Tags />, grants: <ShieldCheck /> }
const empties: Record<Kind, [string, string]> = {
  users: [t('No users yet'), t('Create users here, invite them to an organization, or let them sign up through social login or SCIM.')],
  organizations: [t('No organizations yet'), t('Organizations are your customers or teams. Users sign in to an organization and get roles within it.')],
  applications: [t('No applications yet'), t('An application is a product your users sign in to — a web app, mobile app or CLI.')],
  resources: [t('No resources yet'), t('A resource is an API your applications call. Define its permissions (scopes) here.')],
  roles: [t('No roles yet'), t('Roles bundle permissions of a resource so you can give them to members in one step.')],
  grants: [t('No direct grants'), t('Grants give one user permissions within an organization without a role. Prefer roles for anything you repeat.')],
}
const createHints: Record<Kind, string> = {
  users: t('You can add the user to organizations on the next page.'),
  organizations: t('You can add members, SSO and domains on the next page.'),
  applications: t('Link resources and create OAuth clients for it afterwards.'),
  resources: t('The prefix namespaces every permission of this resource.'),
  roles: '', grants: '',
}
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id), inactive: item.active === false })
function fieldsFor(kind: Kind, _base: string, row?: Entity): Field[] {
  const name: Field = { name: 'name', label: t('Name'), value: row?.name }
  const permissionTags: Field = { name: 'permissions', label: t('Permissions'), type: 'tags', optional: true, tags: row?.permissions ?? [], prefix: row?.prefix, hint: row?.prefix ? t('Type an action and press Enter. Auto-prefixed as {{prefix}}:action.', { prefix: row.prefix }) : t('Define the prefix first — permissions will use it as a namespace.') }
  switch (kind) {
    case 'users': return row ? [name, { name: 'active', label: t('Active'), type: 'checkbox', value: row.active }, { name: 'otp_enabled', label: t('Enable one-time password login'), type: 'checkbox', value: row.otp_enabled }, { name: 'metadata', label: t('Metadata (JSON)'), optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: t('Arbitrary JSON object, e.g. {"team":"billing"}') }] : [name, { name: 'email', label: t('Email'), type: 'email' }, { name: 'password', label: t('Initial password'), type: 'password', optional: true, hint: t('Leave blank for OTP-only or OAuth login. If set, must be 12–72 characters long.') }, { name: 'otp_enabled', label: t('Enable one-time password login'), type: 'checkbox' }, usernameField, avatarField]
    case 'organizations': return row ? [name, { name: 'active', label: t('Active'), type: 'checkbox', value: row.active }, { name: 'mfa_required', label: t('Require a second factor'), type: 'checkbox', value: row.mfa_required, hint: t('Password and email-code sign-ins need an authenticator app; members without one enroll while signing in.') }, { name: 'mfa_for_federated', label: t('Also require it for SSO sign-ins'), type: 'checkbox', value: row.mfa_for_federated, hint: t('By default the identity provider is trusted to have done its own MFA.') }, { name: 'metadata', label: t('Metadata (JSON)'), optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: t('Arbitrary JSON object.') }] : [name]
    case 'applications': return [name, { name: 'redirect_uris', label: t('Redirect URIs'), type: 'tags', optional: true, tags: row?.redirect_uris ?? [], hint: t('Type a redirect URI and press Enter.') }, ...(row ? [{ name: 'active', label: t('Active'), type: 'checkbox' as const, value: row.active }] : [])]
    case 'resources': {
      const createPerms: Field = { name: 'permissions', label: t('Permissions'), type: 'tags', optional: true, tags: [], hint: t('Use prefix:action format (e.g. invoices:read). Must match the prefix above.') }
      return [name, ...(!row ? [{ name: 'prefix', label: t('Prefix'), hint: t('Unique scope namespace (lowercase, e.g. invoices). All scopes must start with this prefix.') }, { name: 'audience', label: t('Audience') }, createPerms] : [permissionTags])]
    }
    // Roles and grants use dedicated forms with PermissionPicker
    case 'roles': return [name]
    case 'grants': return []
  }
}

function RoleForm({ base, row, onClose, onSaved }: { base: string; row?: Entity; onClose: () => void; onSaved: () => void }) {
  const id = useId()
  const [resourceId, setResourceId] = useState(row?.resource_id ?? '')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{row ? t('Edit role') : t('Create role')}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{row ? t('Update role name and permissions.') : t('Name the role, pick a resource, and select permissions from its catalog.')}</DialogDescription>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const form = new FormData(event.currentTarget)
      const data: Record<string, unknown> = {
        name: String(form.get('name') ?? '').trim(),
        resource_id: String(form.get('resource_id') ?? '').trim(),
        permissions: splitList(String(form.get('permissions') ?? '')),
      }
      pending.current = true; setBusy(true); setError('')
      try {
        if (row) await api.put(`${base}/roles/${row.id}`, data)
        else await api.post(`${base}/roles`, data)
        toast.success(row ? t('Role updated') : t('Role created')); onSaved(); onClose()
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
        <Input id={`${id}-name`} name="name" defaultValue={row?.name ?? ''} required disabled={busy} />
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-resource`}>{t('Resource')}</label>
        {row ? (
          <>
            <input type="hidden" name="resource_id" value={row.resource_id} />
            <Input id={`${id}-resource`} value={row.resource_id} disabled className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">{t('Resource cannot be changed on an existing role.')}</p>
          </>
        ) : (
          <SearchSelect id={`${id}-resource`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder={t('Search resource…')} onChange={setResourceId} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium">{t('Permissions')}</label>
        <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" defaultValue={row?.permissions} disabled={busy} />
      </div>
      {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</div>}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button><Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button></div>
    </form>
  </DialogContent></Dialog>
}

function GrantForm({ base, row, onClose, onSaved }: { base: string; row?: Entity; onClose: () => void; onSaved: () => void }) {
  const id = useId()
  const [resourceId, setResourceId] = useState(row?.resource_id ?? '')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const isEdit = !!row
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{isEdit ? t('Edit grant') : t('Create grant')}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{isEdit ? t('Update this grant\'s permissions.') : t('Grant permissions on a resource to a user within an organization.')}</DialogDescription>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const form = new FormData(event.currentTarget)
      const data: Record<string, unknown> = {
        organization_id: String(form.get('organization_id') ?? '').trim(),
        user_id: String(form.get('user_id') ?? '').trim(),
        resource_id: String(form.get('resource_id') ?? '').trim(),
        permissions: splitList(String(form.get('permissions') ?? '')),
      }
      pending.current = true; setBusy(true); setError('')
      try {
        await api.put(`${base}/grants`, data)
        toast.success(row ? t('Grant updated') : t('Grant saved')); onSaved(); onClose()
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-org`}>{t('Organization')}</label>
        {isEdit ? (
          <>
            <input type="hidden" name="organization_id" value={row.organization_id} />
            <Input id={`${id}-org`} value={row.organization_id} disabled className="font-mono text-xs" />
          </>
        ) : (
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder={t('Search organization…')} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-user`}>{t('User')}</label>
        {isEdit ? (
          <>
            <input type="hidden" name="user_id" value={row.user_id} />
            <Input id={`${id}-user`} value={row.user_id} disabled className="font-mono text-xs" />
          </>
        ) : (
          <SearchSelect id={`${id}-user`} name="user_id" path={`${base}/users`} mapItem={named} required disabled={busy} placeholder={t('Search user…')} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-resource`}>{t('Resource')}</label>
        {isEdit ? (
          <>
            <input type="hidden" name="resource_id" value={row.resource_id} />
            <Input id={`${id}-resource`} value={row.resource_id} disabled className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">{t('Resource cannot be changed on an existing grant.')}</p>
          </>
        ) : (
          <SearchSelect id={`${id}-resource`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder={t('Search resource…')} onChange={setResourceId} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium">{t('Permissions')}</label>
        <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" defaultValue={row?.permissions} disabled={busy} />
      </div>
      {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</div>}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button><Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button></div>
    </form>
  </DialogContent></Dialog>
}

export default function EntitiesPage({ kind }: { kind: Kind }) {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const envBase = `/projects/${project}/environments/${environment}`
  const path = `${base}/${kind}`
  const [state, setState] = useState('')
  const [userKind, setUserKind] = useState('')
  const [machine, setMachine] = useState(false)
  const extraParams = useMemo(() => {
    if (kind !== 'users' || (!state && !userKind)) return undefined
    const out: Record<string, string> = {}
    if (state) out.state = state
    if (userKind) out.kind = userKind
    return out
  }, [kind, state, userKind])
  const list = usePaginatedList<Entity>(path, { extraParams })
  const navigate = useNavigate()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [edit, setEdit] = useState<Entity | 'new' | null>(null)
  const openEdit = async (row: Entity) => {
    if (kind === 'users' || kind === 'organizations') {
      // List rows lack settings (status, MFA policy); editing one would reset them.
      try { const full = await api.get<Entity>(`${path}/${row.id}`); setEdit(full) } catch (e) { toast.error(message(e)) }
    } else { setEdit(row) }
  }
  const [remove, setRemove] = useState<Entity | null>(null)
  const [purge, setPurge] = useState<Entity | null>(null)
  const [assign, setAssign] = useState(false)
  const label = (row: Entity) => row.name || row.email || (kind === 'grants' && row.user_name ? `${row.user_name}'s grant` : row.id)
  const detail = (row: Entity) => kind === 'users' ? `${envBase}/users/${row.id}` : kind === 'organizations' ? `${envBase}/organizations/${row.id}` : kind === 'applications' ? `${envBase}/applications/${row.id}` : kind === 'resources' ? `${envBase}/resources/${row.id}` : undefined
  const name = (row: Entity, secondary?: ReactNode) => {
    const to = detail(row)
    return <span className="block min-w-0">
      <span className="flex flex-wrap items-center gap-2">{to ? <Link to={to} className="font-medium hover:text-primary hover:underline">{label(row)}</Link> : <span className="font-medium">{label(row)}</span>}{((kind === 'resources' && row.prefix === 'iam') || (kind === 'roles' && row.system_role)) && <Badge variant="secondary" className="bg-primary/10 text-primary" title={kind === 'roles' ? t('Built-in organization administration role; it cannot be changed or deleted.') : undefined}>{kind === 'roles' ? t('Built-in') : t('System')}</Badge>}{kind === 'resources' && row.require_grant && <Badge variant="outline" title={t('Only the owner organization and organizations it is granted to reach this resource.')}>{t('Grant required')}</Badge>}</span>
      {secondary ?? <CopyText value={row.id} short label={copyIds[kind]} />}
    </span>
  }
  const permissions = (row: Entity) => row.permissions?.length ? <CollapsibleScopes key={row.id} scopes={row.permissions} /> : <span className="text-xs text-muted-foreground">{t('No permissions')}</span>
  const columns: Column[] = kind === 'users' ? [{ header: t('User') }, { header: t('State') }]
    : kind === 'organizations' ? [{ header: t('Organization') }, { header: t('Status') }]
      : kind === 'applications' ? [{ header: t('Application') }, { header: t('Redirect URIs'), hideBelow: 'md' }, { header: t('Status') }]
        : kind === 'resources' ? [{ header: t('Resource') }, { header: t('Prefix'), hideBelow: 'sm' }, { header: t('Audience'), hideBelow: 'lg' }, { header: t('Scopes'), hideBelow: 'md' }]
          : kind === 'roles' ? [{ header: t('Role') }, { header: t('Resource'), hideBelow: 'sm' }, { header: t('Permissions'), hideBelow: 'md' }]
            : [{ header: t('User') }, { header: t('Resource / Permissions') }]
  const cells = (row: Entity): ReactNode[] => {
    switch (kind) {
      case 'users': return [<span className="flex min-w-0 items-center gap-3"><Avatar src={row.avatar_url} name={row.name || row.email} />{row.kind === 'machine' ? name(row, <span className="flex items-center gap-2 text-xs text-muted-foreground"><Badge variant="outline" className="gap-1"><Bot className="size-3" /> {t('Machine')}</Badge><CopyText value={row.id} short label={t('Copy user ID')} /></span>) : name(row, row.username ? `${row.email} · @${row.username}` : row.email)}</span>, <UserState state={row.state} active={!!row.active} />]
      case 'organizations': return [name(row), <Status active={row.active !== false} />]
      case 'applications': return [name(row), <RedirectList uris={row.redirect_uris ?? null} />, <Status active={!!row.active} />]
      case 'resources': return [name(row, <span className="block truncate text-xs text-muted-foreground">{row.audience}</span>), <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">{row.prefix}</code>, <span className="break-all text-sm">{row.audience}</span>, permissions(row)]
      case 'roles': return [name(row), <span className="text-sm">{row.resource_name || '—'}</span>, permissions(row)]
      case 'grants': return [<EntityRef name={row.user_name} id={row.user_id} to={`${envBase}/users/${row.user_id}`} secondary={rich('in {{organization}}', { organization: <Link to={`${envBase}/organizations/${row.organization_id}`} className="hover:underline">{row.organization_name || t('organization')}</Link> })} />, <div className="space-y-1"><p className="text-sm">{row.resource_name}</p>{permissions(row)}</div>]
    }
  }
  const actions = (row: Entity): Action[] => {
    const open = detail(row)
    const out: Action[] = open ? [{ label: kind === 'users' ? t('View profile') : t('Open'), icon: <ArrowRight />, onSelect: () => navigate(open) }] : []
    if (!canWrite) return out
    if (kind === 'organizations') out.push({ label: t('Members'), icon: <Users />, onSelect: () => navigate(`${envBase}/organizations/${row.id}/members`) })
    if (kind === 'roles' && row.system_role) return out
    // The IAM resource's catalog is built in (the API refuses edits).
    if (kind === 'resources' && row.prefix === 'iam') return out
    if (kind !== 'organizations' && kind !== 'users') out.push({ label: t('Edit'), icon: <Pencil />, onSelect: () => openEdit(row) })
    if (kind === 'users') {
      out.push({ label: t('Edit'), icon: <Pencil />, onSelect: () => openEdit(row) })
      if (row.active) out.push({ label: t('Suspend'), icon: <UserX />, onSelect: () => setRemove(row) })
      out.push({ label: t('Delete permanently'), icon: <Trash2 />, destructive: true, onSelect: () => setPurge(row) })
    }
    if (kind === 'roles' || kind === 'grants') out.push({ label: kind === 'roles' ? t('Delete role') : t('Revoke grant'), icon: <Trash2 />, destructive: true, onSelect: () => setRemove(row) })
    return out
  }
  const create = canWrite && <Button onClick={() => setEdit('new')}><Plus />{kind === 'grants' ? t('Grant permissions') : creates[kind]}</Button>
  return <div className="space-y-6">
    <PageHeader title={titles[kind]} description={descriptions[kind]} actions={<>
      {kind === 'roles' && <Link to={`${envBase}/role-assignments`} className={buttonVariants({ variant: 'outline' })}><Eye className="size-4" /> {t('View assignments')}</Link>}
      {kind === 'roles' && canWrite && <Button variant="outline" onClick={() => setAssign(true)}><ShieldCheck /> {t('Assign role')}</Button>}
      {kind === 'users' && canWrite && <Button variant="outline" onClick={() => setMachine(true)}><Bot /> {t('Create machine user')}</Button>}
      {create}
    </>} />
    <PaginationBar state={list} noun={kind} placeholder={searches[kind]} />
    {kind === 'users' && <div className="flex flex-wrap gap-2">
      <select aria-label={t('Filter by state')} className="h-8 rounded-md border border-input bg-background px-2 text-sm" value={state} onChange={e => setState(e.target.value)}>
        <option value="">{t('All states')}</option>
        {userStates.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <select aria-label={t('Filter by kind')} className="h-8 rounded-md border border-input bg-background px-2 text-sm" value={userKind} onChange={e => setUserKind(e.target.value)}>
        <option value="">{t('People and machines')}</option>
        <option value="human">{t('People')}</option>
        <option value="machine">{t('Machine users')}</option>
      </select>
    </div>}
    <DataTable
      columns={[...columns, t('Actions')]}
      loading={list.loading} error={list.error} retry={list.reload}
      rowHref={kind === 'users' || kind === 'organizations' || kind === 'applications' || kind === 'resources' ? i => detail(list.data[i])! : undefined}
      empty={list.search ? <EmptyState title={t('Nothing matches “{{search}}”.', { search: list.search })} /> : <EmptyState icon={icons[kind]} title={empties[kind][0]} description={empties[kind][1]} action={create} />}
      rows={list.data.map(row => [...cells(row), <RowActions label={t('Actions for {{label}}', { label: label(row) })} actions={actions(row)} />])} />
    {edit && kind === 'roles' && <RoleForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind === 'grants' && <GrantForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind !== 'roles' && kind !== 'grants' && <FormDialog title={edit === 'new' ? creates[kind] : t('Edit {{label}}', { label: label(edit) })} description={kind === 'resources' && edit !== 'new' ? t('Removing scopes also removes those permissions from grants, roles, and service accounts.') : createHints[kind]} submitLabel={edit === 'new' ? t('Create') : t('Save')} success={saved[kind][edit === 'new' ? 0 : 1]} fields={fieldsFor(kind, base, edit === 'new' ? undefined : edit)} onClose={() => setEdit(null)} submit={async values => {
      const data: Record<string, unknown> = { ...values }
      for (const field of ['permissions', 'redirect_uris']) if (field in values) data[field] = splitList(values[field])
      if ('metadata' in values) {
        if (values.metadata) try { data.metadata = JSON.parse(String(values.metadata)) } catch { throw new Error(t('Metadata must be valid JSON')) }
        else delete data.metadata
      }
      if (edit === 'new') {
        if (kind === 'users' && !String(values.username ?? '').trim()) delete data.username
        const created = await api.post<{ id?: string }>(path, data)
        list.reload()
        // Users and organizations are configured on their own page.
        if (created?.id && (kind === 'users' || kind === 'organizations')) navigate(`${envBase}/${kind}/${created.id}`)
        return
      }
      if (kind === 'resources') await api.put(`${path}/${edit.id}`, data)
      else await api.patch(`${path}/${edit.id}`, data)
      list.reload()
    }} />}
    {remove && (kind === 'users'
      ? <ConfirmDialog title={t('Suspend {{label}}?', { label: label(remove) })} description={t('They can no longer sign in and their sessions stop refreshing. You can reactivate them from their page.')} confirmLabel={t('Suspend')} onClose={() => setRemove(null)} confirm={async () => { await api.post(`${path}/${remove.id}/deactivate`); toast.success(t('User suspended')); list.reload() }} />
      : <ConfirmDialog title={kind === 'roles' ? t('Delete role {{label}}?', { label: label(remove) }) : t('Revoke {{user}}’s grant?', { user: remove.user_name ?? t('this user') })} description={kind === 'roles' ? t('Everyone holding this role, directly or through a group, loses its permissions at their next token. This cannot be undone.') : t('{{user}} loses these {{resource}} permissions in {{organization}} at their next token.', { user: remove.user_name ?? t('The user'), resource: remove.resource_name ?? '', organization: remove.organization_name ?? t('the organization') })} confirmLabel={kind === 'roles' ? t('Delete role') : t('Revoke grant')} onClose={() => setRemove(null)} confirm={async () => { await api.delete(`${path}/${remove.id}`); toast.success(kind === 'roles' ? t('Role deleted') : t('Grant revoked')); list.reload() }} />)}
    {purge && <ConfirmDialog title={t('Permanently delete {{label}}?', { label: label(purge) })} description={t('This erases {{label}} and every session, membership, grant, role assignment, and linked identity for them in this environment. This cannot be undone.', { label: label(purge) })} confirmLabel={t('Delete permanently')} confirmationText={label(purge)} onClose={() => setPurge(null)} confirm={async () => { await api.delete(`${path}/${purge.id}/permanent`); toast.success(t('User deleted')); list.reload() }} />}
    {assign && <AssignRoleDialog base={base} onClose={() => setAssign(false)} />}
    {machine && <FormDialog title={t('Create machine user')} description={t('A user for scripts and integrations: no email, password or second factor. Add it to organizations and give it roles like a person, then create personal access tokens on its page.')} submitLabel={t('Create')} success={t('Machine user created')} fields={[
      { name: 'name', label: t('Name'), hint: t('e.g. billing-sync') },
      { name: 'home_organization_id', label: t('Home organization'), type: 'select', optional: true, selectPath: `${base}/organizations`, selectMap: item => ({ id: String(item.id), label: String(item.name || item.id) }), hint: t('Optional. The machine user joins it, and its administrators may manage the record.') },
    ]} onClose={() => setMachine(false)} submit={async values => {
      const data: Record<string, unknown> = { kind: 'machine', name: String(values.name ?? '').trim() }
      if (values.home_organization_id) data.home_organization_id = values.home_organization_id
      const created = await api.post<{ id?: string }>(path, data)
      list.reload()
      if (created?.id) navigate(`${envBase}/users/${created.id}`)
    }} />}
  </div>
}
