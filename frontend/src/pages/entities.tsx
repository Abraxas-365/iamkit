import { useId, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { AppWindow, ArrowRight, Building2, Eye, KeyRound, Pencil, Plus, ShieldCheck, Tags, Trash2, UserX, Users } from 'lucide-react'
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
import { RedirectList } from './integrations'

type Kind = 'users' | 'organizations' | 'applications' | 'resources' | 'roles' | 'grants'

interface Entity {
  id: string; name?: string; email?: string; active?: boolean; prefix?: string; audience?: string;
  permissions?: string[]; redirect_uris?: string[]; resource_id?: string; resource_name?: string;
  organization_id?: string; organization_name?: string; user_id?: string; user_name?: string;
  otp_enabled?: boolean; metadata?: Record<string, unknown>; mfa_required?: boolean; mfa_for_federated?: boolean;
}
const descriptions: Record<Kind, string> = {
  users: 'Manage end-user identities in this environment.',
  organizations: 'Tenant organizations and their memberships.',
  applications: 'Applications that authenticate users and request access to resources.',
  resources: 'API audiences and their permission catalogs (scopes).',
  roles: 'Reusable sets of resource permissions for organization members.',
  grants: 'Direct resource permissions granted to users within an organization.',
}
const titles: Record<Kind, string> = { users: 'Users', organizations: 'Organizations', applications: 'Applications', resources: 'Resources & scopes', roles: 'Roles', grants: 'Grants' }
const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
const singular: Record<Kind, string> = { users: 'user', organizations: 'organization', applications: 'application', resources: 'resource', roles: 'role', grants: 'grant' }
const icons: Record<Kind, ReactNode> = { users: <Users />, organizations: <Building2 />, applications: <AppWindow />, resources: <KeyRound />, roles: <Tags />, grants: <ShieldCheck /> }
const empties: Record<Kind, [string, string]> = {
  users: ['No users yet', 'Create users here, invite them to an organization, or let them sign up through social login or SCIM.'],
  organizations: ['No organizations yet', 'Organizations are your customers or teams. Users sign in to an organization and get roles within it.'],
  applications: ['No applications yet', 'An application is a product your users sign in to — a web app, mobile app or CLI.'],
  resources: ['No resources yet', 'A resource is an API your applications call. Define its permissions (scopes) here.'],
  roles: ['No roles yet', 'Roles bundle permissions of a resource so you can give them to members in one step.'],
  grants: ['No direct grants', 'Grants give one user permissions within an organization without a role. Prefer roles for anything you repeat.'],
}
const createHints: Record<Kind, string> = {
  users: 'You can add the user to organizations on the next page.',
  organizations: 'You can add members, SSO and domains on the next page.',
  applications: 'Link resources and create OAuth clients for it afterwards.',
  resources: 'The prefix namespaces every permission of this resource.',
  roles: '', grants: '',
}
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id), inactive: item.active === false })
function fieldsFor(kind: Kind, _base: string, row?: Entity): Field[] {
  const name: Field = { name: 'name', label: 'Name', value: row?.name }
  const permissionTags: Field = { name: 'permissions', label: 'Permissions', type: 'tags', optional: true, tags: row?.permissions ?? [], prefix: row?.prefix, hint: row?.prefix ? `Type an action and press Enter. Auto-prefixed as ${row.prefix}:action.` : 'Define the prefix first — permissions will use it as a namespace.' }
  switch (kind) {
    case 'users': return row ? [name, { name: 'active', label: 'Active', type: 'checkbox', value: row.active }, { name: 'otp_enabled', label: 'Enable one-time password login', type: 'checkbox', value: row.otp_enabled }, { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: 'Arbitrary JSON object, e.g. {"team":"billing"}' }] : [name, { name: 'email', label: 'Email', type: 'email' }, { name: 'password', label: 'Initial password', type: 'password', optional: true, hint: 'Leave blank for OTP-only or OAuth login. If set, must be 12–72 characters long.' }, { name: 'otp_enabled', label: 'Enable one-time password login', type: 'checkbox' }]
    case 'organizations': return row ? [name, { name: 'active', label: 'Active', type: 'checkbox', value: row.active }, { name: 'mfa_required', label: 'Require a second factor', type: 'checkbox', value: row.mfa_required, hint: 'Password and email-code sign-ins need an authenticator app; members without one enroll while signing in.' }, { name: 'mfa_for_federated', label: 'Also require it for SSO sign-ins', type: 'checkbox', value: row.mfa_for_federated, hint: 'By default the identity provider is trusted to have done its own MFA.' }, { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: 'Arbitrary JSON object.' }] : [name]
    case 'applications': return [name, { name: 'redirect_uris', label: 'Redirect URIs', type: 'tags', optional: true, tags: row?.redirect_uris ?? [], hint: 'Type a redirect URI and press Enter.' }, ...(row ? [{ name: 'active', label: 'Active', type: 'checkbox' as const, value: row.active }] : [])]
    case 'resources': {
      const createPerms: Field = { name: 'permissions', label: 'Permissions', type: 'tags', optional: true, tags: [], hint: 'Use prefix:action format (e.g. invoices:read). Must match the prefix above.' }
      return [name, ...(!row ? [{ name: 'prefix', label: 'Prefix', hint: 'Unique scope namespace (lowercase, e.g. invoices). All scopes must start with this prefix.' }, { name: 'audience', label: 'Audience' }, createPerms] : [permissionTags])]
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
    <DialogTitle className="pr-6 text-base font-semibold">{row ? 'Edit role' : 'Create role'}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{row ? 'Update role name and permissions.' : 'Name the role, pick a resource, and select permissions from its catalog.'}</DialogDescription>
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
        toast.success(row ? 'Role updated' : 'Role created'); onSaved(); onClose()
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-name`}>Name</label>
        <Input id={`${id}-name`} name="name" defaultValue={row?.name ?? ''} required disabled={busy} />
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-resource`}>Resource</label>
        {row ? (
          <>
            <input type="hidden" name="resource_id" value={row.resource_id} />
            <Input id={`${id}-resource`} value={row.resource_id} disabled className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">Resource cannot be changed on an existing role.</p>
          </>
        ) : (
          <SearchSelect id={`${id}-resource`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder="Search resource…" onChange={setResourceId} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium">Permissions</label>
        <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" defaultValue={row?.permissions} disabled={busy} />
      </div>
      {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</div>}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button></div>
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
    <DialogTitle className="pr-6 text-base font-semibold">{isEdit ? 'Edit grant' : 'Create grant'}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{isEdit ? 'Update this grant\'s permissions.' : 'Grant permissions on a resource to a user within an organization.'}</DialogDescription>
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
        toast.success(row ? 'Grant updated' : 'Grant saved'); onSaved(); onClose()
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-org`}>Organization</label>
        {isEdit ? (
          <>
            <input type="hidden" name="organization_id" value={row.organization_id} />
            <Input id={`${id}-org`} value={row.organization_id} disabled className="font-mono text-xs" />
          </>
        ) : (
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder="Search organization…" />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-user`}>User</label>
        {isEdit ? (
          <>
            <input type="hidden" name="user_id" value={row.user_id} />
            <Input id={`${id}-user`} value={row.user_id} disabled className="font-mono text-xs" />
          </>
        ) : (
          <SearchSelect id={`${id}-user`} name="user_id" path={`${base}/users`} mapItem={named} required disabled={busy} placeholder="Search user…" />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={`${id}-resource`}>Resource</label>
        {isEdit ? (
          <>
            <input type="hidden" name="resource_id" value={row.resource_id} />
            <Input id={`${id}-resource`} value={row.resource_id} disabled className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">Resource cannot be changed on an existing grant.</p>
          </>
        ) : (
          <SearchSelect id={`${id}-resource`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder="Search resource…" onChange={setResourceId} />
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm font-medium">Permissions</label>
        <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" defaultValue={row?.permissions} disabled={busy} />
      </div>
      {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</div>}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button></div>
    </form>
  </DialogContent></Dialog>
}

export default function EntitiesPage({ kind }: { kind: Kind }) {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const envBase = `/projects/${project}/environments/${environment}`
  const path = `${base}/${kind}`
  const list = usePaginatedList<Entity>(path)
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
  const detail = (row: Entity) => kind === 'users' ? `${envBase}/users/${row.id}` : kind === 'organizations' ? `${envBase}/organizations/${row.id}` : kind === 'applications' ? `${envBase}/applications/${row.id}` : undefined
  const name = (row: Entity, secondary?: ReactNode) => {
    const to = detail(row)
    return <span className="block min-w-0">
      <span className="flex flex-wrap items-center gap-2">{to ? <Link to={to} className="font-medium hover:text-primary hover:underline">{label(row)}</Link> : <span className="font-medium">{label(row)}</span>}{kind === 'resources' && row.prefix === 'iam' && <Badge variant="secondary" className="bg-primary/10 text-primary">System</Badge>}</span>
      {secondary ?? <CopyText value={row.id} short label={`Copy ${singular[kind]} ID`} />}
    </span>
  }
  const permissions = (row: Entity) => row.permissions?.length ? <CollapsibleScopes key={row.id} scopes={row.permissions} /> : <span className="text-xs text-muted-foreground">No permissions</span>
  const columns: Column[] = kind === 'users' ? [{ header: 'User' }, { header: 'Status' }]
    : kind === 'organizations' ? [{ header: 'Organization' }, { header: 'Status' }]
      : kind === 'applications' ? [{ header: 'Application' }, { header: 'Redirect URIs', hideBelow: 'md' }, { header: 'Status' }]
        : kind === 'resources' ? [{ header: 'Resource' }, { header: 'Prefix', hideBelow: 'sm' }, { header: 'Audience', hideBelow: 'lg' }, { header: 'Scopes', hideBelow: 'md' }]
          : kind === 'roles' ? [{ header: 'Role' }, { header: 'Resource', hideBelow: 'sm' }, { header: 'Permissions', hideBelow: 'md' }]
            : [{ header: 'User' }, { header: 'Resource / Permissions' }]
  const cells = (row: Entity): ReactNode[] => {
    switch (kind) {
      case 'users': return [name(row, row.email), <Status active={!!row.active} label={row.active ? 'Active' : 'Suspended'} />]
      case 'organizations': return [name(row), <Status active={row.active !== false} />]
      case 'applications': return [name(row), <RedirectList uris={row.redirect_uris ?? null} />, <Status active={!!row.active} />]
      case 'resources': return [name(row, <span className="block truncate text-xs text-muted-foreground">{row.audience}</span>), <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">{row.prefix}</code>, <span className="break-all text-sm">{row.audience}</span>, permissions(row)]
      case 'roles': return [name(row), <span className="text-sm">{row.resource_name || '—'}</span>, permissions(row)]
      case 'grants': return [<EntityRef name={row.user_name} id={row.user_id} to={`${envBase}/users/${row.user_id}`} secondary={<>in <Link to={`${envBase}/organizations/${row.organization_id}`} className="hover:underline">{row.organization_name || 'organization'}</Link></>} />, <div className="space-y-1"><p className="text-sm">{row.resource_name}</p>{permissions(row)}</div>]
    }
  }
  const actions = (row: Entity): Action[] => {
    const open = detail(row)
    const out: Action[] = open ? [{ label: kind === 'users' ? 'View profile' : 'Open', icon: <ArrowRight />, onSelect: () => navigate(open) }] : []
    if (!canWrite) return out
    if (kind === 'organizations') out.push({ label: 'Members', icon: <Users />, onSelect: () => navigate(`${envBase}/organizations/${row.id}/members`) })
    if (kind !== 'organizations' && kind !== 'users') out.push({ label: 'Edit', icon: <Pencil />, onSelect: () => openEdit(row) })
    if (kind === 'users') {
      out.push({ label: 'Edit', icon: <Pencil />, onSelect: () => openEdit(row) })
      if (row.active) out.push({ label: 'Suspend', icon: <UserX />, onSelect: () => setRemove(row) })
      out.push({ label: 'Delete permanently', icon: <Trash2 />, destructive: true, onSelect: () => setPurge(row) })
    }
    if (kind === 'roles' || kind === 'grants') out.push({ label: kind === 'roles' ? 'Delete role' : 'Revoke grant', icon: <Trash2 />, destructive: true, onSelect: () => setRemove(row) })
    return out
  }
  const create = canWrite && <Button onClick={() => setEdit('new')}><Plus />{kind === 'grants' ? 'Grant permissions' : `Create ${singular[kind]}`}</Button>
  return <div className="space-y-6">
    <PageHeader title={titles[kind]} description={descriptions[kind]} actions={<>
      {kind === 'roles' && <Link to={`${envBase}/role-assignments`} className={buttonVariants({ variant: 'outline' })}><Eye className="size-4" /> View assignments</Link>}
      {kind === 'roles' && canWrite && <Button variant="outline" onClick={() => setAssign(true)}><ShieldCheck /> Assign role</Button>}
      {create}
    </>} />
    <PaginationBar state={list} noun={kind} placeholder={`Search ${titles[kind].toLowerCase()}…`} />
    <DataTable
      columns={[...columns, 'Actions']}
      loading={list.loading} error={list.error} retry={list.reload}
      rowHref={kind === 'users' || kind === 'organizations' || kind === 'applications' ? i => detail(list.data[i])! : undefined}
      empty={list.search ? <EmptyState title={`No ${titles[kind].toLowerCase()} match “${list.search}”`} /> : <EmptyState icon={icons[kind]} title={empties[kind][0]} description={empties[kind][1]} action={create} />}
      rows={list.data.map(row => [...cells(row), <RowActions label={`Actions for ${label(row)}`} actions={actions(row)} />])} />
    {edit && kind === 'roles' && <RoleForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind === 'grants' && <GrantForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind !== 'roles' && kind !== 'grants' && <FormDialog title={edit === 'new' ? `Create ${singular[kind]}` : `Edit ${label(edit)}`} description={kind === 'resources' && edit !== 'new' ? 'Removing scopes also removes those permissions from grants, roles, and service accounts.' : createHints[kind]} submitLabel={edit === 'new' ? 'Create' : 'Save'} success={`${capital(singular[kind])} ${edit === 'new' ? 'created' : 'updated'}`} fields={fieldsFor(kind, base, edit === 'new' ? undefined : edit)} onClose={() => setEdit(null)} submit={async values => {
      const data: Record<string, unknown> = { ...values }
      for (const field of ['permissions', 'redirect_uris']) if (field in values) data[field] = splitList(values[field])
      if ('metadata' in values) {
        if (values.metadata) try { data.metadata = JSON.parse(String(values.metadata)) } catch { throw new Error('Metadata must be valid JSON') }
        else delete data.metadata
      }
      if (edit === 'new') {
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
      ? <ConfirmDialog title={`Suspend ${label(remove)}?`} description="They can no longer sign in and their sessions stop refreshing. You can reactivate them from their page." confirmLabel="Suspend" onClose={() => setRemove(null)} confirm={async () => { await api.delete(`${path}/${remove.id}`); toast.success('User suspended'); list.reload() }} />
      : <ConfirmDialog title={kind === 'roles' ? `Delete role ${label(remove)}?` : `Revoke ${remove.user_name ?? 'this user'}'s grant?`} description={kind === 'roles' ? 'Everyone holding this role, directly or through a group, loses its permissions at their next token. This cannot be undone.' : `${remove.user_name ?? 'The user'} loses these ${remove.resource_name ?? ''} permissions in ${remove.organization_name ?? 'the organization'} at their next token.`} confirmLabel={kind === 'roles' ? 'Delete role' : 'Revoke grant'} onClose={() => setRemove(null)} confirm={async () => { await api.delete(`${path}/${remove.id}`); toast.success(kind === 'roles' ? 'Role deleted' : 'Grant revoked'); list.reload() }} />)}
    {purge && <ConfirmDialog title={`Permanently delete ${label(purge)}?`} description={`This erases ${label(purge)} and every session, membership, grant, role assignment, and linked identity for them in this environment. This cannot be undone.`} confirmLabel="Delete permanently" confirmationText={label(purge)} onClose={() => setPurge(null)} confirm={async () => { await api.delete(`${path}/${purge.id}/permanent`); toast.success('User deleted'); list.reload() }} />}
    {assign && <AssignRoleDialog base={base} onClose={() => setAssign(false)} />}
  </div>
}
