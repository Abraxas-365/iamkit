import { useId, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Plus, Pencil, Trash2, Link as LinkIcon, Eye } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { CollapsibleScopes } from '@/components/ui/collapsible-scopes'
import { PermissionPicker } from '@/components/ui/permission-picker'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, FormDialog, ID, PageHeader, Status, splitList } from '@/components/library/patterns'
import type { Field } from '@/components/library/patterns'

type Kind = 'users' | 'organizations' | 'applications' | 'resources' | 'roles' | 'grants'

interface Entity {
  id: string; name?: string; email?: string; active?: boolean; prefix?: string; audience?: string;
  permissions?: string[]; redirect_uris?: string[]; resource_id?: string; resource_name?: string;
  organization_id?: string; organization_name?: string; user_id?: string; user_name?: string;
  otp_enabled?: boolean; metadata?: Record<string, unknown>;
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
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id) })
function fieldsFor(kind: Kind, _base: string, row?: Entity): Field[] {
  const name: Field = { name: 'name', label: 'Name', value: row?.name }
  const permissionTags: Field = { name: 'permissions', label: 'Permissions', type: 'tags', optional: true, tags: row?.permissions ?? [], prefix: row?.prefix, hint: row?.prefix ? `Type an action and press Enter. Auto-prefixed as ${row.prefix}:action.` : 'Define the prefix first — permissions will use it as a namespace.' }
  switch (kind) {
    case 'users': return row ? [name, { name: 'active', label: 'Active', type: 'checkbox', value: row.active }, { name: 'otp_enabled', label: 'Enable one-time password login', type: 'checkbox', value: row.otp_enabled }, { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: 'Arbitrary JSON object, e.g. {"team":"billing"}' }] : [name, { name: 'email', label: 'Email', type: 'email' }, { name: 'password', label: 'Initial password', type: 'password', optional: true, hint: 'Optional; 12–72 bytes when supplied.' }, { name: 'otp_enabled', label: 'Enable one-time password login', type: 'checkbox' }]
    case 'organizations': return row ? [name, { name: 'active', label: 'Active', type: 'checkbox', value: row.active }, { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: row.metadata ? JSON.stringify(row.metadata) : '', hint: 'Arbitrary JSON object.' }] : [name]
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
        toast.success('Saved successfully'); onSaved(); onClose()
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
        toast.success('Saved successfully'); onSaved(); onClose()
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
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [edit, setEdit] = useState<Entity | 'new' | null>(null)
  const openEdit = async (row: Entity) => {
    if (kind === 'users' || kind === 'organizations') {
      try { const full = await api.get<Entity>(`${path}/${row.id}`); setEdit(full) } catch { setEdit(row) }
    } else { setEdit(row) }
  }
  const [remove, setRemove] = useState<Entity | null>(null)
  const [extra, setExtra] = useState(false)
  const extraConfig = kind === 'applications' ? { title: 'Link resource', path: '/application-resources', fields: [
    { name: 'application_id', label: 'Application', type: 'select' as const, selectPath: `${base}/applications`, selectMap: named },
    { name: 'resource_id', label: 'Resource', type: 'select' as const, selectPath: `${base}/resources`, selectMap: named },
  ] } :
    kind === 'organizations' ? { title: 'Add member', path: '/memberships', fields: [
      { name: 'organization_id', label: 'Organization', type: 'select' as const, selectPath: `${base}/organizations`, selectMap: named },
      { name: 'user_id', label: 'User', type: 'select' as const, selectPath: `${base}/users`, selectMap: named },
    ] } :
      kind === 'roles' ? { title: 'Assign role', path: '/role-assignments', fields: [
        { name: 'organization_id', label: 'Organization', type: 'select' as const, selectPath: `${base}/organizations`, selectMap: named },
        { name: 'user_id', label: 'User', type: 'select' as const, selectPath: `${base}/users`, selectMap: named },
        { name: 'role_id', label: 'Role', type: 'select' as const, selectPath: `${base}/roles`, selectMap: named },
      ] } : null
  const columns = kind === 'users' ? ['Name / ID', 'Email', 'Status'] : kind === 'applications' ? ['Name / ID', 'Redirect URIs', 'Status'] : kind === 'resources' ? ['Name / ID', 'Prefix', 'Audience', 'Scopes'] : kind === 'roles' ? ['Name / ID', 'Resource', 'Permissions'] : kind === 'grants' ? ['Grant ID', 'Organization / User', 'Resource / Permissions'] : ['Name', 'ID']
  const canDelete = kind === 'users' || kind === 'roles' || kind === 'grants'
  return <div className="space-y-6">
    <PageHeader title={titles[kind]} description={descriptions[kind]} actions={canWrite && <div className="flex flex-wrap gap-2">
      {kind === 'roles' && <Link to={`${envBase}/role-assignments`} className={buttonVariants({ variant: 'outline' })}><Eye className="size-4" /> View assignments</Link>}
      {extraConfig && <Button variant="outline" onClick={() => setExtra(true)}><LinkIcon />{extraConfig.title}</Button>}
      <Button onClick={() => setEdit('new')}><Plus />{kind === 'grants' ? 'Set grant' : 'Create'}</Button>
    </div>} />
    <PaginationBar state={list} noun={kind} placeholder={`Search ${titles[kind].toLowerCase()}…`} />
    <DataTable columns={[...columns, ...(canWrite ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(row => {
      const identity = <div className="space-y-1"><p className="font-medium">{row.name}{kind === 'resources' && row.prefix === 'iam' && <span className="ml-2 inline-block rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">System</span>}</p><ID value={row.id} /></div>
      const permissions = row.permissions?.length ? <CollapsibleScopes key={row.id} scopes={row.permissions} /> : <span className="text-xs text-muted-foreground">No permissions</span>
      const cells = kind === 'users' ? [identity, row.email, <Status active={!!row.active} />] :
        kind === 'applications' ? [identity, <span className="text-xs">{row.redirect_uris?.join(', ') || '—'}</span>, <Status active={!!row.active} />] :
          kind === 'resources' ? [identity, <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">{row.prefix}</code>, row.audience, permissions] :
            kind === 'roles' ? [identity, <span className="text-sm">{row.resource_name || <ID value={row.resource_id!} />}</span>, permissions] :
              kind === 'grants' ? [<ID value={row.id} />, <div className="space-y-1"><p className="text-sm">{row.organization_name || <ID value={row.organization_id!} />}</p><p className="text-sm">{row.user_name || <ID value={row.user_id!} />}</p></div>, <div><p className="text-sm">{row.resource_name || <ID value={row.resource_id!} />}</p>{permissions}</div>] : [row.name, <ID value={row.id} />]
      if (canWrite) cells.push(<div className="flex gap-1">
        {kind === 'organizations' && <Link to={`${envBase}/organizations/${row.id}/members`} className={buttonVariants({ variant: 'ghost', size: 'icon' })} aria-label={`Members of ${row.name}`}><Eye className="size-4" /></Link>}
        {kind === 'applications' && <Link to={`${envBase}/applications/${row.id}`} className={buttonVariants({ variant: 'ghost', size: 'icon' })} aria-label={`Details of ${row.name}`}><Eye className="size-4" /></Link>}
        <Button variant="ghost" size="icon" aria-label={`Edit ${row.name || row.id}`} onClick={() => openEdit(row)}><Pencil /></Button>
        {canDelete && <Button variant="ghost" size="icon" aria-label={`${kind === 'users' ? 'Suspend' : 'Delete'} ${row.name || row.id}`} onClick={() => setRemove(row)}><Trash2 /></Button>}
      </div>)
      return cells
    })} />
    {edit && kind === 'roles' && <RoleForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind === 'grants' && <GrantForm base={base} row={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    {edit && kind !== 'roles' && kind !== 'grants' && <FormDialog title={edit === 'new' ? `Create ${kind === 'resources' ? 'resource' : kind.slice(0, -1)}` : 'Edit configuration'} description={kind === 'resources' && edit !== 'new' ? 'Removing scopes also removes those permissions from grants, roles, and service accounts.' : 'Changes apply only to this environment. IDs are available in the corresponding list screens.'} fields={fieldsFor(kind, base, edit === 'new' ? undefined : edit)} onClose={() => setEdit(null)} submit={async values => {
      const data: Record<string, unknown> = { ...values }
      for (const field of ['permissions', 'redirect_uris']) if (field in values) data[field] = splitList(values[field])
      if ('metadata' in values && values.metadata) try { data.metadata = JSON.parse(String(values.metadata)) } catch { /* send raw */ }
      if (edit === 'new') await api.post(path, data)
      else if (kind === 'resources') await api.put(`${path}/${edit.id}`, data)
      else await api.patch(`${path}/${edit.id}`, data)
      list.reload()
    }} />}
    {remove && <ConfirmDialog title={kind === 'users' ? 'Suspend user?' : 'Delete access configuration?'} description={`This affects ${remove.name || remove.id} in the current environment. ${kind === 'users' ? 'You can reactivate the user by editing their status.' : 'This action cannot be undone.'}`} onClose={() => setRemove(null)} confirm={async () => { await api.delete(`${path}/${remove.id}`); list.reload() }} />}
    {extra && extraConfig && <FormDialog title={extraConfig.title} description="Enter the IDs from this environment's list screens." fields={extraConfig.fields} onClose={() => setExtra(false)} submit={async values => { await api.post(`${base}${extraConfig.path}`, values) }} />}
  </div>
}
