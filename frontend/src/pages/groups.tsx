import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Eye, Pencil, Plus, Trash2, UserMinus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, ErrorState, FormDialog, ID, PageHeader, Status } from '@/components/library/patterns'

export interface Group {
  id: string; name: string; description: string
  connection_id: string | null; external_id?: string
  member_count: number; created_at: string; updated_at: string
}
interface GroupMember { user_id: string; user_name: string; user_email: string; active: boolean; added_at: string }
interface GroupRole {
  group_id: string; group_name: string; organization_id: string
  resource_id: string; resource_name: string; role_id: string; role_name: string
}

/** Directory badge: groups owned by a SCIM connection are read-only here. */
export function DirectoryBadge({ group }: { group: Pick<Group, 'connection_id'> }) {
  if (!group.connection_id) return null
  return <Badge variant="secondary" className="bg-primary/10 text-primary" title={`Managed by provisioning connection ${group.connection_id}`}>Directory</Badge>
}

function useOrgName(base: string, orgId?: string) {
  const [name, setName] = useState('')
  useEffect(() => {
    if (!orgId) return
    api.get<{ name: string }>(`${base}/organizations/${orgId}`).then(o => setName(o.name)).catch(() => {})
  }, [base, orgId])
  return name
}

function BackLink({ to, label }: { to: string; label: string }) {
  return <Link to={to} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
    <ArrowLeft className="size-3.5" />{label}
  </Link>
}

export function GroupsPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/groups`
  const envBase = `/projects/${project}/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const orgName = useOrgName(base, orgId)
  const list = usePaginatedList<Group>(path)
  const [editing, setEditing] = useState<Group | 'new' | null>(null)
  const [removing, setRemoving] = useState<Group | null>(null)

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={`${envBase}/organizations/${orgId}/members`} label="Back to members" />
      <PageHeader
        title={orgName ? `Groups of ${orgName}` : 'Groups'}
        description="Roles bound to a group apply to every member. Directory groups are managed by SCIM; you can still bind roles to them."
        actions={canWrite && <Button onClick={() => setEditing('new')}><Plus />Create group</Button>}
      />
    </div>

    <PaginationBar state={list} noun="groups" placeholder="Search groups…" />

    <DataTable
      columns={['Name / ID', 'Description', 'Members', 'Source', 'Actions']}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rows={list.data.map(g => [
        <div className="space-y-1"><Link to={`${envBase}/organizations/${orgId}/groups/${g.id}`} className="font-medium hover:underline">{g.name}</Link><ID value={g.id} /></div>,
        <span className="text-sm text-muted-foreground">{g.description || '—'}</span>,
        <span className="text-sm">{g.member_count}</span>,
        g.connection_id ? <DirectoryBadge group={g} /> : <span className="text-xs text-muted-foreground">Manual</span>,
        <div className="flex gap-1">
          <Link to={`${envBase}/organizations/${orgId}/groups/${g.id}`} className={buttonVariants({ variant: 'ghost', size: 'icon' })} aria-label={`Details of ${g.name}`}><Eye className="size-4" /></Link>
          {canWrite && !g.connection_id && <>
            <Button variant="ghost" size="icon" aria-label={`Edit ${g.name}`} onClick={() => setEditing(g)}><Pencil /></Button>
            <Button variant="ghost" size="icon" aria-label={`Delete ${g.name}`} onClick={() => setRemoving(g)}><Trash2 /></Button>
          </>}
        </div>,
      ])}
    />

    {editing && <GroupForm path={path} group={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={list.reload} />}
    {removing && <ConfirmDialog
      title="Delete group?"
      description={`"${removing.name}" and its role bindings will be deleted. Its ${removing.member_count} member(s) lose the roles granted through it.`}
      confirmLabel="Delete"
      onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success('Group deleted'); list.reload() }}
    />}
  </div>
}

function GroupForm({ path, group, onClose, onSaved }: { path: string; group: Group | null; onClose: () => void; onSaved: () => void }) {
  return <FormDialog
    title={group ? 'Edit group' : 'Create group'}
    description={group ? group.id : 'Group names are unique within the organization.'}
    fields={[
      { name: 'name', label: 'Name', value: group?.name ?? '' },
      { name: 'description', label: 'Description', optional: true, value: group?.description ?? '' },
    ]}
    onClose={onClose}
    submit={async data => {
      const body = { name: data.name, description: data.description }
      if (group) await api.patch(`${path}/${group.id}`, body)
      else await api.post(path, body)
      onSaved()
    }}
  />
}

export function GroupDetailPage() {
  const { project, environment, orgId, groupId } = useParams()
  const base = `/environments/${environment}`
  const orgPath = `${base}/organizations/${orgId}`
  const path = `${orgPath}/groups/${groupId}`
  const envBase = `/projects/${project}/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [group, setGroup] = useState<Group | null>(null)
  const [loadError, setLoadError] = useState('')
  const [version, setVersion] = useState(0)
  const members = usePaginatedList<GroupMember>(`${path}/members`)
  const roleParams = useMemo(() => ({ organization_id: orgId ?? '', group_id: groupId ?? '' }), [orgId, groupId])
  const roles = usePaginatedList<GroupRole>(`${base}/group-role-assignments`, { extraParams: roleParams })
  const [adding, setAdding] = useState(false)
  const [binding, setBinding] = useState(false)
  const [removingMember, setRemovingMember] = useState<GroupMember | null>(null)
  const [unbinding, setUnbinding] = useState<GroupRole | null>(null)

  useEffect(() => {
    api.get<Group>(path).then(setGroup).catch(e => setLoadError(message(e)))
  }, [path, version])
  const refresh = () => { setVersion(v => v + 1); members.reload() }

  if (loadError) return <ErrorState error={loadError} />
  if (!group) return <div role="status" className="py-8 text-sm text-muted-foreground">Loading group…</div>
  const managed = !!group.connection_id

  return <div className="space-y-8">
    <div className="space-y-3">
      <BackLink to={`${envBase}/organizations/${orgId}/groups`} label="Back to groups" />
      <PageHeader title={group.name} description={group.description || group.id} actions={<DirectoryBadge group={group} />} />
      {managed && <p className="text-sm text-muted-foreground">
        This group is managed by a provisioning directory{group.external_id ? <> (external id <code className="font-mono text-xs">{group.external_id}</code>)</> : null}. Its name and members are synced by SCIM; roles are managed here.
      </p>}
    </div>

    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-mono text-lg font-semibold">Roles</h2>
          <p className="text-sm text-muted-foreground">Every member holds these roles in addition to their direct roles.</p>
        </div>
        {canWrite && <Button variant="outline" onClick={() => setBinding(true)}><Plus className="size-4" /> Assign role</Button>}
      </div>
      <DataTable
        columns={['Role', 'Resource', ...(canWrite ? ['Actions'] : [])]}
        loading={roles.loading}
        error={roles.error}
        retry={roles.reload}
        rows={roles.data.map(r => {
          const cells: React.ReactNode[] = [
            <div className="space-y-1"><p className="font-medium">{r.role_name}</p><ID value={r.role_id} /></div>,
            <span className="text-sm">{r.resource_name}</span>,
          ]
          if (canWrite) cells.push(<Button variant="ghost" size="icon" aria-label={`Unassign ${r.role_name}`} onClick={() => setUnbinding(r)}><Trash2 className="size-4" /></Button>)
          return cells
        })}
      />
    </section>

    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-mono text-lg font-semibold">Members</h2>
          <p className="text-sm text-muted-foreground">Active organization members only. Removing someone from the organization removes them from its groups.</p>
        </div>
        {canWrite && !managed && <Button variant="outline" onClick={() => setAdding(true)}><Plus className="size-4" /> Add member</Button>}
      </div>
      <PaginationBar state={members} noun="members" placeholder="Search members…" />
      <DataTable
        columns={['User', 'Email', 'Status', ...(canWrite && !managed ? ['Actions'] : [])]}
        loading={members.loading}
        error={members.error}
        retry={members.reload}
        rows={members.data.map(m => {
          const cells: React.ReactNode[] = [
            <div className="space-y-1"><p className="font-medium">{m.user_name}</p><ID value={m.user_id} /></div>,
            <span className="text-sm">{m.user_email}</span>,
            <Status active={m.active} />,
          ]
          if (canWrite && !managed) cells.push(<Button variant="ghost" size="icon" aria-label={`Remove ${m.user_name}`} onClick={() => setRemovingMember(m)}><UserMinus className="size-4" /></Button>)
          return cells
        })}
      />
    </section>

    {adding && <PickDialog
      title="Add member"
      description={`Add an active member of the organization to ${group.name}.`}
      label="Member"
      path={`${orgPath}/members`}
      mapItem={item => ({ id: String(item.user_id), label: `${item.user_name} (${item.user_email})`, inactive: item.active === false })}
      onClose={() => setAdding(false)}
      submit={async user => { await api.post(`${path}/members`, { add: [user] }); toast.success('Member added'); refresh() }}
    />}
    {binding && <PickDialog
      title="Assign role"
      description={`Members of ${group.name} will receive this role.`}
      label="Role"
      path={`${base}/roles`}
      mapItem={item => ({ id: String(item.id), label: item.resource_name ? `${item.name} (${item.resource_name})` : String(item.name) })}
      onClose={() => setBinding(false)}
      submit={async role => { await api.post(`${base}/group-role-assignments`, { role_id: role, organization_id: orgId, group_id: groupId }); toast.success('Role assigned'); roles.reload() }}
    />}
    {removingMember && <ConfirmDialog
      title="Remove member?"
      description={`${removingMember.user_name} loses the roles granted through ${group.name}. Direct roles are not affected.`}
      confirmLabel="Remove"
      onClose={() => setRemovingMember(null)}
      confirm={async () => { await api.post(`${path}/members`, { remove: [removingMember.user_id] }); refresh() }}
    />}
    {unbinding && <ConfirmDialog
      title="Unassign role?"
      description={`Members of ${group.name} lose "${unbinding.role_name}" unless they hold it directly or through another group.`}
      confirmLabel="Unassign"
      onClose={() => setUnbinding(null)}
      confirm={async () => { await api.delete(`${base}/group-role-assignments/${unbinding.role_id}/${orgId}/${groupId}`); roles.reload() }}
    />}
  </div>
}

/** Single-choice dialog backed by a searchable server list. */
function PickDialog({ title, description, label, path, mapItem, submit, onClose }: {
  title: string; description: string; label: string; path: string
  mapItem: (item: Record<string, unknown>) => { id: string; label: string; inactive?: boolean }
  submit: (id: string) => Promise<void>; onClose: () => void
}) {
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">{title}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
      <div className="space-y-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{label}</label>
          <SearchSelect name="pick" path={path} mapItem={mapItem} disabled={busy} placeholder={`Search ${label.toLowerCase()}s…`} onChange={setValue} />
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button disabled={busy || !value} onClick={async () => {
            setBusy(true); setError('')
            try { await submit(value); onClose() } catch (e) { setError(message(e)) } finally { setBusy(false) }
          }}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
}
