import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Pencil, Plus, ShieldCheck, Tags, Trash2, UserMinus, Users } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { useOrganization } from './organization-layout'
import { BackLink, ConfirmDialog, DataTable, EmptyState, EntityRef, ErrorState, FormDialog, Status } from '@/components/library/patterns'
import { AssignRoleDialog } from '@/components/library/assign-role'
import { RowActions } from '@/components/ui/menu'

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

export function GroupsPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/groups`
  const envBase = `/projects/${project}/environments/${environment}`
  const navigate = useNavigate()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const { org } = useOrganization()
  const list = usePaginatedList<Group>(path)
  // Every role binding of the organization in one request (the API caps a page
  // at 100); groups beyond that page show "—" rather than a wrong "No roles".
  const roleParams = useMemo(() => ({ organization_id: orgId ?? '' }), [orgId])
  const bindings = usePaginatedList<GroupRole>(`${base}/group-role-assignments`, { extraParams: roleParams, limit: 100 })
  const rolesOf = useMemo(() => {
    const out = new Map<string, GroupRole[]>()
    for (const r of bindings.data) out.set(r.group_id, [...(out.get(r.group_id) ?? []), r])
    return out
  }, [bindings.data])
  const complete = !bindings.loading && !bindings.error && bindings.total <= bindings.data.length
  const [editing, setEditing] = useState<Group | 'new' | null>(null)
  const [removing, setRemoving] = useState<Group | null>(null)
  const [assigning, setAssigning] = useState<Group | null>(null)
  const detail = (g: Pick<Group, 'id'>) => `${envBase}/organizations/${orgId}/groups/${g.id}`

  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold">Groups of {org.name}</h2>
        <p className="max-w-2xl text-sm text-muted-foreground">Every member of a group holds the group's roles in {org.name}, in addition to their own. Directory groups are synced by SCIM; you still assign their roles here.</p>
      </div>
      {canWrite && <Button onClick={() => setEditing('new')}><Plus />Create group</Button>}
    </div>

    <PaginationBar state={list} noun="groups" placeholder="Search groups…" />

    <DataTable
      columns={['Group', { header: 'Roles', hideBelow: 'md' }, { header: 'Members', nowrap: true }, { header: 'Source', hideBelow: 'sm' }, ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rowHref={i => detail(list.data[i])}
      empty={<EmptyState icon={<Users />} title="No groups yet" description="Create a group, assign it roles, then add members: every member holds the group's roles." action={canWrite && <Button variant="outline" onClick={() => setEditing('new')}><Plus />Create group</Button>} />}
      rows={list.data.map(g => [
        <EntityRef name={g.name} id={g.id} to={detail(g)} secondary={g.description || undefined} />,
        <GroupRoles roles={rolesOf.get(g.id) ?? []} known={complete || rolesOf.has(g.id)} />,
        <span className="text-sm">{g.member_count}</span>,
        g.connection_id ? <DirectoryBadge group={g} /> : <span className="text-xs text-muted-foreground">Manual</span>,
        ...(canWrite ? [<RowActions label={`Actions for ${g.name}`} actions={[
          { label: 'Assign role', icon: <ShieldCheck />, onSelect: () => setAssigning(g) },
          ...(g.connection_id ? [] : [
            { label: 'Edit', icon: <Pencil />, onSelect: () => setEditing(g) },
            { label: 'Delete group', icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(g) },
          ]),
        ]} />] : []),
      ])}
    />

    {editing && <GroupForm path={path} group={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={id => { list.reload(); if (id) navigate(detail({ id })) }} />}
    {assigning && <AssignRoleDialog base={base} organization={org} group={assigning} onClose={() => setAssigning(null)} onAssigned={bindings.reload} />}
    {removing && <ConfirmDialog
      title={`Delete ${removing.name}?`}
      description={`Its role bindings are deleted too, and its ${removing.member_count === 1 ? 'member loses' : `${removing.member_count} members lose`} the roles granted through it. Direct roles are not affected.`}
      confirmLabel="Delete group"
      onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success('Group deleted'); list.reload(); bindings.reload() }}
    />}
  </div>
}

/** GroupRoles shows a group's first roles as badges, the rest as "+N". */
function GroupRoles({ roles, known }: { roles: GroupRole[]; known: boolean }) {
  if (!known) return <span className="text-sm text-muted-foreground">—</span>
  if (roles.length === 0) return <span className="text-xs text-muted-foreground">No roles</span>
  const shown = roles.slice(0, 3)
  return <span className="flex flex-wrap gap-1">
    {shown.map(r => <Badge key={r.role_id} variant="secondary" title={`${r.role_name} · ${r.resource_name}`}>{r.role_name}</Badge>)}
    {roles.length > shown.length && <Badge variant="outline" title={roles.slice(3).map(r => r.role_name).join(', ')}>+{roles.length - shown.length}</Badge>}
  </span>
}

function GroupForm({ path, group, onClose, onSaved }: { path: string; group: Group | null; onClose: () => void; onSaved: (created?: string) => void }) {
  return <FormDialog
    title={group ? `Edit ${group.name}` : 'Create group'}
    description={group ? 'Group names are unique within the organization.' : 'Group names are unique within the organization. Next, assign the group roles and add members.'}
    submitLabel={group ? 'Save' : 'Create group'}
    success={group ? 'Group updated' : 'Group created'}
    fields={[
      { name: 'name', label: 'Name', value: group?.name ?? '' },
      { name: 'description', label: 'Description', optional: true, value: group?.description ?? '' },
    ]}
    onClose={onClose}
    submit={async data => {
      const body = { name: data.name, description: data.description }
      if (group) { await api.patch(`${path}/${group.id}`, body); onSaved(); return }
      const created = await api.post<{ id?: string }>(path, body)
      onSaved(created?.id)
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
  const { org } = useOrganization()

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
    <div className="space-y-2">
      <BackLink to={`${envBase}/organizations/${orgId}/groups`}>All groups</BackLink>
      <div className="flex flex-wrap items-center gap-2"><h2 className="text-lg font-semibold">{group.name}</h2><DirectoryBadge group={group} /></div>
      {group.description && <p className="text-sm text-muted-foreground">{group.description}</p>}
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
      {(roles.hasPrev || roles.hasNext || roles.rawSearch !== '') && <PaginationBar state={roles} noun="roles" placeholder="Search roles…" />}
      <DataTable
        columns={['Role', 'Resource', ...(canWrite ? ['Actions'] : [])]}
        loading={roles.loading}
        error={roles.error}
        retry={roles.reload}
        empty={roles.rawSearch ? <EmptyState title="No roles match this search" /> : <EmptyState icon={<Tags />} title="No roles" description="Assign a role and every member of this group holds it." />}
        rows={roles.data.map(r => [
          <span className="font-medium">{r.role_name}</span>,
          <span className="text-sm">{r.resource_name}</span>,
          ...(canWrite ? [<RowActions label={`Actions for ${r.role_name}`} actions={[{ label: 'Unassign role', icon: <Trash2 />, destructive: true, onSelect: () => setUnbinding(r) }]} />] : []),
        ])}
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
        columns={['Member', 'Status', ...(canWrite && !managed ? ['Actions'] : [])]}
        loading={members.loading}
        error={members.error}
        retry={members.reload}
        empty={<EmptyState icon={<Users />} title="No members" description={managed ? 'Members are synced from the directory.' : 'Add organization members to give them this group\'s roles.'} />}
        rows={members.data.map(m => [
          <EntityRef name={m.user_name || m.user_email} id={m.user_id} to={`${envBase}/users/${m.user_id}`} secondary={m.user_name ? m.user_email : undefined} />,
          <Status active={m.active} />,
          ...(canWrite && !managed ? [<RowActions label={`Actions for ${m.user_name}`} actions={[{ label: 'Remove from group', icon: <UserMinus />, destructive: true, onSelect: () => setRemovingMember(m) }]} />] : []),
        ])}
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
    {binding && <AssignRoleDialog base={base} organization={org} group={group} onClose={() => setBinding(false)} onAssigned={roles.reload} />}
    {removingMember && <ConfirmDialog
      title={`Remove ${removingMember.user_name} from ${group.name}?`}
      description={`${removingMember.user_name} loses the roles granted through ${group.name}. Direct roles are not affected.`}
      confirmLabel="Remove"
      onClose={() => setRemovingMember(null)}
      confirm={async () => { await api.post(`${path}/members`, { remove: [removingMember.user_id] }); toast.success('Member removed'); refresh() }}
    />}
    {unbinding && <ConfirmDialog
      title={`Unassign ${unbinding.role_name}?`}
      description={`Members of ${group.name} lose "${unbinding.role_name}" unless they hold it directly or through another group.`}
      confirmLabel="Unassign"
      onClose={() => setUnbinding(null)}
      confirm={async () => { await api.delete(`${base}/group-role-assignments/${unbinding.role_id}/${orgId}/${groupId}`); toast.success('Role unassigned'); roles.reload() }}
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
          <label className="text-sm font-medium" htmlFor="group-pick">{label}</label>
          <SearchSelect id="group-pick" name="pick" path={path} mapItem={mapItem} disabled={busy} placeholder={`Search ${label.toLowerCase()}s…`} onChange={setValue} />
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
