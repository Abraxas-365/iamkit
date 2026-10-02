import { useCallback, useEffect, useId, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Handshake, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { Skeleton } from '@/components/ui/skeleton'
import { BackLink, ConfirmDialog, CopyText, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, PageHeader, SwitchField, Time } from '@/components/library/patterns'
import { HistorySection } from './history'
import { rich, t } from '@/lib/i18n'

export interface Resource {
  id: string; name: string; prefix: string; audience: string; permissions: string[]
  owner_organization_id: string | null; require_grant: boolean
}

/** A resource grant (authorization.ResourceGrant); role_ids null = every role. */
export interface ResourceGrant {
  id: string; resource_id: string; resource_name: string
  organization_id: string; organization_name: string
  role_ids: string[] | null; created_at: string; updated_at: string
}

interface Role { id: string; name: string; resource_id: string }
interface Named { id: string; name: string }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name ?? item.id) })

/** GrantedRoles renders a grant's roles: "All roles" for null. */
export function GrantedRoles({ grant, roles }: { grant: ResourceGrant; roles?: Role[] }) {
  if (grant.role_ids === null) return <Badge variant="secondary">{t('All roles')}</Badge>
  if (grant.role_ids.length === 0) return <span className="text-xs text-muted-foreground">{t('No roles')}</span>
  const names = new Map((roles ?? []).map(r => [r.id, r.name]))
  return <span className="flex flex-wrap gap-1">{grant.role_ids.map(id => <Badge key={id} variant="outline">{names.get(id) ?? id.slice(0, 8)}</Badge>)}</span>
}

/** GrantDialog grants the resource to an organization, or edits the granted
 * roles of an existing grant. `path` is the resource-grants collection. */
export function GrantDialog({ path, organizationsPath, resource, roles, grant, onClose, onSaved }: {
  path: string; organizationsPath: string; resource: string; roles: Role[]; grant?: ResourceGrant; onClose: () => void; onSaved: () => void
}) {
  const id = useId()
  const [organization, setOrganization] = useState(grant?.organization_id ?? '')
  const [all, setAll] = useState(!grant || grant.role_ids === null)
  const [selected, setSelected] = useState<string[]>(grant?.role_ids ?? [])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const toggle = (role: string) => setSelected(s => s.includes(role) ? s.filter(r => r !== role) : [...s, role])
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle>{grant ? t('Edit grant to {{organization_name}}', { organization_name: grant.organization_name }) : t('Grant to an organization')}</DialogTitle>
      <DialogDescription>{t('The organization\'s administrators can then assign the granted roles to their members. Narrowing or revoking a grant ends the sessions that relied on it.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault()
        if (!organization) { setError(t('Choose an organization')); return }
        setBusy(true); setError('')
        try {
          await api.put(path, { resource_id: resource, organization_id: organization, role_ids: all ? null : selected })
          toast.success(grant ? t('Grant updated') : t('Resource granted'))
          onSaved(); onClose()
        } catch (e) { setError(message(e)) } finally { setBusy(false) }
      }}>
        {!grant && <div className="space-y-1.5">
          <label htmlFor={`${id}-org`} className="text-sm font-medium">{t('Organization')}</label>
          <SearchSelect id={`${id}-org`} name="organization_id" path={organizationsPath} mapItem={named} required disabled={busy} placeholder={t('Search organization…')} onChange={setOrganization} />
        </div>}
        <SwitchField id={`${id}-all`} label={t('Every role')} hint={t('Includes roles added to the resource later.')} checked={all} disabled={busy} onCheckedChange={setAll} />
        {!all && <fieldset className="space-y-2">
          <legend className="text-sm font-medium">{t('Granted roles')}</legend>
          {roles.length === 0 && <p className="text-xs text-muted-foreground">{t('The resource has no roles yet; the grant still lets the organization reach it.')}</p>}
          {roles.map(role => <label key={role.id} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={selected.includes(role.id)} disabled={busy} onChange={() => toggle(role.id)} />{role.name}
          </label>)}
        </fieldset>}
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose} disabled={busy}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{grant ? t('Save') : t('Grant')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

/** ResourceDetailPage shows a resource's ownership, grant requirement and
 * the organizations it is granted to. */
export default function ResourceDetailPage() {
  const { project, environment, resourceId } = useParams()
  const base = `/environments/${environment}`
  const envBase = `/projects/${project}/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [resource, setResource] = useState<Resource | null>(null)
  const [owner, setOwner] = useState<Named | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [granting, setGranting] = useState<ResourceGrant | 'new' | null>(null)
  const [revoking, setRevoking] = useState<ResourceGrant | null>(null)
  const grants = usePaginatedList<ResourceGrant>(`${base}/resource-grants`, { extraParams: { resource_id: resourceId ?? '' } })
  const allRoles = usePaginatedList<Role>(`${base}/roles`, { limit: 100 })
  const roles = allRoles.data.filter(r => r.resource_id === resourceId)

  const load = useCallback(() => {
    setError('')
    api.get<Resource>(`${base}/resources/${resourceId}`).then(async r => {
      setResource(r)
      setOwner(r.owner_organization_id ? await api.get<Named>(`${base}/organizations/${r.owner_organization_id}`).catch(() => ({ id: r.owner_organization_id!, name: '' })) : null)
    }).catch(e => setError(message(e)))
  }, [base, resourceId])
  useEffect(load, [load])

  const back = <BackLink to={`${envBase}/resources`}>{t('Resources')}</BackLink>
  if (error) return <div className="space-y-6">{back}<ErrorState error={error} retry={load} /></div>
  if (!resource) return <div role="status" className="space-y-6">{back}<Skeleton className="h-9 w-64" /><Skeleton className="h-48" /><span className="sr-only">{t('Loading resource…')}</span></div>
  const system = resource.prefix === 'iam'

  return <div className="space-y-6">
    <div className="space-y-3">{back}
      <PageHeader title={resource.name} description={resource.audience} />
      <div className="flex flex-wrap items-center gap-2"><code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">{resource.prefix}</code><CopyText value={resource.id} short label={t('Copy resource ID')} /></div>
    </div>

    <DetailSection title={t('Access')} description={t('Which organization ships this resource, and whether only it and the organizations it is granted to can reach it.')}
      actions={canWrite && !system && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil />{t('Edit access')}</Button>}>
      {system ? <p className="text-sm text-muted-foreground">{t('The IAM resource is available to every organization; it cannot be owned or granted.')}</p>
        : <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div><dt className="text-xs text-muted-foreground">{t('Owner')}</dt><dd>{owner ? <EntityRef name={owner.name} id={owner.id} to={`${envBase}/organizations/${owner.id}`} /> : t('This environment')}</dd></div>
          <div><dt className="text-xs text-muted-foreground">{t('Grant required')}</dt><dd>{resource.require_grant ? t('Yes — only the owner and granted organizations') : t('No — any organization')}</dd></div>
        </dl>}
    </DetailSection>

    {!system && <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{t('Granted organizations')}</h2>
          <p className="max-w-2xl text-sm text-muted-foreground">{resource.require_grant
            ? t('Organizations that may use this resource. Their administrators assign the granted roles to members.')
            : t('Organizations that may use this resource (grants take effect when a grant is required). Their administrators assign the granted roles to members.')}</p>
        </div>
        {canWrite && <Button onClick={() => setGranting('new')}><Plus />{t('Grant to organization')}</Button>}
      </div>
      <PaginationBar state={grants} noun="grants" placeholder={t('Search organizations…')} />
      <DataTable
        columns={[t('Organization'), t('Roles'), { header: t('Updated'), hideBelow: 'sm', nowrap: true }, t('Actions')]}
        loading={grants.loading} error={grants.error} retry={grants.reload}
        empty={<EmptyState icon={<Handshake />} title={t('Not granted to any organization')} description={t('Grant the resource to let another organization\'s administrators assign its roles.')} />}
        rows={grants.data.map(g => [
          <EntityRef name={g.organization_name} id={g.organization_id} to={`${envBase}/organizations/${g.organization_id}`} />,
          <GrantedRoles grant={g} roles={roles} />,
          <Time value={g.updated_at} />,
          <RowActions label={t('Actions for {{organization_name}}', { organization_name: g.organization_name })} actions={canWrite ? [
            { label: t('Edit roles'), icon: <Pencil />, onSelect: () => setGranting(g) },
            { label: t('Revoke grant'), icon: <Trash2 />, destructive: true, onSelect: () => setRevoking(g) },
          ] : []} />,
        ])} />
    </div>}

    {!system && <HistorySection path={`${base}/resources/${resource.id}`} refresh={resource} />}

    {editing && <AccessDialog base={base} resource={resource} owner={owner} onClose={() => setEditing(false)} onSaved={load} />}
    {granting && <GrantDialog path={`${base}/resource-grants`} organizationsPath={`${base}/organizations`} resource={resource.id} roles={roles}
      grant={granting === 'new' ? undefined : granting} onClose={() => setGranting(null)} onSaved={grants.reload} />}
    {revoking && <ConfirmDialog title={t('Revoke {{organization_name}}\'s grant?', { organization_name: revoking.organization_name })} description={t('{{organization_name}} loses the {{name}} roles it was granted, and its members\' sessions for {{name2}} end when a grant is required.', { organization_name: revoking.organization_name, name: resource.name, name2: resource.name })}
      confirmLabel={t('Revoke grant')} onClose={() => setRevoking(null)}
      confirm={async () => { await api.delete(`${base}/resource-grants/${revoking.id}`); toast.success(t('Grant revoked')); grants.reload() }} />}
    {!system && <p className="text-xs text-muted-foreground">{rich('Roles of this resource: {{roles}}.', { roles: <Link to={`${envBase}/roles`} className="hover:underline">{t('{{count}} roles', { count: roles.length })}</Link> })}</p>}
  </div>
}

function AccessDialog({ base, resource, owner, onClose, onSaved }: { base: string; resource: Resource; owner: Named | null; onClose: () => void; onSaved: () => void }) {
  const id = useId()
  const [ownerId, setOwnerId] = useState(owner?.id ?? '')
  const [requireGrant, setRequireGrant] = useState(resource.require_grant)
  const [cleared, setCleared] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle>{t('Edit access to {{name}}', { name: resource.name })}</DialogTitle>
      <DialogDescription>{t('Organizations that lose access have their sessions for this resource ended.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); setBusy(true); setError('')
        try {
          await api.put(`${base}/resources/${resource.id}/access`, { owner_organization_id: ownerId || null, require_grant: requireGrant })
          toast.success(t('Access updated')); onSaved(); onClose()
        } catch (e) { setError(message(e)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label htmlFor={`${id}-owner`} className="text-sm font-medium">{t('Owner organization')}</label>
          <SearchSelect key={cleared} id={`${id}-owner`} name="owner_organization_id" path={`${base}/organizations`} mapItem={named} defaultValue={ownerId} disabled={busy} placeholder={t('This environment')} onChange={setOwnerId} />
          <p className="text-xs text-muted-foreground">{t('Its administrators (Resource manager role) grant the resource to other organizations. Leave empty to keep it with the environment\'s operators.')}</p>
          {ownerId && <Button type="button" variant="ghost" size="sm" onClick={() => { setOwnerId(''); setCleared(c => c + 1) }} disabled={busy}>{t('Clear owner')}</Button>}
        </div>
        <SwitchField id={`${id}-require`} label={t('Require a grant')} hint={t('Only the owner and granted organizations get tokens and roles for this resource.')} checked={requireGrant} disabled={busy} onCheckedChange={setRequireGrant} />
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose} disabled={busy}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{t('Save')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
