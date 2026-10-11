import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { KeySquare, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { EmptyState, ErrorState, PageHeader, selectClass } from '@/components/library/patterns'
import { ExpiryField, IssuedKeyDialog, KeysTable, PermissionChecks, RevokeKeyDialog, useExpiry, type APIKey, type IssuedKey, type KeyPolicy } from '@/components/library/api-keys'
import type { Resource } from './resource-detail'
import { t } from '@/lib/i18n'

interface Named { id: string; name: string }
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

/** APIKeysPage lists every API key of the environment (user, organization
 * and machine keys), filtered, and revokes them. Operators also create
 * organization keys here; machine keys are created on the machine user. */
export default function APIKeysPage() {
  const { project, environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const [filters, setFilters] = useState({ owner_type: '', organization_id: '', resource_id: '', user_id: '', state: '' })
  const [userReset, setUserReset] = useState(0)
  const extraParams = useMemo(() => filters, [filters])
  const list = usePaginatedList<APIKey>(`${base}/api-keys`, { extraParams })
  const organizations = useList<Named>(`${base}/organizations?limit=100`)
  const resources = useList<Named>(`${base}/resources?limit=100`)
  const [creating, setCreating] = useState(false)
  const [issued, setIssued] = useState<IssuedKey | null>(null)
  const [revoke, setRevoke] = useState<APIKey | null>(null)
  const set = (key: keyof typeof filters) => (value: string) => setFilters(f => ({ ...f, [key]: value }))
  const filtered = Object.values(filters).some(Boolean)
  const create = canWrite && <Button onClick={() => setCreating(true)}><Plus /> {t('Create organization key')}</Button>
  const select = (label: string, key: keyof typeof filters, options: [string, string][], all: string) => <label className="space-y-1 text-xs text-muted-foreground">
    {label}
    <select aria-label={label} className={`${selectClass} w-44 text-foreground`} value={filters[key]} onChange={e => set(key)(e.target.value)}>
      <option value="">{all}</option>
      {options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
    </select>
  </label>
  return <div className="space-y-6">
    <PageHeader title={t('API keys')} description={t('Credentials your applications\' customers use to call your APIs: personal keys of users, keys of organizations and keys of machine users. Values are shown once, when created.')} actions={create} />
    <PaginationBar state={list} noun="keys" label={t('Search keys')} placeholder={t('Search keys by name…')} />
    <div className="flex flex-wrap items-end gap-3">
      {select(t('Owner type'), 'owner_type', [['user', t('User')], ['organization', t('Organization')], ['machine', t('Machine user')]], t('All owners'))}
      {select(t('Organization'), 'organization_id', organizations.data.map(o => [o.id, o.name]), t('All organizations'))}
      {select(t('Resource'), 'resource_id', resources.data.map(r => [r.id, r.name]), t('All resources'))}
      <div className="w-56 space-y-1 text-xs text-muted-foreground">
        <label htmlFor="api-keys-user">{t('User')}</label>
        <SearchSelect key={userReset} id="api-keys-user" name="user_id" path={`${base}/users`} mapItem={named} placeholder={t('Any user')} onChange={set('user_id')} />
      </div>
      {select(t('State'), 'state', [['active', t('Active')], ['revoked', t('Revoked')], ['expired', t('Expired')]], t('Any state'))}
      {filtered && <Button variant="ghost" size="sm" onClick={() => { setFilters({ owner_type: '', organization_id: '', resource_id: '', user_id: '', state: '' }); setUserReset(n => n + 1) }}>{t('Clear filters')}</Button>}
    </div>
    <KeysTable keys={list.data} loading={list.loading} error={list.error} retry={list.reload} console={console}
      columns={{ owner: true, organization: true, resource: true, createdBy: true }}
      onRevoke={canWrite ? setRevoke : undefined}
      empty={<EmptyState icon={<KeySquare />} title={filtered || list.search ? t('No keys match') : t('No API keys')}
        description={filtered || list.search ? undefined : t('Turn on user or organization keys in Settings, choose which permissions each resource allows, and keys created by users, organization admins and machine users appear here.')} action={filtered ? undefined : create} />} />
    {creating && <OrganizationKeyForm base={base} onClose={() => setCreating(false)} onCreated={key => { setIssued(key); list.reload() }} />}
    {issued && <IssuedKeyDialog issued={issued} onClose={() => setIssued(null)} />}
    {revoke && <RevokeKeyDialog apiKey={revoke} onClose={() => setRevoke(null)} remove={async () => { await api.delete(`${base}/api-keys/${revoke.id}`); toast.success(t('Key revoked')); list.reload() }} />}
  </div>
}

/** OrganizationKeyForm creates an organization's key: its resource, a name,
 * permissions inside the resource's allowlist for organization keys and a lifetime. */
function OrganizationKeyForm({ base, onClose, onCreated }: { base: string; onClose: () => void; onCreated: (key: IssuedKey) => void }) {
  const id = useId()
  const [organization, setOrganization] = useState('')
  const [resource, setResource] = useState('')
  const [permissions, setPermissions] = useState<string[]>([])
  const [policy, setPolicy] = useState<KeyPolicy | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const resources = useList<Resource>(`${base}/resources?limit=100`)
  const usable = resources.data.filter(r => (r.api_key_permissions?.organization ?? []).length > 0)
  const chosen = usable.find(r => r.id === resource)
  const allowed = chosen?.api_key_permissions?.organization ?? []
  const expiry = useExpiry(policy?.max_ttl_days)
  useEffect(() => { api.get<KeyPolicy>(`${base}/api-key-policy`).then(setPolicy).catch(() => {}) }, [base])
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Create organization key')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('The key belongs to the organization, not to a person, and keeps working when its creator leaves. It can only carry the permissions the resource allows for organization keys, and never more than the organization can reach.')}</DialogDescription>
      {policy && !policy.organization_keys && <div role="note" className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t('Organization keys are turned off for this environment: creating one is refused until you turn them on in Settings.')}</div>}
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        pending.current = true; setBusy(true); setError('')
        try {
          const key = await api.post<IssuedKey>(`${base}/api-keys`, {
            organization_id: organization, resource_id: resource, name: String(new FormData(event.currentTarget).get('name') ?? '').trim(),
            permissions, expires_in: expiry.value,
          })
          toast.success(t('API key created')); onCreated(key); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-org`}>{t('Organization')}</label>
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder={t('Search organizations…')} onChange={setOrganization} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-res`}>{t('Resource')}</label>
          <select id={`${id}-res`} className={selectClass} required value={resource} disabled={busy || resources.loading} onChange={e => { setResource(e.target.value); setPermissions([]) }}>
            <option value="">{resources.loading ? t('Loading…') : t('Choose a resource')}</option>
            {usable.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
          {!resources.loading && usable.length === 0 && <p className="text-xs text-muted-foreground">{t('No resource allows organization keys yet. Choose their permissions on the resource\'s page.')}</p>}
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} placeholder={t('e.g. ERP integration')} />
        </div>
        {chosen && <PermissionChecks available={allowed} selected={permissions} onChange={setPermissions} disabled={busy} hint={t('Only permissions this resource allows for organization keys.')} />}
        <ExpiryField id={`${id}-ttl`} expiry={expiry} disabled={busy} />
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy || !organization || !resource || permissions.length === 0}>{busy ? t('Creating…') : t('Create')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
