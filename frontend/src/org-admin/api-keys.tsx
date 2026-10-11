import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { KeySquare, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { EmptyState, ErrorState, PageHeader, selectClass } from '@/components/library/patterns'
import { ExpiryField, IssuedKeyDialog, KeysTable, PermissionChecks, RevokeKeyDialog, useExpiry, type APIKey, type IssuedKey, type KeyOptions } from '@/components/library/api-keys'
import { cn, message } from '@/lib/utils'
import { useAdmin } from './context'
import type { Page } from './session'
import { t } from '@/lib/i18n'

export const API_KEYS_READ = 'iam:org:api-keys:read'
export const API_KEYS_WRITE = 'iam:org:api-keys:write'

type Tab = 'organization' | 'members'

/** useKeys pages one kind of key of the organization (GET /admin/api-keys). */
function useKeys(owner: Tab) {
  const { client } = useAdmin()
  const [rawSearch, setSearch] = useState('')
  const [search, setDebounced] = useState('')
  const [offset, setOffset] = useState(0)
  const [version, setVersion] = useState(0)
  const [state, setState] = useState<{ data: APIKey[]; total: number; loading: boolean; error: string }>({ data: [], total: 0, loading: true, error: '' })
  const limit = 50
  useEffect(() => { const timer = setTimeout(() => { setDebounced(rawSearch); setOffset(0) }, 300); return () => clearTimeout(timer) }, [rawSearch])
  useEffect(() => {
    const ctrl = new AbortController()
    const q = new URLSearchParams({ limit: String(limit), offset: String(offset), owner_type: owner === 'members' ? 'user' : 'organization' })
    if (search) q.set('search', search)
    setState(s => ({ ...s, loading: true, error: '' }))
    client.get<Page<APIKey>>(`/api-keys?${q}`, ctrl.signal)
      .then(r => { if (!ctrl.signal.aborted) setState({ data: r.items ?? [], total: r.page?.total ?? 0, loading: false, error: '' }) })
      .catch(e => { if (!ctrl.signal.aborted) setState({ data: [], total: 0, loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [client, owner, offset, search, version])
  return {
    ...state, rawSearch, setSearch, from: state.total ? offset + 1 : 0, to: Math.min(offset + limit, state.total),
    hasPrev: offset > 0, hasNext: offset + limit < state.total, nextPage: () => setOffset(o => o + limit), prevPage: () => setOffset(o => Math.max(0, o - limit)),
    search, reload: () => setVersion(v => v + 1),
  }
}

/** APIKeysPage is the portal's API keys page: the organization's own keys and
 * the keys its members created for themselves (/admin/api-keys). */
export function APIKeysPage() {
  const { can } = useAdmin()
  const write = can(API_KEYS_WRITE)
  const [tab, setTab] = useState<Tab>('organization')
  const tabs: [Tab, string][] = [['organization', t('Organization keys')], ['members', t('Members\' keys')]]
  return <div className="space-y-6">
    <PageHeader title={t('API keys')} description={t('Credentials that call your applications\' APIs. Values are shown once, when created.')} />
    <div role="tablist" aria-label={t('API keys')} className="flex gap-1 border-b">
      {tabs.map(([id, label]) => <button key={id} type="button" role="tab" id={`keys-tab-${id}`} aria-selected={tab === id} aria-controls={`keys-panel-${id}`}
        className={cn('-mb-px border-b-2 px-3 py-2 text-sm font-medium', tab === id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}
        onClick={() => setTab(id)}>{label}</button>)}
    </div>
    <div role="tabpanel" id={`keys-panel-${tab}`} aria-labelledby={`keys-tab-${tab}`} className="space-y-4">
      {tab === 'organization' ? <OrganizationKeys write={write} /> : <MemberKeys write={write} />}
    </div>
  </div>
}

function OrganizationKeys({ write }: { write: boolean }) {
  const { client } = useAdmin()
  const list = useKeys('organization')
  const options = useOptions(write)
  const [creating, setCreating] = useState(false)
  const [issued, setIssued] = useState<IssuedKey | null>(null)
  const [revoke, setRevoke] = useState<APIKey | null>(null)
  const disabled = options !== null && !options.enabled
  const create = write && !disabled && <Button onClick={() => setCreating(true)} disabled={options === null}><Plus /> {t('Create API key')}</Button>
  return <>
    {disabled && <div role="note" className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm">{t('Organization keys are turned off. The operator of this environment must enable organization keys before you can create them.')}</div>}
    <div className="flex items-start justify-between gap-3">
      <p className="text-sm text-muted-foreground">{t('Keys that belong to the organization, not to a person: they keep working when their creator leaves.')}</p>
      {create}
    </div>
    <PaginationBar state={list} placeholder={t('Search keys by name…')} label={t('Search keys')} noun="keys" />
    <KeysTable keys={list.data} loading={list.loading} error={list.error} retry={list.reload} columns={{ resource: true, createdBy: true }}
      onRevoke={write ? setRevoke : undefined}
      empty={list.search ? <EmptyState title={t('No keys match')} /> : <EmptyState icon={<KeySquare />} title={t('No organization keys')} description={t('Create a key to let a system of yours call an API on behalf of the organization.')} action={create || undefined} />} />
    {creating && options && <CreateKey options={options} onClose={() => setCreating(false)} onCreated={key => { setIssued(key); list.reload() }} />}
    {issued && <IssuedKeyDialog issued={issued} onClose={() => setIssued(null)} />}
    {revoke && <RevokeKeyDialog apiKey={revoke} onClose={() => setRevoke(null)} remove={async () => { await client.delete(`/api-keys/${revoke.id}`); toast.success(t('Key revoked')); list.reload() }} />}
  </>
}

function MemberKeys({ write }: { write: boolean }) {
  const { client } = useAdmin()
  const list = useKeys('members')
  const [revoke, setRevoke] = useState<APIKey | null>(null)
  return <>
    <p className="text-sm text-muted-foreground">{t('Personal keys your members created for themselves. You can revoke them; members create new ones.')}</p>
    <PaginationBar state={list} placeholder={t('Search keys by name…')} label={t('Search keys')} noun="keys" />
    <KeysTable keys={list.data} loading={list.loading} error={list.error} retry={list.reload} columns={{ member: true, resource: true }}
      onRevoke={write ? setRevoke : undefined}
      empty={list.search ? <EmptyState title={t('No keys match')} /> : <EmptyState icon={<KeySquare />} title={t('No member keys')} description={t('Keys your members create appear here.')} />} />
    {revoke && <RevokeKeyDialog apiKey={revoke} onClose={() => setRevoke(null)} remove={async () => { await client.delete(`/api-keys/${revoke.id}`); toast.success(t('Key revoked')); list.reload() }} />}
  </>
}

/** useOptions loads what this admin may give a new key. Only writers can read it. */
function useOptions(write: boolean) {
  const { client } = useAdmin()
  const [options, setOptions] = useState<KeyOptions | null>(null)
  useEffect(() => {
    if (!write) return
    const ctrl = new AbortController()
    client.get<KeyOptions>('/api-keys/options', ctrl.signal).then(o => { if (!ctrl.signal.aborted) setOptions(o) }).catch(() => {})
    return () => ctrl.abort()
  }, [client, write])
  return options
}

function CreateKey({ options, onClose, onCreated }: { options: KeyOptions; onClose: () => void; onCreated: (key: IssuedKey) => void }) {
  const { client } = useAdmin()
  const id = useId()
  const [resource, setResource] = useState('')
  const [permissions, setPermissions] = useState<string[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const expiry = useExpiry(options.max_ttl_days)
  const chosen = useMemo(() => options.resources.find(r => r.id === resource), [options, resource])
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Create API key')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('The key belongs to your organization and carries only the permissions you pick, never more than you can give.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        pending.current = true; setBusy(true); setError('')
        try {
          const key = await client.post<IssuedKey>('/api-keys', { resource_id: resource, name: String(new FormData(event.currentTarget).get('name') ?? '').trim(), permissions, expires_in: expiry.value })
          toast.success(t('API key created')); onCreated(key); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} placeholder={t('e.g. ERP integration')} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-res`}>{t('Resource')}</label>
          <select id={`${id}-res`} className={selectClass} required value={resource} disabled={busy} onChange={e => { setResource(e.target.value); setPermissions([]) }}>
            <option value="">{t('Choose a resource')}</option>
            {options.resources.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
          {options.resources.length === 0 && <p className="text-xs text-muted-foreground">{t('No resource lets you create keys yet.')}</p>}
        </div>
        {chosen && <PermissionChecks available={chosen.permissions} selected={permissions} onChange={setPermissions} disabled={busy} />}
        <ExpiryField id={`${id}-ttl`} expiry={expiry} disabled={busy} />
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy || !resource || permissions.length === 0}>{busy ? t('Creating…') : t('Create')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
