import { useEffect, useMemo, useState } from 'react'
import { BadgeCheck, Ban, Check, History, Trash2, Undo2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { RowActions } from '@/components/ui/menu'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, ErrorState, Time } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

export type Admission = 'pending' | 'approved' | 'blocked'

/** oauth.ExternalClientView: an external client (named by a metadata document
 * URL) as one protected resource sees it. */
export interface ExternalClient {
  id: string; client_id: string; protected_resource_id: string
  client_name: string; client_uri: string; logo_uri: string; host: string
  admission: Admission; admission_expires_at: string | null
  admission_source: 'manual' | 'allowlist' | 'preset' | 'open' | ''
  redirect_uris: string[]; token_endpoint_auth_method: string; jwks_uri: string
  /** Digest of the three fields above as the server holds them now: an approval sends the one on screen. */
  metadata_hash: string
  preset: string; preset_name: string; access_requests: number
  metadata_fetched_at: string | null; last_used_at: string | null; created_at: string
}

interface AccessRequest { user_id: string; email: string; name: string; requested_at: string }

const tabs: Admission[] = ['pending', 'approved', 'blocked']
const tabLabel = (a: Admission) => a === 'pending' ? t('Pending') : a === 'approved' ? t('Approved') : t('Blocked')

/** hostOf is the host of a client_id URL: the one thing about the client IAMKit
 * can vouch for. The server sends it; this is only the fallback. */
const hostOf = (c: ExternalClient) => c.host || (() => { try { return new URL(c.client_id).host } catch { return c.client_id } })()

/** logoOf is the document's logo only when it is https on the client_id's own
 * host: a document must not make the console load an image from elsewhere. */
function logoOf(c: ExternalClient) {
  try {
    const logo = new URL(c.logo_uri)
    return logo.protocol === 'https:' && logo.host === new URL(c.client_id).host ? logo.href : ''
  } catch { return '' }
}

const sourceLabel = (c: ExternalClient) => c.admission_source === 'preset' ? t('Template') : t('Metadata document')

/** ClientIdentity names the client: its host first (verified), then the name the
 * document claims. A name is marked "unverified" unless a preset vouches for it. */
function ClientIdentity({ client }: { client: ExternalClient }) {
  const logo = logoOf(client)
  const name = client.preset_name || client.client_name
  return <div className="flex min-w-0 items-start gap-2.5">
    {logo ? <img src={logo} alt="" className="mt-0.5 size-8 shrink-0 rounded object-contain" referrerPolicy="no-referrer" /> : null}
    <div className="min-w-0 space-y-0.5">
      <p className="truncate font-mono text-sm font-semibold" title={client.client_id}>{hostOf(client)}</p>
      {client.preset_name
        ? <p className="flex items-center gap-1 text-xs text-success"><BadgeCheck className="size-3.5" /> {t('Verified: {{name}}', { name: client.preset_name })}</p>
        : name
          ? <p className="text-xs text-muted-foreground">{name} <Badge variant="outline" className="ml-1">{t('Unverified')}</Badge></p>
          : null}
    </div>
  </div>
}

function ApproveDialog({ path, client, onClose, onDone }: { path: string; client: ExternalClient; onClose: () => void; onDone: () => void }) {
  const [expires, setExpires] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10)
  const submit = async () => {
    setBusy(true); setError('')
    try {
      // The end of the chosen day, in the operator's time zone.
      // The approval names the document the operator is looking at (the
      // hash of what this page showed); the server refuses it if the
      // client's document changed since.
      await api.post(`${path}/${client.id}/approve`, { metadata_hash: client.metadata_hash, ...(expires ? { expires_at: new Date(`${expires}T23:59:59`).toISOString() } : {}) })
      toast.success(t('Approved {{host}}', { host: hostOf(client) })); onDone(); onClose()
    } catch (e) {
      if (e instanceof ApiError && e.code === 'CLIENT_METADATA_CHANGED') {
        // Reload the list: its row now shows the new document to review.
        toast.error(t('The metadata of {{host}} changed since you opened this. The list was refreshed: review it and approve again.', { host: hostOf(client) })); onDone(); onClose()
      } else setError(message(e))
    } finally { setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{t('Approve {{host}}?', { host: hostOf(client) })}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{t('Its users can then authorize it to use this MCP server. IAMKit vouches only for the host; the name and logo in its document are its own claim.')}</DialogDescription>
    <p className="break-all font-mono text-xs text-muted-foreground">{client.client_id}</p>
    <div className="space-y-1 text-xs">
      <p className="font-medium">{t('You approve exactly this')}</p>
      <ul className="list-disc space-y-0.5 pl-4 font-mono text-muted-foreground">
        {client.redirect_uris.map(uri => <li key={uri} className="break-all">{uri}</li>)}
        <li>{t('Authentication: {{method}}', { method: client.token_endpoint_auth_method })}{client.jwks_uri ? <span className="break-all"> · {client.jwks_uri}</span> : null}</li>
      </ul>
      <p className="text-muted-foreground">{t('If the client changes any of this later, it waits for approval again.')}</p>
    </div>
    <div className="space-y-1.5">
      <label htmlFor="approval-expiry" className="text-sm font-medium">{t('Approval expires')} <span className="font-normal text-muted-foreground">{t('(optional)')}</span></label>
      <Input id="approval-expiry" type="date" min={tomorrow} value={expires} onChange={e => setExpires(e.target.value)} disabled={busy} />
      <p className="text-xs text-muted-foreground">{t('When it expires, the client\'s sessions end and it waits for approval again. Leave empty to approve without an end date.')}</p>
    </div>
    {error && <ErrorState error={error} />}
    <div className="flex justify-end gap-2"><Button variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button><Button disabled={busy} onClick={() => void submit()}>{busy ? t('Working…') : t('Approve')}</Button></div>
  </DialogContent></Dialog>
}

function RequestsDialog({ path, client, onClose }: { path: string; client: ExternalClient; onClose: () => void }) {
  const [rows, setRows] = useState<AccessRequest[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.get<{ items: AccessRequest[] } | AccessRequest[]>(`${path}/${client.id}/requests`)
      .then(r => setRows(Array.isArray(r) ? r : r.items ?? []))
      .catch(e => setError(message(e)))
  }, [path, client.id])
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{t('Access requests for {{host}}', { host: hostOf(client) })}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{t('People who tried to use this client while it was waiting for approval.')}</DialogDescription>
    {error ? <ErrorState error={error} /> : rows === null ? <p role="status" className="text-sm text-muted-foreground">{t('Loading data…')}</p> :
      rows.length === 0 ? <p className="text-sm text-muted-foreground">{t('Nobody has asked yet.')}</p> :
        <ul className="max-h-72 divide-y overflow-auto text-sm">{rows.map(r => <li key={`${r.user_id}-${r.requested_at}`} className="flex items-center justify-between gap-3 py-2">
          <span className="min-w-0"><span className="block truncate">{r.name || r.email}</span>{r.name && <span className="block truncate text-xs text-muted-foreground">{r.email}</span>}</span>
          <Time value={r.requested_at} />
        </li>)}</ul>}
  </DialogContent></Dialog>
}

/** ClientImpact is what blocking or deleting a client ends (…/clients/:id/impact). */
type ClientImpact = { active_sessions: number; users: number }

/** impactText says how many sessions, of how many people, a block or delete ends. */
const impactText = (i: ClientImpact) => i.active_sessions === 0
  ? t('No session of this client is active right now.')
  : t('{{count}} active sessions end now.', { count: i.active_sessions }) + ' ' + t('{{count}} people must authorize this client again.', { count: i.users })

/** ClientsSection lists the external clients of an MCP server by admission
 * state and lets operators approve, block, unblock or forget them. Blocking
 * and forgetting end the client's sessions (the backend does it in the same
 * transaction). */
export function ClientsSection({ path, canWrite, refresh }: { path: string; canWrite: boolean; refresh?: unknown }) {
  const [admission, setAdmission] = useState<Admission>('pending')
  const extraParams = useMemo(() => ({ admission }), [admission])
  const list = usePaginatedList<ExternalClient>(`${path}/clients`, { extraParams })
  const [counts, setCounts] = useState<Partial<Record<Admission, number>>>({})
  const [approving, setApproving] = useState<ExternalClient | null>(null)
  const [ending, setEnding] = useState<{ client: ExternalClient; action: 'block' | 'delete'; impact: ClientImpact } | null>(null)
  const [requests, setRequests] = useState<ExternalClient | null>(null)
  const [busy, setBusy] = useState('')
  const { reload } = list
  const [version, setVersion] = useState(0)
  useEffect(() => {
    let live = true
    for (const a of tabs) {
      api.list<ExternalClient>(`${path}/clients?admission=${a}&limit=1`)
        .then(r => { if (live) setCounts(c => ({ ...c, [a]: r.total })) })
        .catch(() => undefined)
    }
    return () => { live = false }
  }, [path, version, refresh])
  const changed = () => { reload(); setVersion(v => v + 1) }
  // Blocking and deleting end the client's sessions: ask …/impact first and say how many.
  const ask = async (client: ExternalClient, action: 'block' | 'delete') => {
    setBusy(client.id)
    try { setEnding({ client, action, impact: await api.get<ClientImpact>(`${path}/clients/${client.id}/impact`) }) } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const act = async (client: ExternalClient, verb: 'unblock', done: string) => {
    setBusy(client.id)
    try { await api.post(`${path}/clients/${client.id}/${verb}`); toast.success(done); changed() } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const empty = <EmptyState icon={<BadgeCheck />} title={admission === 'pending' ? t('No clients are waiting') : admission === 'approved' ? t('No approved clients') : t('No blocked clients')}
    description={admission === 'pending' ? t('A client whose metadata URL is not on the allowlist shows up here the first time someone tries to use it.') : undefined} />

  return <DetailSection title={t('Clients')} description={t('MCP clients that name themselves with a URL (Client ID Metadata Documents), and the fixed clients created from templates, as this server sees them.')}>
    <div className="flex flex-wrap items-center gap-3">
      <div role="tablist" aria-label={t('Filter clients by admission')} className="inline-flex rounded-lg border p-0.5">
        {tabs.map(a => <button key={a} type="button" role="tab" aria-selected={admission === a} onClick={() => setAdmission(a)}
          className={`rounded-md px-3 py-1 text-sm transition-colors ${admission === a ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted'}`}>
          {tabLabel(a)}{counts[a] !== undefined && <span className="ml-1.5 text-xs opacity-80">{counts[a]}</span>}
        </button>)}
      </div>
    </div>
    <DataTable
      columns={[t('Client'), { header: t('Source'), hideBelow: 'md' }, { header: t('Last used'), hideBelow: 'lg', nowrap: true }, ...(admission === 'approved' ? [{ header: t('Approval expires'), hideBelow: 'lg' as const, nowrap: true }] : []), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload} empty={empty}
      rows={list.data.map(c => [
        <ClientIdentity client={c} />,
        <span className="text-sm text-muted-foreground">{sourceLabel(c)}{c.admission_source === 'allowlist' && <> · {t('allowlist')}</>}{c.admission_source === 'open' && <> · {t('open admission')}</>}</span>,
        <Time value={c.last_used_at} />,
        ...(admission === 'approved' ? [c.admission_expires_at ? <Time value={c.admission_expires_at} /> : <span className="text-muted-foreground">{t('Never')}</span>] : []),
        ...(canWrite ? [<RowActions label={t('Actions for {{host}}', { host: hostOf(c) })} actions={[
          ...(c.admission !== 'approved' && c.admission !== 'blocked' ? [{ label: t('Approve'), icon: <Check />, disabled: busy === c.id, onSelect: () => setApproving(c) }] : []),
          ...(c.admission === 'approved' ? [{ label: t('Change expiry'), icon: <Check />, disabled: busy === c.id, onSelect: () => setApproving(c) }] : []),
          ...(c.admission === 'blocked' ? [{ label: t('Unblock'), icon: <Undo2 />, disabled: busy === c.id, onSelect: () => void act(c, 'unblock', t('Unblocked {{host}}', { host: hostOf(c) })) }] : [{ label: t('Block'), icon: <Ban />, disabled: busy === c.id, onSelect: () => void ask(c, 'block') }]),
          { label: t('Access requests ({{count}})', { count: c.access_requests }), icon: <History />, onSelect: () => setRequests(c) },
          { label: t('Delete'), icon: <Trash2 />, destructive: true, disabled: busy === c.id, onSelect: () => void ask(c, 'delete') },
        ]} />] : []),
      ])} />
    {list.total > list.limit && <div className="flex items-center justify-between text-xs text-muted-foreground">
      <span>{t('{{from}}–{{to}} of {{total}} {{noun}}', { from: list.from, to: list.to, total: list.total, noun: t('clients') })}</span>
      <div className="flex gap-2"><Button variant="outline" size="sm" disabled={!list.hasPrev} onClick={list.prevPage}>{t('Previous page')}</Button><Button variant="outline" size="sm" disabled={!list.hasNext} onClick={list.nextPage}>{t('Next page')}</Button></div>
    </div>}
    {approving && <ApproveDialog path={`${path}/clients`} client={approving} onClose={() => setApproving(null)} onDone={changed} />}
    {requests && <RequestsDialog path={`${path}/clients`} client={requests} onClose={() => setRequests(null)} />}
    {ending?.action === 'block' && <ConfirmDialog title={t('Block {{host}}?', { host: hostOf(ending.client) })}
      description={impactText(ending.impact) + ' ' + t('Its sessions and grants for this MCP server end at once, and it cannot be authorized again until you unblock it.')}
      confirmLabel={t('Block')} onClose={() => setEnding(null)}
      confirm={async () => { await api.post(`${path}/clients/${ending.client.id}/block`); toast.success(t('Blocked {{host}}', { host: hostOf(ending.client) })); changed() }} />}
    {ending?.action === 'delete' && <ConfirmDialog title={t('Delete {{host}}?', { host: hostOf(ending.client) })}
      description={impactText(ending.impact) + ' ' + t('IAMKit forgets this client and ends its sessions. If it tries again it is treated as new: admitted or held for approval according to the allowlist.')}
      confirmLabel={t('Delete')} onClose={() => setEnding(null)}
      confirm={async () => { await api.delete(`${path}/clients/${ending.client.id}`); toast.success(t('Deleted {{host}}', { host: hostOf(ending.client) })); changed() }} />}
  </DetailSection>
}

