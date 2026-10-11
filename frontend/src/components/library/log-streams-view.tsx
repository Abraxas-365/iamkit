import { useEffect, useId, useState, type ReactNode } from 'react'
import { Ban, ListOrdered, Pencil, Plus, Power, RotateCw, Send, Trash2, Waypoints } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, DataTable, EmptyState, ErrorState, PageHeader, Time, selectClass, splitList } from '@/components/library/patterns'
import { message } from '@/lib/utils'
import { t } from '@/lib/i18n'

export interface LogStreamConfig {
  site?: string; service?: string; tags?: string[]
  url?: string; index?: string; source?: string; sourcetype?: string
  bucket?: string; region?: string; prefix?: string; endpoint?: string; path_style?: boolean; access_key_id?: string
}
export interface LogStream {
  id: string; organization_id?: string; name: string; destination: Destination; config: LogStreamConfig; sources: string[]
  secret_set: boolean; active: boolean; disabled_reason?: string; failing_since?: string | null
  previous_secret_expires_at?: string | null; pending: number; created_at: string; updated_at: string
}
export interface LogStreamDelivery {
  id: number; source: string; seq: number; status: 'pending' | 'delivered' | 'failed'; attempts: number
  next_attempt_at?: string | null; response_status?: number | null; last_error?: string; queued_at: string; finished_at?: string | null
}
export interface LogStreamIssued { id: string; secret?: string }
export interface LogStreamTest { delivered: boolean; status?: number; error?: string }
export type Destination = 'datadog' | 'splunk' | 's3' | 'https'

/** LogStreamsTransport is where the streams live: the management API for
 * the console, the organization's /admin routes for the portal. Keep the
 * object stable (useMemo). */
export interface LogStreamsTransport {
  list: (signal: AbortSignal) => Promise<{ items: LogStream[] }>
  create: (body: Record<string, unknown>) => Promise<LogStreamIssued>
  update: (id: string, body: Record<string, unknown>) => Promise<unknown>
  remove: (id: string) => Promise<unknown>
  test: (id: string) => Promise<LogStreamTest>
  enable: (id: string) => Promise<unknown>
  rotate: (id: string) => Promise<LogStreamIssued>
  deliveries: (id: string, query: URLSearchParams, signal: AbortSignal) => Promise<{ items: LogStreamDelivery[]; page?: { total: number; limit: number; offset: number } }>
  retry: (id: string, delivery: number) => Promise<unknown>
}

/** The Datadog regions the backend accepts (logstream.DatadogSites). */
export const DATADOG_SITES = ['datadoghq.com', 'us3.datadoghq.com', 'us5.datadoghq.com', 'datadoghq.eu', 'ap1.datadoghq.com', 'ddog-gov.com']

const destinations: [Destination, string][] = [['datadog', 'Datadog'], ['splunk', 'Splunk (HEC)'], ['s3', 'Amazon S3'], ['https', t('Signed HTTPS endpoint')]]
const destinationLabel = (d: string) => destinations.find(([value]) => value === d)?.[1] ?? d
const sourceLabels: Record<string, string> = { events: t('Event log'), audit_logs: t('App audit logs') }
const secretLabel: Record<Exclude<Destination, 'https'>, string> = { datadog: t('API key'), splunk: t('HEC token'), s3: t('Secret access key') }

/** streamState names where a stream stands (like a webhook). */
export function streamState(s: LogStream): [string, string] {
  if (!s.active) return [s.disabled_reason === 'failing' ? t('Disabled (failing)') : t('Disabled'), 'bg-muted text-muted-foreground']
  if (s.failing_since) return [t('Failing'), 'bg-destructive/10 text-destructive']
  return [t('Active'), 'bg-success/10 text-success']
}

const deliveryTones: Record<LogStreamDelivery['status'], [string, string]> = {
  pending: [t('Pending'), 'bg-warning/10 text-warning'],
  delivered: [t('Delivered'), 'bg-success/10 text-success'],
  failed: [t('Failed'), 'bg-destructive/10 text-destructive'],
}

function target(s: LogStream) {
  const c = s.config
  return s.destination === 'datadog' ? c.site : s.destination === 's3' ? `s3://${c.bucket}${c.prefix ? `/${c.prefix}` : ''}` : c.url
}

/** LogStreamsView lists log streams with create/edit, test, enable, rotate,
 * deliveries and delete. In an organization (`organization`) streams carry
 * the audit logs only, so the sources choice is hidden. */
export function LogStreamsView({ transport, canWrite, organization, title, description }: { transport: LogStreamsTransport; canWrite: boolean; organization?: boolean; title: string; description: string }) {
  const [state, setState] = useState<{ items: LogStream[]; loading: boolean; error: string }>({ items: [], loading: true, error: '' })
  const [version, setVersion] = useState(0)
  const [editing, setEditing] = useState<LogStream | 'new' | null>(null)
  const [removing, setRemoving] = useState<LogStream | null>(null)
  const [rotating, setRotating] = useState<LogStream | null>(null)
  const [watching, setWatching] = useState<LogStream | null>(null)
  const [secret, setSecret] = useState<{ title: string; value: string } | null>(null)
  const reload = () => setVersion(v => v + 1)
  useEffect(() => {
    const ctrl = new AbortController()
    setState(s => ({ ...s, loading: true, error: '' }))
    transport.list(ctrl.signal)
      .then(r => { if (!ctrl.signal.aborted) setState({ items: r.items ?? [], loading: false, error: '' }) })
      .catch(e => { if (!ctrl.signal.aborted) setState({ items: [], loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [transport, version])
  const run = async (fn: () => Promise<void>) => { try { await fn() } catch (e) { toast.error(message(e)) } }
  const add = canWrite && <Button onClick={() => setEditing('new')}><Plus /> {t('Add log stream')}</Button>
  return <div className="space-y-6">
    <PageHeader title={title} description={description} actions={add} />
    <DataTable
      columns={[t('Stream'), { header: t('Destination'), hideBelow: 'md' }, ...(organization ? [] : [{ header: t('Sources'), hideBelow: 'lg' as const }]), t('Status'), { header: t('Pending'), hideBelow: 'sm' }, t('Actions')]}
      loading={state.loading} error={state.error} retry={reload}
      empty={<EmptyState icon={<Waypoints />} title={t('No log streams')} description={t('Send your audit log events to Datadog, Splunk, S3 or a signed HTTPS endpoint.')} action={add || undefined} />}
      rows={state.items.map(s => {
        const [label, tone] = streamState(s)
        return [
          <div><p className="font-medium">{s.name}</p><p className="max-w-xs truncate text-xs text-muted-foreground" title={target(s)}>{target(s)}</p></div>,
          destinationLabel(s.destination),
          ...(organization ? [] : [<span className="flex flex-wrap gap-1">{s.sources.map(x => <Badge key={x} variant="secondary">{sourceLabels[x] ?? x}</Badge>)}</span>]),
          <div className="space-y-0.5">
            <Badge variant="secondary" className={tone}>{label}</Badge>
            {s.failing_since && <p className="text-xs text-muted-foreground">{t('Failing since')} <Time value={s.failing_since} /></p>}
            {!s.active && s.disabled_reason === 'failing' && <p className="text-xs text-muted-foreground">{t('Turned off after failing for days.')}</p>}
          </div>,
          <span className="tabular-nums">{s.pending}</span>,
          <RowActions label={t('Actions for {{name}}', { name: s.name })} actions={[
            { label: t('Deliveries'), icon: <ListOrdered />, onSelect: () => setWatching(s) },
            ...(canWrite ? [
              { label: t('Send test record'), icon: <Send />, onSelect: () => void run(async () => {
                const out = await transport.test(s.id)
                if (out.delivered) toast.success(t('Test record delivered'))
                else toast.error(t('Test record not delivered: {{reason}}', { reason: out.error || `HTTP ${out.status}` }))
              }) },
              { label: t('Edit'), icon: <Pencil />, onSelect: () => setEditing(s) },
              s.active
                ? { label: t('Disable'), icon: <Ban />, onSelect: () => void run(async () => { await transport.update(s.id, { active: false }); toast.success(t('Log stream disabled')); reload() }) }
                : { label: t('Enable'), icon: <Power />, onSelect: () => void run(async () => { await transport.enable(s.id); toast.success(t('Log stream enabled')); reload() }) },
              ...(s.destination === 'https' ? [{ label: t('Rotate signing secret'), icon: <RotateCw />, onSelect: () => setRotating(s) }] : []),
              { label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(s) },
            ] : []),
          ]} />,
        ]
      })} />
    {editing && <StreamDialog stream={editing === 'new' ? null : editing} organization={!!organization} transport={transport} onClose={() => setEditing(null)}
      onSaved={(issued, name) => { reload(); if (issued?.secret) setSecret({ title: t('Signing secret for {{name}}', { name }), value: issued.secret }) }} />}
    {removing && <ConfirmDialog title={t('Delete this log stream?')} description={t('Records not yet delivered are dropped. Records already sent stay at the destination.')} confirmLabel={t('Delete')} onClose={() => setRemoving(null)}
      confirm={async () => { await transport.remove(removing.id); toast.success(t('Log stream deleted')); reload() }} />}
    {rotating && <ConfirmDialog title={t('Rotate the signing secret?')} description={t('A new secret is generated and shown once. The old one keeps signing for a while so your receiver can switch.')} confirmLabel={t('Rotate secret')} onClose={() => setRotating(null)}
      confirm={async () => { const out = await transport.rotate(rotating.id); if (out.secret) setSecret({ title: t('Signing secret for {{name}}', { name: rotating.name }), value: out.secret }); reload() }} />}
    {secret && <Dialog open onOpenChange={o => { if (!o) setSecret(null) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{secret.title}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Copy the secret now — it is shown only once. Receivers verify each request with it (Standard Webhooks signature).')}</DialogDescription>
      <CopyField label={t('Signing secret')} value={secret.value} secret />
      <div className="flex justify-end border-t pt-4"><Button onClick={() => setSecret(null)}>{t('I have copied the secret')}</Button></div>
    </DialogContent></Dialog>}
    {watching && <DeliveriesDialog stream={watching} canWrite={canWrite} transport={transport} onClose={() => setWatching(null)} />}
  </div>
}

function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: ReactNode }) {
  return <div className="space-y-1.5"><label className="text-sm font-medium" htmlFor={id}>{label}</label>{children}{hint && <p className="text-xs text-muted-foreground">{hint}</p>}</div>
}

/** StreamDialog creates a stream or edits one. Secrets are write-only: an
 * empty field on edit keeps the stored one. */
function StreamDialog({ stream, organization, transport, onClose, onSaved }: { stream: LogStream | null; organization: boolean; transport: LogStreamsTransport; onClose: () => void; onSaved: (issued: LogStreamIssued | null, name: string) => void }) {
  const id = useId()
  const c = stream?.config ?? {}
  const [name, setName] = useState(stream?.name ?? '')
  const [destination, setDestination] = useState<Destination>(stream?.destination ?? 'datadog')
  const [site, setSite] = useState(c.site ?? DATADOG_SITES[0])
  const [service, setService] = useState(c.service ?? '')
  const [tags, setTags] = useState((c.tags ?? []).join(', '))
  const [url, setUrl] = useState(c.url ?? '')
  const [index, setIndex] = useState(c.index ?? '')
  const [source, setSource] = useState(c.source ?? '')
  const [sourcetype, setSourcetype] = useState(c.sourcetype ?? '')
  const [bucket, setBucket] = useState(c.bucket ?? '')
  const [region, setRegion] = useState(c.region ?? '')
  const [prefix, setPrefix] = useState(c.prefix ?? '')
  const [endpoint, setEndpoint] = useState(c.endpoint ?? '')
  const [pathStyle, setPathStyle] = useState(c.path_style ?? false)
  const [accessKey, setAccessKey] = useState(c.access_key_id ?? '')
  const [sources, setSources] = useState<string[]>(stream?.sources ?? ['events', 'audit_logs'])
  const [secret, setSecret] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const keep = !!stream
  const drop = <T extends Record<string, unknown>>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== '' && v !== false && !(Array.isArray(v) && !v.length)))
  const config = (): Record<string, unknown> => destination === 'datadog' ? drop({ site, service: service.trim(), tags: splitList(tags) })
    : destination === 'splunk' ? drop({ url: url.trim(), index: index.trim(), source: source.trim(), sourcetype: sourcetype.trim() })
      : destination === 's3' ? drop({ bucket: bucket.trim(), region: region.trim(), prefix: prefix.trim(), endpoint: endpoint.trim(), path_style: pathStyle, access_key_id: accessKey.trim() })
        : { url: url.trim() }
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (busy) return
    setError('')
    if (!organization && !sources.length) { setError(t('Choose at least one source.')); return }
    setBusy(true)
    try {
      if (stream) {
        const body: Record<string, unknown> = { name: name.trim(), config: config() }
        if (!organization) body.sources = sources
        if (secret && destination !== 'https') body.secret = secret
        await transport.update(stream.id, body)
        onSaved(null, name.trim())
      } else {
        const body: Record<string, unknown> = { name: name.trim(), destination, config: config() }
        if (!organization) body.sources = sources
        if (destination !== 'https') body.secret = secret
        const issued = await transport.create(body)
        onSaved(issued, name.trim())
      }
      toast.success(stream ? t('Log stream saved') : t('Log stream created'))
      onClose()
    } catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const text = (key: string, label: string, value: string, set: (v: string) => void, extra: { hint?: string; placeholder?: string; required?: boolean } = {}) =>
    <Field id={`${id}-${key}`} label={label} hint={extra.hint}><Input id={`${id}-${key}`} value={value} placeholder={extra.placeholder} required={extra.required} disabled={busy} onChange={e => set(e.target.value)} /></Field>
  return <Dialog open onOpenChange={o => { if (!o && !busy) onClose() }}><DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
    <DialogTitle className="pr-6 text-base font-semibold">{stream ? t('Edit log stream') : t('Add log stream')}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{organization ? t('Records of your organization\'s audit log are sent here, in order, at least once.') : t('Records are sent here in order, at least once. Failed deliveries are retried with backoff.')}</DialogDescription>
    <form className="space-y-4" onSubmit={submit}>
      {text('name', t('Name'), name, setName, { required: true })}
      <Field id={`${id}-destination`} label={t('Destination')}>
        <select id={`${id}-destination`} className={selectClass} value={destination} disabled={busy || keep} onChange={e => setDestination(e.target.value as Destination)}>
          {destinations.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </Field>
      {destination === 'datadog' && <>
        <Field id={`${id}-site`} label={t('Datadog site')}>
          <select id={`${id}-site`} className={selectClass} value={site} disabled={busy} onChange={e => setSite(e.target.value)}>{DATADOG_SITES.map(s => <option key={s} value={s}>{s}</option>)}</select>
        </Field>
        {text('service', t('Service'), service, setService, { hint: t('Optional. Sets the service of every record.') })}
        {text('tags', t('Tags'), tags, setTags, { hint: t('Optional, comma-separated (e.g. env:prod, team:iam).') })}
      </>}
      {destination === 'splunk' && <>
        {text('url', t('HEC endpoint URL'), url, setUrl, { placeholder: 'https://splunk.example.com:8088', required: true })}
        {text('index', t('Index'), index, setIndex, { hint: t('Optional.') })}
        {text('source', t('Source'), source, setSource, { hint: t('Optional.') })}
        {text('sourcetype', t('Source type'), sourcetype, setSourcetype, { hint: t('Optional.') })}
      </>}
      {destination === 's3' && <>
        {text('bucket', t('Bucket'), bucket, setBucket, { required: true })}
        {text('region', t('Region'), region, setRegion, { placeholder: 'us-east-1', required: true })}
        {text('prefix', t('Key prefix'), prefix, setPrefix, { hint: t('Optional. Objects are written under it.') })}
        {text('endpoint', t('Endpoint'), endpoint, setEndpoint, { hint: t('Optional. Only for S3-compatible servers.') })}
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-primary" checked={pathStyle} disabled={busy} onChange={e => setPathStyle(e.target.checked)} /> {t('Use path-style addressing')}</label>
        {text('access-key', t('Access key ID'), accessKey, setAccessKey, { required: true })}
      </>}
      {destination === 'https' && <>
        {text('url', t('Endpoint URL'), url, setUrl, { placeholder: 'https://logs.example.com/iamkit', required: true, hint: t('Requests are signed per Standard Webhooks.') })}
        {!stream && <p className="rounded-lg border bg-muted/50 p-3 text-xs text-muted-foreground">{t('A signing secret is generated and shown once after you create the stream.')}</p>}
      </>}
      {destination !== 'https' && <Field id={`${id}-secret`} label={secretLabel[destination]} hint={stream ? t('Write-only. Leave empty to keep the current one; required again when the host, bucket, region or key id changes.') : t('Write-only: it is stored sealed and never shown again.')}>
        <Input id={`${id}-secret`} type="password" autoComplete="off" value={secret} required={!stream} placeholder={stream ? t('Unchanged') : undefined} disabled={busy} onChange={e => setSecret(e.target.value)} />
      </Field>}
      {!organization && <fieldset className="space-y-2" disabled={busy}>
        <legend className="mb-1 text-sm font-medium">{t('Sources')}</legend>
        {(['events', 'audit_logs'] as const).map(source => <label key={source} className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="accent-primary" checked={sources.includes(source)} onChange={e => setSources(s => e.target.checked ? [...s, source] : s.filter(x => x !== source))} /> {sourceLabels[source]}
        </label>)}
      </fieldset>}
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
        <Button type="submit" disabled={busy}>{busy ? t('Saving…') : stream ? t('Save') : t('Create log stream')}</Button>
      </div>
    </form>
  </DialogContent></Dialog>
}

const PAGE = 20

/** DeliveriesDialog lists a stream's deliveries (newest first) and retries failed ones. */
function DeliveriesDialog({ stream, canWrite, transport, onClose }: { stream: LogStream; canWrite: boolean; transport: LogStreamsTransport; onClose: () => void }) {
  const [status, setStatus] = useState('')
  const [offset, setOffset] = useState(0)
  const [version, setVersion] = useState(0)
  const [state, setState] = useState<{ items: LogStreamDelivery[]; total: number; loading: boolean; error: string }>({ items: [], total: 0, loading: true, error: '' })
  useEffect(() => {
    const ctrl = new AbortController()
    const q = new URLSearchParams({ limit: String(PAGE), offset: String(offset) })
    if (status) q.set('status', status)
    setState(s => ({ ...s, loading: true, error: '' }))
    transport.deliveries(stream.id, q, ctrl.signal)
      .then(r => { if (!ctrl.signal.aborted) setState({ items: r.items ?? [], total: r.page?.total ?? (r.items ?? []).length, loading: false, error: '' }) })
      .catch(e => { if (!ctrl.signal.aborted) setState({ items: [], total: 0, loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [transport, stream.id, status, offset, version])
  return <Dialog open onOpenChange={o => { if (!o) onClose() }}><DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
    <DialogTitle className="pr-6 text-base font-semibold">{t('Deliveries of {{name}}', { name: stream.name })}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{t('Records are sent in batches. Failed ones can be retried.')}</DialogDescription>
    <div className="flex items-center gap-2 text-sm">
      <label className="flex items-center gap-2">{t('Status')}
        <select aria-label={t('Delivery status')} className={`${selectClass} w-40`} value={status} onChange={e => { setStatus(e.target.value); setOffset(0) }}>
          <option value="">{t('All')}</option><option value="pending">{t('Pending')}</option><option value="delivered">{t('Delivered')}</option><option value="failed">{t('Failed')}</option>
        </select>
      </label>
    </div>
    <DataTable
      columns={[t('Source'), t('Status'), { header: t('Attempts'), hideBelow: 'sm' }, { header: t('Detail'), hideBelow: 'md' }, { header: t('Queued'), nowrap: true }, ...(canWrite ? [t('Actions')] : [])]}
      loading={state.loading} error={state.error} retry={() => setVersion(v => v + 1)}
      empty={<EmptyState icon={<Waypoints />} title={t('No deliveries')} description={t('Deliveries appear here as records are queued.')} />}
      rows={state.items.map(d => {
        const [label, tone] = deliveryTones[d.status] ?? [d.status, '']
        const row: ReactNode[] = [
          sourceLabels[d.source] ?? d.source,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          <span className="tabular-nums">{d.attempts}</span>,
          <span className="block max-w-xs truncate text-xs text-muted-foreground" title={d.last_error}>{d.last_error || (d.response_status ? `HTTP ${d.response_status}` : '—')}</span>,
          <Time value={d.queued_at} />,
        ]
        if (canWrite) row.push(d.status === 'failed'
          ? <Button variant="outline" size="sm" aria-label={t('Retry delivery {{id}}', { id: d.id })} onClick={async () => {
            try { await transport.retry(stream.id, d.id); toast.success(t('Delivery queued again')); setVersion(v => v + 1) } catch (e) { toast.error(message(e)) }
          }}><RotateCw /> {t('Retry')}</Button> : null)
        return row
      })} />
    {state.total > PAGE && <div className="flex items-center justify-between text-xs text-muted-foreground">
      <span>{t('{{from}}–{{to}} of {{total}} {{noun}}', { from: offset + 1, to: Math.min(offset + PAGE, state.total), total: state.total, noun: 'deliveries' })}</span>
      <span className="flex gap-2">
        <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(o => Math.max(0, o - PAGE))}>{t('Previous page')}</Button>
        <Button variant="outline" size="sm" disabled={offset + PAGE >= state.total} onClick={() => setOffset(o => o + PAGE)}>{t('Next page')}</Button>
      </span>
    </div>}
  </DialogContent></Dialog>
}
