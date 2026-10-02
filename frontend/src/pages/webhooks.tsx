import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { Ban, Pencil, Play, Plus, Power, RefreshCw, RotateCw, Send, Trash2, Webhook } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { BackLink, ConfirmDialog, CopyField, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, FormDialog, PageHeader, Properties, Time, selectClass, splitList } from '@/components/library/patterns'
import { SecretDialog } from './integrations'
import { t } from '@/lib/i18n'

export interface Subscription {
  id: string; name: string; url: string; types: string[]; active: boolean; disabled_reason?: string
  failing_since?: string | null; previous_secret_expires_at?: string | null; pending: number; created_at: string; updated_at: string
}
export interface WebhookDelivery {
  id: number; event_id: number; event_type: string; status: 'pending' | 'delivered' | 'failed'; attempts: number
  next_attempt_at?: string | null; response_status?: number | null; last_error?: string; queued_at: string; finished_at?: string | null
}
interface Secret { id: string; secret: string }

/** subscriptionState names where a subscription stands. */
export function subscriptionState(s: Subscription): [string, string] {
  if (!s.active) return [s.disabled_reason === 'failing' ? t('Disabled (failing)') : t('Disabled'), 'bg-muted text-muted-foreground']
  if (s.failing_since) return [t('Failing'), 'bg-destructive/10 text-destructive']
  return [t('Active'), 'bg-success/10 text-success']
}

const deliveryTones: Record<WebhookDelivery['status'], [string, string]> = {
  pending: [t('Pending'), 'bg-warning/10 text-warning'],
  delivered: [t('Delivered'), 'bg-success/10 text-success'],
  failed: [t('Failed'), 'bg-destructive/10 text-destructive'],
}

const typesHint = t('Event types or families, comma-separated (e.g. user.created, membership.*). Leave empty for every event.')
const urlHint = t('HTTPS endpoint (http only for localhost). Requests are signed per Standard Webhooks.')

/** WebhooksPage lists the environment's event webhook subscriptions. */
export default function WebhooksPage() {
  const { project, environment } = useParams()
  const path = `/environments/${environment}/webhooks`
  const list = useList<Subscription>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [adding, setAdding] = useState(false)
  const [secret, setSecret] = useState<Secret | null>(null)
  const [removing, setRemoving] = useState<Subscription | null>(null)
  const base = `/projects/${project}/environments/${environment}/webhooks`
  const add = canWrite && <Button onClick={() => setAdding(true)}><Plus /> {t('Add webhook')}</Button>
  return <div className="space-y-6">
    <PageHeader title={t('Webhooks')} description={t('Push events from the event log to your endpoints, in order, signed per Standard Webhooks. Failed deliveries are retried with backoff for 24 hours; an endpoint failing for three days is disabled.')} actions={list.data.length > 0 && add} />
    <DataTable
      columns={[t('Webhook'), { header: t('Events'), hideBelow: 'md' }, t('Status'), { header: t('Pending'), hideBelow: 'sm' }, ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      rowHref={i => `${base}/${list.data[i].id}`}
      empty={<EmptyState icon={<Webhook />} title={t('No webhooks')} description={t('Nothing is sent until you add one. Each webhook receives the events it subscribes to, from the moment it is created.')} action={add} />}
      rows={list.data.map(s => {
        const [label, tone] = subscriptionState(s)
        return [
          <EntityRef name={s.name} id={s.url} to={`${base}/${s.id}`} />,
          <span className="text-xs text-muted-foreground">{s.types.length ? s.types.join(', ') : t('All events')}</span>,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          <span className="tabular-nums">{s.pending}</span>,
          ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: s.name })} actions={[{ label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(s) }]} />] : []),
        ]
      })} />
    {adding && <FormDialog title={t('Add webhook')} description={t('The signing secret is shown once after creation.')} submitLabel={t('Add')} success="" fields={[
      { name: 'name', label: t('Name') },
      { name: 'url', label: t('Endpoint URL'), hint: urlHint },
      { name: 'types', label: t('Events'), type: 'list', optional: true, hint: typesHint },
    ]} onClose={() => setAdding(false)} submit={async v => {
      const out = await api.post<Secret>(path, { name: v.name, url: v.url, types: splitList(v.types) })
      setSecret(out); list.reload()
    }} />}
    {secret && <SigningSecret secret={secret} onClose={() => setSecret(null)} />}
    {removing && <ConfirmDialog title={t('Delete {{name}}?', { name: removing.name })} description={t('Its pending deliveries are dropped and nothing more is sent to the endpoint.')} confirmLabel={t('Delete')} onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success(t('Webhook deleted')); list.reload() }} />}
  </div>
}

function SigningSecret({ secret, onClose }: { secret: Secret; onClose: () => void }) {
  return <SecretDialog title={t('Signing secret')} description={t('Copy the secret now — it is shown only once.')} confirm={t('I have saved the secret')} onClose={onClose}>
    <CopyField label={t('Secret')} value={secret.secret} secret hint={t('Verify the webhook-signature header with any Standard Webhooks library using this secret.')} />
  </SecretDialog>
}

/** WebhookDetailPage shows one subscription, its delivery log and its
 * operations (test, rotate, replay, enable/disable). */
export function WebhookDetailPage() {
  const { project, environment, webhook } = useParams()
  const path = `/environments/${environment}/webhooks/${webhook}`
  const back = `/projects/${project}/environments/${environment}/webhooks`
  const [sub, setSub] = useState<Subscription | null>(null)
  const [error, setError] = useState('')
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [editing, setEditing] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [replaying, setReplaying] = useState(false)
  const [secret, setSecret] = useState<Secret | null>(null)
  const [busy, setBusy] = useState('')
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? ''
  const extraParams = useMemo(() => status ? { status } : undefined, [status])
  const deliveries = usePaginatedList<WebhookDelivery>(`${path}/deliveries`, { extraParams })
  const load = useCallback(() => { api.get<Subscription>(path).then(setSub, e => setError(message(e))) }, [path])
  useEffect(load, [load])
  if (error) return <ErrorState error={error} retry={() => { setError(''); load() }} />
  if (!sub) return <p className="text-sm text-muted-foreground">{t('Loading…')}</p>
  const [label, tone] = subscriptionState(sub)
  const run = async (key: string, fn: () => Promise<void>) => { setBusy(key); try { await fn() } catch (e) { toast.error(message(e)) } finally { setBusy('') } }
  const test = () => run('test', async () => {
    const out = await api.post<{ delivered: boolean; status?: number; error?: string }>(`${path}/test`, {})
    if (out.delivered) toast.success(t('Test event delivered (HTTP {{status}})', { status: out.status }))
    else toast.error(t('Test event not delivered: {{reason}}', { reason: out.error || `HTTP ${out.status}` }))
  })
  const toggle = () => run('toggle', async () => { await api.patch(path, { active: !sub.active }); toast.success(sub.active ? t('Webhook disabled') : t('Webhook enabled')); load() })
  const retry = (d: WebhookDelivery) => run(`retry-${d.id}`, async () => { await api.post(`${path}/deliveries/${d.id}/retry`, {}); toast.success(t('Delivery queued again')); deliveries.reload(); load() })
  const filter = (value: string) => { const next = new URLSearchParams(params); if (value) next.set('status', value); else next.delete('status'); setParams(next, { replace: true }) }
  return <div className="space-y-6">
    <BackLink to={back}>{t('Webhooks')}</BackLink>
    <PageHeader title={sub.name} description={sub.url} actions={canWrite && <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={!!busy} onClick={test}><Send /> {busy === 'test' ? t('Sending…') : t('Send test event')}</Button>
      <Button variant="outline" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>
      <Button variant="outline" disabled={!!busy} onClick={toggle}>{sub.active ? <><Ban /> {t('Disable')}</> : <><Power /> {t('Enable')}</>}</Button>
    </div>} />
    <DetailSection title={t('Subscription')}>
      <Properties items={[
        [t('Status'), <Badge variant="secondary" className={tone}>{label}</Badge>],
        [t('Events'), sub.types.length ? sub.types.join(', ') : t('All events')],
        [t('Pending deliveries'), sub.pending],
        ...(sub.failing_since ? [[t('Failing since'), <Time value={sub.failing_since} />] as [string, ReactNode]] : []),
        ...(sub.previous_secret_expires_at ? [[t('Previous secret valid until'), <Time value={sub.previous_secret_expires_at} />] as [string, ReactNode]] : []),
        [t('Created'), <Time value={sub.created_at} />],
      ]} />
    </DetailSection>
    {canWrite && <DetailSection title={t('Secret and replay')} description={t('Rotating keeps signing with the previous secret too for 24 hours, so receivers can switch over. Replay queues the matching events from an event id again (at most 10,000).')}>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setRotating(true)}><RefreshCw /> {t('Rotate secret')}</Button>
        <Button variant="outline" onClick={() => setReplaying(true)}><Play /> {t('Replay events')}</Button>
        <Link className="self-center text-sm text-primary hover:underline" to={`/projects/${project}/environments/${environment}/audit-events`}>{t('Open the event log')}</Link>
      </div>
    </DetailSection>}
    <DetailSection title={t('Deliveries')}>
      <div className="mb-3 flex items-center gap-2 text-sm"><label className="flex items-center gap-2">{t('Status')}
        <select aria-label={t('Status')} className={`${selectClass} w-40`} value={status} onChange={e => filter(e.target.value)}>
          <option value="">{t('All')}</option><option value="pending">{t('Pending')}</option><option value="failed">{t('Failed')}</option><option value="delivered">{t('Delivered')}</option>
        </select></label></div>
      <PaginationBar state={deliveries} noun="deliveries" />
      <DataTable
        columns={[t('Event'), t('Status'), { header: t('Detail'), hideBelow: 'lg' }, { header: t('Queued'), nowrap: true }, ...(canWrite ? [t('Actions')] : [])]}
        loading={deliveries.loading} error={deliveries.error} retry={deliveries.reload}
        empty={<EmptyState icon={<Webhook />} title={t('No deliveries')} description={t('Events this webhook subscribes to appear here as they are sent.')} />}
        rows={deliveries.data.map(d => {
          const [l, tone] = deliveryTones[d.status]
          const tries = t('{{count}} attempts', { count: d.attempts })
          return [
            <EntityRef name={d.event_type} id={String(d.event_id)} />,
            <Badge variant="secondary" className={tone}>{l}</Badge>,
            <span className="block max-w-xs truncate text-xs text-muted-foreground" title={d.last_error}>{d.status === 'pending' && d.attempts === 0 ? t('Queued') : d.last_error ? `${tries} · ${d.last_error}` : tries}</span>,
            <Time value={d.queued_at} />,
            ...(canWrite ? [d.status === 'failed' ? <RowActions label={t('Actions for delivery {{id}}', { id: d.id })} actions={[{ label: busy === `retry-${d.id}` ? t('Retrying…') : t('Retry delivery'), icon: <RotateCw />, onSelect: () => void retry(d) }]} /> : null] : []),
          ]
        })} />
    </DetailSection>
    {editing && <FormDialog title={t('Edit webhook')} description={t('Changes apply to events queued from now on.')} fields={[
      { name: 'name', label: t('Name'), value: sub.name },
      { name: 'url', label: t('Endpoint URL'), value: sub.url, hint: urlHint },
      { name: 'types', label: t('Events'), type: 'list', optional: true, value: sub.types.join(', '), hint: typesHint },
    ]} onClose={() => setEditing(false)} submit={async v => { await api.patch(path, { name: v.name, url: v.url, types: splitList(v.types) }); load() }} />}
    {rotating && <ConfirmDialog title={t('Rotate the signing secret?')} description={t('A new secret is generated and shown once. Both secrets sign requests for the next 24 hours.')} confirmLabel={t('Rotate')} onClose={() => setRotating(false)} confirm={async () => { setSecret(await api.post<Secret>(`${path}/rotate-secret`, {})); load() }} />}
    {replaying && <FormDialog title={t('Replay events')} description={t('Queue the events this webhook subscribes to again, starting at an event id (see the event log).')} submitLabel={t('Replay')} success="" fields={[
      { name: 'from', label: t('From event id') },
    ]} onClose={() => setReplaying(false)} submit={async v => {
      const out = await api.post<{ queued: number }>(`${path}/replay`, { from: Number(v.from) })
      toast.success(t('{{count}} events queued', { count: out.queued })); deliveries.reload(); load()
    }} />}
    {secret && <SigningSecret secret={secret} onClose={() => setSecret(null)} />}
  </div>
}
