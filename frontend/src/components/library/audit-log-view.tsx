import { useEffect, useId, useState } from 'react'
import { Download, ScrollText } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { DataTable, EmptyState, Properties, Time, selectClass, splitList } from '@/components/library/patterns'
import { cn, message } from '@/lib/utils'
import { formatDateTime, t } from '@/lib/i18n'

/** An actor or target of an app audit log event. */
export interface AuditParty { type: string; id: string; name?: string; metadata?: Record<string, unknown> }
/** One app audit log event (auditlog.Event). */
export interface AuditEvent {
  seq: number; id: string; environment_id?: string; organization_id?: string; action: string; version: number; occurred_at: string
  actor: AuditParty; targets: AuditParty[]; context?: { location?: string; user_agent?: string }; metadata?: Record<string, unknown>; created_at: string
}
/** A page of events: `next` is the cursor for the next (older) page, 0 when exhausted. */
export interface AuditPage { items: AuditEvent[]; next: number }
export type ExportFormat = 'ndjson' | 'csv'

/** AuditTransport is where the events live: the management API for the
 * console, the organization's /admin routes for the portal. Exports are a
 * plain link (the console's session cookie) or a bearer request saved
 * through the browser (the portal). Keep the object stable (useMemo). */
export interface AuditTransport {
  list: (params: URLSearchParams, signal: AbortSignal) => Promise<AuditPage>
  exportHref?: (format: ExportFormat, params: URLSearchParams) => string
  save?: (format: ExportFormat, params: URLSearchParams) => Promise<void>
}

interface Filters { organization: string; action: string; actor: string; target: string; from: string; to: string }
const noFilters: Filters = { organization: '', action: '', actor: '', target: '', from: '', to: '' }

const instant = (local: string) => { const d = new Date(local); return local && !Number.isNaN(d.getTime()) ? d.toISOString() : '' }

/** filterParams turns the filters into the query the list and export share. */
export function filterParams(f: Filters): URLSearchParams {
  const p = new URLSearchParams()
  if (f.organization) p.set('organization_id', f.organization)
  const actions = splitList(f.action)
  if (actions.length) p.set('action', actions.join(','))
  if (f.actor.trim()) p.set('actor_id', f.actor.trim())
  if (f.target.trim()) p.set('target_id', f.target.trim())
  if (instant(f.from)) p.set('occurred_after', instant(f.from))
  if (instant(f.to)) p.set('occurred_before', instant(f.to))
  return p
}

/** saveBlob hands a downloaded file to the browser. */
export function saveBlob(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = name; a.click()
  URL.revokeObjectURL(url)
}

const party = (p: AuditParty) => p.name || p.id

/** AuditLogView lists the app audit log: filters, cursor "load more", a
 * detail dialog with the raw JSON and NDJSON/CSV exports of the filtered
 * events. With `organizations` it offers an organization filter. */
export function AuditLogView({ transport, organizations }: { transport: AuditTransport; organizations?: [string, string][] }) {
  const id = useId()
  const [draft, setDraft] = useState(noFilters)
  const [applied, setApplied] = useState(noFilters)
  const [state, setState] = useState<{ items: AuditEvent[]; next: number; loading: boolean; error: string }>({ items: [], next: 0, loading: true, error: '' })
  const [loadingMore, setLoadingMore] = useState(false)
  const [version, setVersion] = useState(0)
  const [open, setOpen] = useState<AuditEvent | null>(null)
  const [saving, setSaving] = useState('')
  const key = filterParams(applied).toString()
  useEffect(() => {
    const ctrl = new AbortController()
    setState({ items: [], next: 0, loading: true, error: '' })
    transport.list(new URLSearchParams(key), ctrl.signal)
      .then(page => { if (!ctrl.signal.aborted) setState({ items: page.items ?? [], next: page.next ?? 0, loading: false, error: '' }) })
      .catch(e => { if (!ctrl.signal.aborted) setState({ items: [], next: 0, loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [transport, key, version])
  const loadMore = async () => {
    setLoadingMore(true)
    try {
      const params = new URLSearchParams(key)
      params.set('before', String(state.next))
      const page = await transport.list(params, new AbortController().signal)
      setState(s => ({ ...s, items: [...s.items, ...(page.items ?? [])], next: page.next ?? 0 }))
    } catch (e) { toast.error(message(e)) } finally { setLoadingMore(false) }
  }
  const orgName = new Map(organizations)
  const set = (field: keyof Filters) => (e: { target: { value: string } }) => setDraft(d => ({ ...d, [field]: e.target.value }))
  const exportLink = (format: ExportFormat, label: string) => {
    const params = new URLSearchParams(key)
    if (transport.exportHref) return <a key={format} href={transport.exportHref(format, params)} download className={cn(buttonVariants({ variant: 'outline', size: 'sm' }))}><Download /> {label}</a>
    return <Button key={format} variant="outline" size="sm" disabled={saving !== ''} onClick={async () => {
      setSaving(format)
      try { await transport.save?.(format, params) } catch (e) { toast.error(message(e)) } finally { setSaving('') }
    }}><Download /> {label}</Button>
  }
  return <div className="space-y-4">
    <form className="flex flex-wrap items-end gap-3" aria-label={t('Filter events')} onSubmit={e => { e.preventDefault(); setApplied(draft) }}>
      {organizations && <div className="space-y-1">
        <label className="text-xs text-muted-foreground" htmlFor={`${id}-org`}>{t('Organization')}</label>
        <select id={`${id}-org`} className={cn(selectClass, 'w-48')} value={draft.organization} onChange={set('organization')}>
          <option value="">{t('All organizations')}</option>{organizations.map(([value, name]) => <option key={value} value={value}>{name}</option>)}
        </select>
      </div>}
      <div className="space-y-1"><label className="text-xs text-muted-foreground" htmlFor={`${id}-action`}>{t('Action')}</label><Input id={`${id}-action`} className="w-48" placeholder="invoice.created" value={draft.action} onChange={set('action')} /></div>
      <div className="space-y-1"><label className="text-xs text-muted-foreground" htmlFor={`${id}-actor`}>{t('Actor ID')}</label><Input id={`${id}-actor`} className="w-44" value={draft.actor} onChange={set('actor')} /></div>
      <div className="space-y-1"><label className="text-xs text-muted-foreground" htmlFor={`${id}-target`}>{t('Target ID')}</label><Input id={`${id}-target`} className="w-44" value={draft.target} onChange={set('target')} /></div>
      <div className="space-y-1"><label className="text-xs text-muted-foreground" htmlFor={`${id}-from`}>{t('From')}</label><Input id={`${id}-from`} type="datetime-local" className="w-48" value={draft.from} onChange={set('from')} /></div>
      <div className="space-y-1"><label className="text-xs text-muted-foreground" htmlFor={`${id}-to`}>{t('To')}</label><Input id={`${id}-to`} type="datetime-local" className="w-48" value={draft.to} onChange={set('to')} /></div>
      <Button type="submit" size="sm">{t('Apply filters')}</Button>
      <Button type="button" variant="ghost" size="sm" onClick={() => { setDraft(noFilters); setApplied(noFilters) }}>{t('Clear')}</Button>
      <span className="ml-auto flex flex-wrap gap-2">{exportLink('ndjson', t('Export NDJSON'))}{exportLink('csv', t('Export CSV'))}</span>
    </form>
    <DataTable
      columns={[{ header: t('When'), nowrap: true }, t('Action'), t('Actor'), { header: t('Targets'), hideBelow: 'md' }, ...(organizations ? [{ header: t('Organization'), hideBelow: 'lg' as const }] : [])]}
      loading={state.loading} error={state.error} retry={() => setVersion(v => v + 1)}
      empty={<EmptyState icon={<ScrollText />} title={t('No audit log events')} description={t('Events your applications record appear here, newest first.')} />}
      rows={state.items.map(e => [
        <Time value={e.occurred_at} />,
        <button type="button" className="font-mono text-xs font-medium text-primary hover:underline" onClick={() => setOpen(e)}>{e.action}</button>,
        <span className="flex flex-wrap items-center gap-2"><span title={e.actor.id}>{party(e.actor)}</span><Badge variant="secondary">{e.actor.type}</Badge></span>,
        <span className="block max-w-xs truncate" title={e.targets.map(party).join(', ')}>{e.targets.length ? `${e.targets[0].type}: ${party(e.targets[0])}` : '—'}{e.targets.length > 1 && ` (+${e.targets.length - 1})`}</span>,
        ...(organizations ? [e.organization_id ? orgName.get(e.organization_id) ?? e.organization_id : '—'] : []),
      ])} />
    {state.next > 0 && !state.loading && <div className="flex justify-center"><Button variant="outline" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? t('Loading…') : t('Load more')}</Button></div>}
    {open && <Dialog open onOpenChange={o => { if (!o) setOpen(null) }}><DialogContent className="sm:max-w-2xl">
      <DialogTitle className="pr-6 font-mono text-base font-semibold">{open.action}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Recorded {{when}}.', { when: formatDateTime(open.occurred_at) })}</DialogDescription>
      <Properties items={[
        [t('Event ID'), <code className="text-xs">{open.id}</code>],
        [t('Action version'), String(open.version)],
        [t('Actor'), `${open.actor.type}: ${party(open.actor)}`],
        [t('Targets'), open.targets.length ? <ul>{open.targets.map((x, i) => <li key={i}>{`${x.type}: ${party(x)}`}</li>)}</ul> : '—'],
        [t('Location'), open.context?.location || '—'],
        [t('User agent'), open.context?.user_agent || '—'],
      ]} />
      <div className="space-y-1.5">
        <p className="text-sm font-medium">{t('Event JSON')}</p>
        <pre aria-label={t('Event JSON')} className="max-h-80 overflow-auto rounded-lg border bg-muted/50 p-3 font-mono text-xs">{JSON.stringify(open, null, 2)}</pre>
      </div>
    </DialogContent></Dialog>}
  </div>
}
