import { useCallback, useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { Pencil, Plus, Trash2, Zap } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { AuditLogView, type AuditPage, type AuditTransport, type ExportFormat } from '@/components/library/audit-log-view'
import { ConfirmDialog, DataTable, EmptyState, ErrorState, PageHeader, Time, splitList } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** An audit log action: the contract events of that name are validated with
 * (auditlog.Action). */
export interface AuditAction {
  id: string; name: string; description: string; target_types: string[]
  schema: { metadata?: unknown; actor?: unknown; targets?: Record<string, unknown> }
  version: number; created_at: string; updated_at: string
}
interface Named { id: string; name: string }

const tabs = [['events', t('Events')], ['actions', t('Actions')]] as const

/** AuditLogsPage is the environment's app audit log: events, and the
 * actions (event contracts) applications record against. */
export default function AuditLogsPage() {
  const { environment } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'actions' ? 'actions' : 'events'
  const show = (value: string) => setParams(value === 'events' ? {} : { tab: value }, { replace: true })
  return <div className="space-y-6">
    <PageHeader title={t('Audit logs')} description={t('What your applications record about their own users and data: who did what to which object. Stream it to your SIEM with log streams.')} />
    <div role="tablist" aria-label={t('Audit logs')} className="inline-flex rounded-lg border p-0.5">
      {tabs.map(([value, label]) => <button key={value} id={`audit-tab-${value}`} type="button" role="tab" aria-selected={tab === value} aria-controls="audit-panel" tabIndex={tab === value ? 0 : -1}
        className={cn('h-7 rounded-md px-3 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50', tab === value ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground')}
        onClick={() => show(value)}>{label}</button>)}
    </div>
    <div id="audit-panel" role="tabpanel" aria-labelledby={`audit-tab-${tab}`}>
      {tab === 'events' ? <EventsTab environment={environment ?? ''} /> : <ActionsTab environment={environment ?? ''} />}
    </div>
  </div>
}

function EventsTab({ environment }: { environment: string }) {
  const base = `/environments/${environment}/audit-logs/events`
  const orgs = useList<Named>(`/environments/${environment}/organizations?limit=100`)
  const transport = useMemo<AuditTransport>(() => ({
    list: (params, signal) => api.get<AuditPage>(`${base}${params.size ? `?${params}` : ''}`, signal),
    // A plain GET with the console's session cookie: the browser saves the stream.
    exportHref: (format: ExportFormat, params) => { const p = new URLSearchParams(params); p.set('format', format); return `/management/v1${base}/export?${p}` },
  }), [base])
  const options = useMemo<[string, string][]>(() => orgs.data.map(o => [o.id, o.name]), [orgs.data])
  return <AuditLogView transport={transport} organizations={options} />
}

const empty = '{}'
const pretty = (v: unknown) => v === undefined || v === null ? '' : JSON.stringify(v, null, 2)

function ActionsTab({ environment }: { environment: string }) {
  const path = `/environments/${environment}/audit-logs/actions`
  const list = useList<AuditAction>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [editing, setEditing] = useState<AuditAction | 'new' | null>(null)
  const [removing, setRemoving] = useState<AuditAction | null>(null)
  const add = canWrite && <Button onClick={() => setEditing('new')}><Plus /> {t('Add action')}</Button>
  return <div className="space-y-4">
    <div className="flex items-start justify-between gap-4">
      <p className="max-w-2xl text-sm text-muted-foreground">{t('An action names an event your applications record (e.g. invoice.created) and may require its metadata, actor and targets to match JSON schemas. The version grows with every change of the rules.')}</p>
      {add}
    </div>
    <DataTable
      columns={[t('Action'), { header: t('Target types'), hideBelow: 'md' }, t('Version'), { header: t('Updated'), hideBelow: 'lg', nowrap: true }, ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Zap />} title={t('No audit log actions')} description={t('Register the actions your applications record to validate their events.')} action={add || undefined} />}
      rows={list.data.map(a => {
        const row = [
          <div><p className="font-mono text-xs font-medium">{a.name}</p>{a.description && <p className="max-w-md truncate text-xs text-muted-foreground" title={a.description}>{a.description}</p>}</div>,
          <span className="flex flex-wrap gap-1">{a.target_types.map(x => <Badge key={x} variant="secondary">{x}</Badge>)}</span>,
          <span className="tabular-nums">{t('v{{version}}', { version: a.version })}</span>,
          <Time value={a.updated_at} />,
        ]
        if (canWrite) row.push(<RowActions label={t('Actions for {{name}}', { name: a.name })} actions={[
          { label: t('Edit'), icon: <Pencil />, onSelect: () => setEditing(a) },
          { label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(a) },
        ]} />)
        return row
      })} />
    {editing && <ActionDialog path={path} action={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={list.reload} />}
    {removing && <ConfirmDialog title={t('Delete {{name}}?', { name: removing.name })} description={t('Applications can no longer record this action. Events already recorded stay.')} confirmLabel={t('Delete')} onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success(t('Action deleted')); list.reload() }} />}
  </div>
}

/** parseSchema reads an optional JSON object. */
function parseSchema(label: string, raw: string): unknown {
  if (!raw.trim()) return undefined
  let v: unknown
  try { v = JSON.parse(raw) } catch { throw new Error(t('{{label}} must be valid JSON', { label })) }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error(t('{{label}} must be a JSON object', { label }))
  return v
}

/** ActionDialog creates or edits an action. The name is fixed once created;
 * the three schema editors are JSON objects (empty = no rule). On edit the
 * schema is sent whole, as the API replaces every schema at once. */
function ActionDialog({ path, action, onClose, onSaved }: { path: string; action: AuditAction | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(action?.name ?? '')
  const [description, setDescription] = useState(action?.description ?? '')
  const [types, setTypes] = useState((action?.target_types ?? []).join(', '))
  const [metadata, setMetadata] = useState(pretty(action?.schema.metadata))
  const [actor, setActor] = useState(pretty(action?.schema.actor))
  const [targets, setTargets] = useState(pretty(action?.schema.targets))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    if (busy) return
    setError('')
    setBusy(true)
    try {
      const schema: Record<string, unknown> = {}
      const m = parseSchema(t('Metadata schema'), metadata), a = parseSchema(t('Actor schema'), actor), tg = parseSchema(t('Target schemas'), targets)
      if (m) schema.metadata = m
      if (a) schema.actor = a
      if (tg) schema.targets = tg
      const target_types = splitList(types)
      if (action) await api.patch(`${path}/${action.id}`, { description: description.trim(), target_types, schema })
      else await api.post(path, { name: name.trim(), description: description.trim(), target_types, schema })
      toast.success(action ? t('Action saved') : t('Action created'))
      onSaved(); onClose()
    } catch (err) { setError(message(err)) } finally { setBusy(false) }
  }, [busy, metadata, actor, targets, types, action, path, description, name, onSaved, onClose])
  const area = (id: string, label: string, value: string, set: (v: string) => void, hint: string) => <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={`audit-action-${id}`}>{label}<span className="ml-1 font-normal text-muted-foreground">{t('(optional)')}</span></label>
    <textarea id={`audit-action-${id}`} className="min-h-24 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" spellCheck={false} placeholder={empty} value={value} disabled={busy} onChange={e => set(e.target.value)} />
    <p className="text-xs text-muted-foreground">{hint}</p>
  </div>
  return <Dialog open onOpenChange={o => { if (!o && !busy) onClose() }}><DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <DialogTitle className="pr-6 text-base font-semibold">{action ? t('Edit {{name}}', { name: action.name }) : t('Add action')}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{action ? t('Version {{version}}. Changing the target types or schemas starts a new version.', { version: action.version }) : t('Name it like resource.verb, lowercase with dots (e.g. invoice.created).')}</DialogDescription>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label className="text-sm font-medium" htmlFor="audit-action-name">{t('Name')}</label><Input id="audit-action-name" value={name} required disabled={busy || !!action} placeholder="invoice.created" onChange={e => setName(e.target.value)} /></div>
      <div className="space-y-1.5"><label className="text-sm font-medium" htmlFor="audit-action-description">{t('Description')}<span className="ml-1 font-normal text-muted-foreground">{t('(optional)')}</span></label><Input id="audit-action-description" value={description} disabled={busy} onChange={e => setDescription(e.target.value)} /></div>
      <div className="space-y-1.5"><label className="text-sm font-medium" htmlFor="audit-action-types">{t('Target types')}<span className="ml-1 font-normal text-muted-foreground">{t('(optional)')}</span></label><Input id="audit-action-types" value={types} disabled={busy} placeholder="invoice, customer" onChange={e => setTypes(e.target.value)} />
        <p className="text-xs text-muted-foreground">{t('Comma-separated lowercase names of the objects the action may be done to. Empty accepts events without targets only.')}</p></div>
      {area('metadata', t('Metadata schema'), metadata, setMetadata, t('A JSON Schema the event metadata must match.'))}
      {area('actor', t('Actor schema'), actor, setActor, t('A JSON Schema the actor metadata must match.'))}
      {area('targets', t('Target schemas'), targets, setTargets, t('A JSON object from target type to JSON Schema. Each type must be listed above.'))}
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
        <Button type="submit" disabled={busy}>{busy ? t('Saving…') : action ? t('Save') : t('Create action')}</Button>
      </div>
    </form>
  </DialogContent></Dialog>
}
