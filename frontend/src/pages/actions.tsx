import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Pencil, Plus, RefreshCw, Send, Trash2, Zap } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { BackLink, ConfirmDialog, CopyField, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, FormDialog, PageHeader, Properties, Time, selectClass, type Field } from '@/components/library/patterns'
import { SecretDialog } from './integrations'
import { t } from '@/lib/i18n'

/** GET /action-targets (action.Target). */
export interface ActionTarget {
  id: string; name: string; url: string; kind: 'call' | 'webhook' | 'async'; timeout_ms: number
  interrupt_on_error: boolean; created_at: string; updated_at: string
}
/** GET /action-conditions (action.Condition). */
export interface ActionCondition { name: string; description: string; deny: boolean; claims: boolean; patch?: string[] }
/** GET /action-executions (action.Execution). */
export interface ActionExecution { condition: string; targets: string[]; updated_at: string }
/** GET /action-calls (action.Call). */
export interface ActionCall {
  id: number; target_id: string; condition: string; outcome: 'ok' | 'denied' | 'failed' | 'skipped'
  status?: number; duration_ms: number; error?: string; created_at: string
}
interface Secret { id: string; secret: string }
interface TestResult { outcome: ActionCall['outcome']; status?: number; duration_ms: number; error?: string; response: Record<string, unknown> }

const kinds = [
  { value: 'call', label: t('Call'), description: t('Waits for the answer and applies it: deny, add claims, patch the request.') },
  { value: 'webhook', label: t('Webhook'), description: t('Waits for a 2xx answer and ignores the body.') },
  { value: 'async', label: t('Async'), description: t('Sent in the background; never changes or stops the flow.') },
]
const kindLabel = (k: string) => kinds.find(o => o.value === k)?.label ?? k

const outcomeTones: Record<ActionCall['outcome'], [string, string]> = {
  ok: ['OK', 'bg-success/10 text-success'],
  denied: [t('Denied'), 'bg-warning/10 text-warning'],
  failed: [t('Failed'), 'bg-destructive/10 text-destructive'],
  skipped: [t('Skipped'), 'bg-muted text-muted-foreground'],
}

/** conditionLabel turns function:pre_sign_in into "Pre sign in" style
 * text, keeping the technical name available as the id. */
export function conditionLabel(name: string) {
  const [kind, rest = ''] = name.split(':')
  const words = rest.replace(/[._]/g, ' ')
  return `${kind === 'request' ? 'Request: ' : ''}${words.charAt(0).toUpperCase()}${words.slice(1)}`
}

/** answers says what a condition's targets may answer. */
export function answers(c: ActionCondition) {
  const out: string[] = []
  if (c.deny) out.push(t('deny'))
  if (c.claims) out.push(t('add claims'))
  if (c.patch?.length) out.push(t('patch {{fields}}', { fields: c.patch.join(', ') }))
  return out.length ? out.join(' · ') : t('observe only')
}

const urlHint = t('HTTPS endpoint (http only for localhost). Requests are signed per Standard Webhooks.')
const timeoutHint = t('Milliseconds, at most 10000. Leave empty for 5000.')
const interruptHint = t('Stop the flow when the target fails or times out. Off: the flow goes on without its changes.')

function targetFields(tgt?: ActionTarget): Field[] {
  return [
    { name: 'name', label: t('Name'), value: tgt?.name },
    { name: 'url', label: t('Endpoint URL'), value: tgt?.url, hint: urlHint },
    { name: 'kind', label: t('Kind'), type: 'radio', options: kinds, value: tgt?.kind ?? 'call' },
    { name: 'timeout_ms', label: t('Timeout'), optional: true, value: tgt ? String(tgt.timeout_ms) : '', hint: timeoutHint },
    { name: 'interrupt_on_error', label: t('Interrupt on error'), type: 'checkbox', value: tgt?.interrupt_on_error ?? false, hint: interruptHint },
  ]
}
function targetBody(v: Record<string, string | boolean>) {
  return { name: v.name, url: v.url, kind: v.kind, timeout_ms: v.timeout_ms ? Number(v.timeout_ms) : 0, interrupt_on_error: v.interrupt_on_error === true }
}

/** ActionsPage: targets, which conditions call them, and recent calls. */
export default function ActionsPage() {
  const { project, environment } = useParams()
  const path = `/environments/${environment}`
  const targets = useList<ActionTarget>(`${path}/action-targets`)
  const conditions = useList<ActionCondition>(`${path}/action-conditions`)
  const executions = useList<ActionExecution>(`${path}/action-executions`)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [adding, setAdding] = useState(false)
  const [secret, setSecret] = useState<Secret | null>(null)
  const [removing, setRemoving] = useState<ActionTarget | null>(null)
  const [binding, setBinding] = useState<ActionCondition | null>(null)
  const base = `/projects/${project}/environments/${environment}/actions`
  const names = Object.fromEntries(targets.data.map(tgt => [tgt.id, tgt.name]))
  const bound = Object.fromEntries(executions.data.map(e => [e.condition, e.targets]))
  const add = canWrite && <Button onClick={() => setAdding(true)}><Plus /> {t('Add target')}</Button>
  return <div className="space-y-6">
    <PageHeader title={t('Actions')} description={t('Call your own endpoints during sign-in, token issuance and management requests: refuse a sign-in, add token claims, or adjust a request. Turn them all off with the actions feature.')} actions={targets.data.length > 0 && add} />
    <DetailSection title={t('Targets')} description={t('Endpoints IAMKit calls. Each request is signed with the target\'s secret and bounded by its timeout.')}>
      <DataTable
        columns={[t('Target'), t('Kind'), { header: t('Timeout'), hideBelow: 'sm' }, { header: t('On error'), hideBelow: 'md' }, ...(canWrite ? [t('Actions')] : [])]}
        loading={targets.loading} error={targets.error} retry={targets.reload}
        rowHref={i => `${base}/${targets.data[i].id}`}
        empty={<EmptyState icon={<Zap />} title={t('No targets')} description={t('Add an endpoint, then choose the conditions that call it.')} action={add} />}
        rows={targets.data.map(tgt => [
          <EntityRef name={tgt.name} id={tgt.url} to={`${base}/${tgt.id}`} />,
          <Badge variant="secondary">{kindLabel(tgt.kind)}</Badge>,
          <span className="tabular-nums">{tgt.timeout_ms} ms</span>,
          <span className="text-xs text-muted-foreground">{tgt.kind === 'async' ? '—' : tgt.interrupt_on_error ? t('Interrupt') : t('Continue')}</span>,
          ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: tgt.name })} actions={[{ label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(tgt) }]} />] : []),
        ])} />
    </DetailSection>
    <DetailSection title={t('Conditions')} description={t('Each condition calls its targets in order; a later target\'s claims or patch overwrite an earlier one\'s.')}>
      <DataTable
        columns={[t('Condition'), { header: t('Targets may'), hideBelow: 'md' }, t('Targets'), ...(canWrite ? [t('Actions')] : [])]}
        loading={conditions.loading || executions.loading} error={conditions.error || executions.error} retry={() => { conditions.reload(); executions.reload() }}
        empty={<EmptyState title={t('No conditions')} />}
        rows={conditions.data.map(c => [
          <EntityRef name={conditionLabel(c.name)} id={c.name} secondary={c.description} />,
          <span className="text-xs text-muted-foreground">{answers(c)}</span>,
          bound[c.name]?.length ? <span className="text-sm">{bound[c.name].map(id => names[id] ?? id).join(' → ')}</span> : <span className="text-xs text-muted-foreground">{t('None')}</span>,
          ...(canWrite ? [<Button variant="outline" size="sm" aria-label={t('Edit {{name}}', { name: c.name })} disabled={targets.data.length === 0} onClick={() => setBinding(c)}><Pencil /> {t('Edit')}</Button>] : []),
        ])} />
    </DetailSection>
    <CallLog path={path} names={names} />
    {adding && <FormDialog title={t('Add target')} description={t('The signing secret is shown once after creation.')} submitLabel={t('Add')} success="" fields={targetFields()} onClose={() => setAdding(false)} submit={async v => {
      setSecret(await api.post<Secret>(`${path}/action-targets`, targetBody(v))); targets.reload()
    }} />}
    {secret && <SigningSecret secret={secret} onClose={() => setSecret(null)} />}
    {removing && <ConfirmDialog title={t('Delete {{name}}?', { name: removing.name })} description={t('It is removed from every condition that calls it.')} confirmLabel={t('Delete')} onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${path}/action-targets/${removing.id}`); toast.success(t('Target deleted')); targets.reload(); executions.reload() }} />}
    {binding && <ExecutionDialog condition={binding} targets={targets.data} current={bound[binding.name] ?? []} path={path} onClose={() => setBinding(null)} onSaved={executions.reload} />}
  </div>
}

function SigningSecret({ secret, onClose }: { secret: Secret; onClose: () => void }) {
  return <SecretDialog title={t('Signing secret')} description={t('Copy the secret now — it is shown only once.')} confirm={t('I have saved the secret')} onClose={onClose}>
    <CopyField label={t('Secret')} value={secret.secret} secret hint={t('Verify the webhook-signature header with any Standard Webhooks library using this secret.')} />
  </SecretDialog>
}

/** ExecutionDialog picks the ordered targets a condition calls. */
function ExecutionDialog({ condition, targets, current, path, onClose, onSaved }: { condition: ActionCondition; targets: ActionTarget[]; current: string[]; path: string; onClose: () => void; onSaved: () => void }) {
  const [chosen, setChosen] = useState<string[]>(current)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const toggle = (id: string) => setChosen(c => c.includes(id) ? c.filter(x => x !== id) : [...c, id])
  const move = (i: number, by: number) => setChosen(c => { const next = [...c]; [next[i], next[i + by]] = [next[i + by], next[i]]; return next })
  const save = async () => {
    setBusy(true); setError('')
    const url = `${path}/action-executions/${encodeURIComponent(condition.name)}`
    try {
      if (chosen.length) await api.put(url, { targets: chosen })
      else if (current.length) await api.delete(url)
      toast.success(t('Saved')); onSaved(); onClose()
    } catch (e) { setError(message(e)) } finally { setBusy(false) }
  }
  const name = (id: string) => targets.find(tgt => tgt.id === id)?.name ?? id
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{conditionLabel(condition.name)}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{t('{{description}}. Targets run in the order shown.', { description: condition.description })}</DialogDescription>
    <fieldset className="space-y-2" disabled={busy}>
      <legend className="mb-1 text-sm font-medium">{t('Targets')}</legend>
      {targets.map(tgt => <label key={tgt.id} className="flex items-center gap-2 text-sm">
        <input type="checkbox" className="accent-primary" checked={chosen.includes(tgt.id)} onChange={() => toggle(tgt.id)} /> {tgt.name} <span className="text-xs text-muted-foreground">({kindLabel(tgt.kind)})</span>
      </label>)}
    </fieldset>
    {chosen.length > 1 && <ol className="space-y-1 text-sm" aria-label={t('Order')}>
      {chosen.map((id, i) => <li key={id} className="flex items-center gap-2">
        <span className="w-5 tabular-nums text-muted-foreground">{i + 1}.</span><span className="flex-1">{name(id)}</span>
        <Button type="button" variant="ghost" size="sm" aria-label={t('Move {{name}} up', { name: name(id) })} disabled={i === 0 || busy} onClick={() => move(i, -1)}>↑</Button>
        <Button type="button" variant="ghost" size="sm" aria-label={t('Move {{name}} down', { name: name(id) })} disabled={i === chosen.length - 1 || busy} onClick={() => move(i, 1)}>↓</Button>
      </li>)}
    </ol>}
    {error && <ErrorState error={error} />}
    <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button><Button disabled={busy} onClick={save}>{busy ? t('Saving…') : t('Save')}</Button></div>
  </DialogContent></Dialog>
}

/** CallLog lists recent target calls, newest first. */
function CallLog({ path, names, target }: { path: string; names: Record<string, string>; target?: string }) {
  const [outcome, setOutcome] = useState('')
  const params = new URLSearchParams()
  if (target) params.set('target_id', target)
  if (outcome) params.set('outcome', outcome)
  const query = params.toString()
  const calls = useList<ActionCall>(`${path}/action-calls${query ? `?${query}` : ''}`)
  return <DetailSection title={t('Recent calls')} description={t('Kept for 7 days. Test calls are logged too.')} actions={<Button variant="outline" size="sm" onClick={calls.reload}><RefreshCw /> {t('Refresh')}</Button>}>
    <div className="mb-3 flex items-center gap-2 text-sm"><label className="flex items-center gap-2">{t('Outcome')}
      <select aria-label={t('Outcome')} className={`${selectClass} w-40`} value={outcome} onChange={e => setOutcome(e.target.value)}>
        <option value="">{t('All')}</option><option value="ok">OK</option><option value="denied">{t('Denied')}</option><option value="failed">{t('Failed')}</option><option value="skipped">{t('Skipped')}</option>
      </select></label></div>
    <DataTable
      columns={[t('Condition'), ...(target ? [] : [t('Target')]), t('Outcome'), { header: t('Detail'), hideBelow: 'lg' }, { header: t('When'), nowrap: true }]}
      loading={calls.loading} error={calls.error} retry={calls.reload}
      empty={<EmptyState icon={<Zap />} title={t('No calls')} description={t('Calls appear here as conditions run their targets.')} />}
      rows={calls.data.map(c => {
        const [l, tone] = outcomeTones[c.outcome] ?? [c.outcome, '']
        return [
          <span className="font-mono text-xs">{c.condition}</span>,
          ...(target ? [] : [<span>{names[c.target_id] ?? c.target_id}</span>]),
          <Badge variant="secondary" className={tone}>{l}</Badge>,
          <span className="block max-w-xs truncate text-xs text-muted-foreground" title={c.error}>{[c.status && `HTTP ${c.status}`, `${c.duration_ms} ms`, c.error].filter(Boolean).join(' · ')}</span>,
          <Time value={c.created_at} />,
        ]
      })} />
  </DetailSection>
}

/** ActionTargetPage shows one target: settings, test, secret rotation and
 * its calls. */
export function ActionTargetPage() {
  const { project, environment, target } = useParams()
  const envPath = `/environments/${environment}`
  const path = `${envPath}/action-targets/${target}`
  const back = `/projects/${project}/environments/${environment}/actions`
  const [tgt, setT] = useState<ActionTarget | null>(null)
  const [error, setError] = useState('')
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [editing, setEditing] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [testing, setTesting] = useState(false)
  const [secret, setSecret] = useState<Secret | null>(null)
  const [result, setResult] = useState<TestResult | null>(null)
  const executions = useList<ActionExecution>(`${envPath}/action-executions`)
  const load = useCallback(() => { api.get<ActionTarget>(path).then(setT, e => setError(message(e))) }, [path])
  useEffect(load, [load])
  if (error) return <ErrorState error={error} retry={() => { setError(''); load() }} />
  if (!tgt) return <p className="text-sm text-muted-foreground">{t('Loading…')}</p>
  const usedBy = executions.data.filter(e => e.targets.includes(tgt.id)).map(e => e.condition)
  return <div className="space-y-6">
    <BackLink to={back}>{t('Actions')}</BackLink>
    <PageHeader title={tgt.name} description={tgt.url} actions={canWrite && <div className="flex flex-wrap gap-2">
      <Button variant="outline" onClick={() => setTesting(true)}><Send /> {t('Test')}</Button>
      <Button variant="outline" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>
      <Button variant="outline" onClick={() => setRotating(true)}><RefreshCw /> {t('Rotate secret')}</Button>
    </div>} />
    <DetailSection title={t('Target')}>
      <Properties items={[
        [t('Kind'), kindLabel(tgt.kind)],
        [t('Timeout'), `${tgt.timeout_ms} ms`],
        [t('On error'), tgt.kind === 'async' ? '—' : tgt.interrupt_on_error ? t('Interrupt the flow') : t('Continue without its changes')],
        [t('Conditions'), usedBy.length ? usedBy.join(', ') : <Link className="text-primary hover:underline" to={back}>{t('Not called yet')}</Link>],
        [t('Created'), <Time value={tgt.created_at} />],
      ] as [string, ReactNode][]} />
    </DetailSection>
    {result && <DetailSection title={t('Last test')} description={t('Test calls are logged but never applied.')}>
      <Properties items={[
        [t('Outcome'), <Badge variant="secondary" className={outcomeTones[result.outcome]?.[1]}>{outcomeTones[result.outcome]?.[0] ?? result.outcome}</Badge>],
        [t('Detail'), [result.status && `HTTP ${result.status}`, `${result.duration_ms} ms`, result.error].filter(Boolean).join(' · ')],
        [t('Answer'), <pre className="max-h-48 overflow-auto rounded bg-muted p-2 text-xs">{JSON.stringify(result.response ?? {}, null, 2)}</pre>],
      ] as [string, ReactNode][]} />
    </DetailSection>}
    <CallLog path={envPath} names={{}} target={tgt.id} />
    {editing && <FormDialog title={t('Edit target')} description={t('Changes apply to the next call.')} fields={targetFields(tgt)} onClose={() => setEditing(false)} submit={async v => { setT(await api.patch<ActionTarget>(path, targetBody(v))) }} />}
    {testing && <FormDialog title={t('Test target')} description={t('Calls the target as the condition would, without user data, and shows the answer without applying it. Use the CLI or API to send a full input.')} submitLabel={t('Send')} success="" fields={[
      { name: 'condition', label: t('Condition'), type: 'dropdown', options: ['function:pre_sign_in', 'function:pre_registration', 'function:post_federation', 'function:pre_access_token', 'function:pre_id_token', 'function:pre_userinfo', 'request:user.create', 'request:user.update', 'request:membership.create'].map(c => ({ value: c, label: c })) },
    ]} onClose={() => setTesting(false)} submit={async v => { setResult(await api.post<TestResult>(`${path}/test`, { condition: v.condition })) }} />}
    {rotating && <ConfirmDialog title={t('Rotate the signing secret?')} description={t('A new secret is generated and shown once. Both secrets sign requests for the next 24 hours.')} confirmLabel={t('Rotate')} onClose={() => setRotating(false)} confirm={async () => { setSecret(await api.post<Secret>(`${path}/rotate-secret`, {})) }} />}
    {secret && <SigningSecret secret={secret} onClose={() => setSecret(null)} />}
  </div>
}
