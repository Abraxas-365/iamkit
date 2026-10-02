import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, PageHeader, Time } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** GET /limits (usage.Limits): deployment caps, the environment's own
 * limits and the effective (tighter) values; a missing name is unlimited. */
export interface Limits {
  deployment: Record<string, number>
  environment: Record<string, number>
  effective: Record<string, number>
  updated_at?: string
}

/** GET /usage (usage.Report). */
export interface Report {
  days: { day: string; metrics: Record<string, number> }[]
  totals: Record<string, number>
  now: { name: string; count: number; max: number | null }[]
}

/** The limit catalog (usage.Catalog), in display order. */
const LIMITS: [string, string][] = [
  ['users_max', t('Users')],
  ['organizations_max', t('Organizations')],
  ['applications_max', t('Applications')],
  ['requests_per_minute', t('API requests per minute')],
  ['emails_per_day', t('Emails per day')],
  ['sms_per_day', t('SMS per day')],
  ['action_calls_per_minute', t('Action calls per minute')],
]

/** The metrics (usage.Metrics), in display order. */
const METRICS: [string, string][] = [
  ['logins', t('Sign-ins')],
  ['users_created', t('Users created')],
  ['tokens', t('Tokens issued')],
  ['emails', t('Emails sent')],
  ['sms', t('SMS sent')],
  ['action_calls', t('Action calls')],
  ['api_requests', t('API requests')],
]

const RANGES = [7, 30, 90]
const number = (n: number) => n.toLocaleString()

/** UsagePage shows the environment's usage and its limits; workspace
 * owners tighten the limits below the deployment's caps. */
export default function UsagePage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const isOwner = principal?.role === 'owner'
  const base = `/environments/${environment}`
  const [days, setDays] = useState(30)
  const [report, setReport] = useState<Report | null>(null)
  const [limits, setLimits] = useState<Limits | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const fill = (l: Limits) => {
    setLimits(l)
    setDraft(Object.fromEntries(LIMITS.map(([name]) => [name, l.environment[name] === undefined ? '' : String(l.environment[name])])))
  }
  const load = useCallback(() => {
    setError('')
    Promise.all([api.get<Report>(`${base}/usage?days=${days}`), api.get<Limits>(`${base}/limits`)])
      .then(([r, l]) => { setReport(r); fill(l) })
      .catch(e => setError(message(e)))
  }, [base, days])
  useEffect(load, [load])

  const header = <PageHeader title={t('Usage and limits')} description={t('What this environment used per UTC day, and the limits that bound it. Limits set on the server (IAMKIT_LIMITS) are ceilings; this environment can only tighten them.')} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!report || !limits) return <div role="status" className="space-y-6">{header}<Skeleton className="h-48" /><span className="sr-only">{t('Loading usage…')}</span></div>

  const save = async (e: FormEvent) => {
    e.preventDefault()
    const body: Record<string, number | null> = {}
    for (const [name] of LIMITS) body[name] = draft[name].trim() === '' ? null : Number(draft[name])
    setSaving(true)
    try {
      fill(await api.put<Limits>(`${base}/limits`, body))
      toast.success(t('Limits saved'))
    } catch (err) { toast.error(message(err)) } finally { setSaving(false) }
  }
  const unlimited = t('Unlimited')
  const shown = (v: number | undefined) => v === undefined ? unlimited : number(v)
  const peak = Math.max(1, ...report.days.map(d => METRICS.reduce((n, [m]) => n + (d.metrics[m] ?? 0), 0)))

  return <div className="space-y-6">{header}
    <DetailSection title={t('Now')} description={t('What exists in this environment against its limits.')}>
      <dl className="grid gap-3 sm:grid-cols-3">
        {report.now.map(x => {
          const label = LIMITS.find(([name]) => name === x.name)?.[1] ?? x.name
          const share = x.max ? Math.min(100, Math.round(x.count / x.max * 100)) : 0
          return <div key={x.name} className="space-y-1.5 rounded-lg border p-3">
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="text-sm font-medium">{x.max === null ? number(x.count) : t('{{used}} of {{max}}', { used: number(x.count), max: number(x.max) })}</dd>
            {x.max !== null && <div className="h-1.5 rounded bg-muted" role="progressbar" aria-label={label} aria-valuenow={share} aria-valuemin={0} aria-valuemax={100}>
              <div className={share >= 90 ? 'h-full rounded bg-destructive' : 'h-full rounded bg-primary'} style={{ width: `${share}%` }} />
            </div>}
          </div>
        })}
      </dl>
    </DetailSection>
    <DetailSection title={t('Daily usage')} description={t('Sign-ins and created users are added about a minute after they happen; the rest within 30 seconds.')}
      actions={<div className="flex gap-1">{RANGES.map(n => <Button key={n} type="button" size="sm" variant={n === days ? 'secondary' : 'ghost'} aria-pressed={n === days} onClick={() => setDays(n)}>{t('{{count}} days', { count: n })}</Button>)}</div>}>
      <div className="space-y-4">
        <dl className="grid gap-3 sm:grid-cols-4">
          {METRICS.map(([m, label]) => <div key={m} className="rounded-lg border p-3"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="text-sm font-medium">{number(report.totals[m] ?? 0)}</dd></div>)}
        </dl>
        <div className="flex h-24 items-end gap-px" aria-hidden="true">
          {report.days.map(d => {
            const n = METRICS.reduce((sum, [m]) => sum + (d.metrics[m] ?? 0), 0)
            return <div key={d.day} title={`${d.day}: ${number(n)}`} className="flex-1 rounded-t bg-primary/70" style={{ height: `${Math.max(n ? 4 : 1, n / peak * 100)}%` }} />
          })}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t('Daily usage')}</caption>
            <thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="py-1.5 pr-3 font-medium">{t('Day (UTC)')}</th>{METRICS.map(([m, label]) => <th key={m} className="px-3 py-1.5 text-right font-medium">{label}</th>)}</tr></thead>
            <tbody>{[...report.days].reverse().map(d => <tr key={d.day} className="border-b last:border-0">
              <td className="py-1.5 pr-3 whitespace-nowrap">{d.day}</td>
              {METRICS.map(([m]) => <td key={m} className="px-3 py-1.5 text-right tabular-nums">{number(d.metrics[m] ?? 0)}</td>)}
            </tr>)}</tbody>
          </table>
        </div>
      </div>
    </DetailSection>
    <DetailSection title={t('Limits')} description={limits.updated_at ? <>{t('Leave a field empty to keep the server\'s cap.')} <Time value={limits.updated_at} prefix={t('Changed')} /></> : t('Leave a field empty to keep the server\'s cap.')}>
      <form className="space-y-4" onSubmit={e => void save(e)}>
        <div className="grid gap-4 sm:grid-cols-2">
          {LIMITS.map(([name, label]) => {
            const id = `limit-${name}`
            return <div key={name} className="space-y-1.5">
              <label htmlFor={id} className="text-sm font-medium">{label}</label>
              <Input id={id} type="number" inputMode="numeric" min={0} placeholder={unlimited} value={draft[name] ?? ''} disabled={!isOwner || saving} aria-describedby={`${id}-hint`}
                onChange={e => setDraft(d => ({ ...d, [name]: e.target.value }))} />
              <p id={`${id}-hint`} className="text-xs text-muted-foreground">{t('Server: {{deployment}} · in effect: {{effective}}', { deployment: shown(limits.deployment[name]), effective: shown(limits.effective[name]) })}</p>
            </div>
          })}
        </div>
        {isOwner ? <Button type="submit" disabled={saving}>{t('Save limits')}</Button> : <p className="text-sm text-muted-foreground">{t('Only workspace owners change limits.')}</p>}
      </form>
    </DetailSection>
  </div>
}
