import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { describeUserAgent } from '@/lib/user-agent'
import { actionLabels, captchaLabels, detectionLabels, detections, methodLabels, outcomeLabels, outcomes, outcomeTones, reasonLabels, surfaceLabels, type SignInAttempt } from '@/lib/risk'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { CopyText, DataTable, EmptyState, Properties, Time, selectClass } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

interface Page { items: SignInAttempt[]; next?: string }
interface Filters { user_id: string; ip: string; outcome: string; detection: string; country: string }
const noFilters: Filters = { user_id: '', ip: '', outcome: '', detection: '', country: '' }

/** OutcomeBadge names what happened to a sign-in attempt. */
export function OutcomeBadge({ outcome }: { outcome: string }) {
  return <Badge variant="secondary" className={outcomeTones[outcome]}>{outcomeLabels[outcome] ?? outcome}</Badge>
}

/** SignInAttempts lists the environment's sign-in attempts, newest first
 * (GET …/sign-in-attempts, keyset `before`), with a detail drawer. With
 * `userId` it shows only that user's attempts and no filters. */
export function SignInAttempts({ userId, limit = 50 }: { userId?: string; limit?: number }) {
  const { project, environment } = useParams()
  const base = `/environments/${environment}/sign-in-attempts`
  const [draft, setDraft] = useState<Filters>(noFilters)
  const [filters, setFilters] = useState<Filters>(noFilters)
  const [items, setItems] = useState<SignInAttempt[]>([])
  const [next, setNext] = useState<string | undefined>()
  const [state, setState] = useState({ loading: true, more: false, error: '' })
  const [version, setVersion] = useState(0)
  const [open, setOpen] = useState<SignInAttempt | null>(null)
  const latest = useRef(0)

  useEffect(() => { const id = setTimeout(() => setFilters(draft), 300); return () => clearTimeout(id) }, [draft])

  const query = useCallback((before?: string) => {
    const p = new URLSearchParams({ limit: String(limit) })
    for (const [k, v] of Object.entries(userId ? { ...filters, user_id: userId } : filters)) if (v.trim()) p.set(k, k === 'country' ? v.trim().toUpperCase() : v.trim())
    if (before) p.set('before', before)
    return `${base}?${p}`
  }, [base, filters, userId, limit])

  useEffect(() => {
    const run = ++latest.current
    setState({ loading: true, more: false, error: '' })
    api.get<Page>(query()).then(page => {
      if (run !== latest.current) return
      setItems(page.items ?? []); setNext(page.next || undefined); setState({ loading: false, more: false, error: '' })
    }).catch(e => { if (run === latest.current) { setItems([]); setNext(undefined); setState({ loading: false, more: false, error: message(e) }) } })
  }, [query, version])

  const loadMore = () => {
    const run = latest.current
    setState(s => ({ ...s, more: true }))
    api.get<Page>(query(next)).then(page => {
      if (run !== latest.current) return
      setItems(list => [...list, ...(page.items ?? [])]); setNext(page.next || undefined); setState(s => ({ ...s, more: false }))
    }).catch(e => { if (run === latest.current) setState(s => ({ ...s, more: false, error: message(e) })) })
  }

  const set = (patch: Partial<Filters>) => setDraft(d => ({ ...d, ...patch }))
  const userLink = (id: string) => `/projects/${project}/environments/${environment}/users/${id}`
  const filtered = Object.values(filters).some(Boolean)

  return <div className="space-y-4">
    {!userId && <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <Input aria-label={t('Filter by user ID')} placeholder={t('User ID')} value={draft.user_id} onChange={e => set({ user_id: e.target.value })} />
      <Input aria-label={t('Filter by IP address')} placeholder={t('IP address')} value={draft.ip} onChange={e => set({ ip: e.target.value })} />
      <select aria-label={t('Filter by outcome')} className={selectClass} value={draft.outcome} onChange={e => set({ outcome: e.target.value })}>
        <option value="">{t('Any outcome')}</option>{outcomes.map(o => <option key={o} value={o}>{outcomeLabels[o]}</option>)}
      </select>
      <select aria-label={t('Filter by detection')} className={selectClass} value={draft.detection} onChange={e => set({ detection: e.target.value })}>
        <option value="">{t('Any detection')}</option>{detections.map(d => <option key={d} value={d}>{detectionLabels[d]}</option>)}
      </select>
      <Input aria-label={t('Filter by country')} placeholder={t('Country (US)')} maxLength={2} value={draft.country} onChange={e => set({ country: e.target.value })} />
    </div>}
    <DataTable
      columns={[{ header: t('When'), nowrap: true }, t('Outcome'), { header: t('IP address'), nowrap: true }, { header: t('Country'), hideBelow: 'md' }, { header: t('Method'), hideBelow: 'md' }, { header: t('Detections'), hideBelow: 'lg' }, { header: t('Action'), hideBelow: 'lg' }, '']}
      loading={state.loading} error={state.error} retry={() => setVersion(v => v + 1)}
      empty={<EmptyState icon={<ShieldAlert />} title={filtered ? t('No attempts match') : t('No sign-in attempts')} description={filtered ? t('Try other filters.') : t('Attempts are recorded when the risk_signals feature is on.')} />}
      rows={items.map(a => [
        <Time value={a.created_at} />,
        <OutcomeBadge outcome={a.outcome} />,
        a.ip ? <span className="font-mono text-xs">{a.ip}</span> : '—',
        a.country || '—',
        methodLabels[a.method] ?? a.method,
        a.detections?.length ? <span className="flex flex-wrap gap-1">{a.detections.map(d => <Badge key={d} variant="outline">{detectionLabels[d] ?? d}</Badge>)}</span> : '—',
        a.action && a.action !== 'none' ? actionLabels[a.action] ?? a.action : '—',
        <Button variant="ghost" size="sm" onClick={() => setOpen(a)} aria-label={t('Details of the attempt {{when}}', { when: new Date(a.created_at).toISOString() })}>{t('Details')}</Button>,
      ])} />
    {next && <div className="flex justify-center"><Button variant="outline" disabled={state.more} onClick={loadMore}>{state.more ? t('Loading…') : t('Load more')}</Button></div>}
    <Sheet open={!!open} onOpenChange={o => { if (!o) setOpen(null) }}>
      <SheetContent className="left-auto right-0 w-full overflow-y-auto border-l border-r-0 data-ending-style:translate-x-10 data-starting-style:translate-x-10 sm:max-w-md">
        {open && <>
          <SheetHeader><SheetTitle>{t('Sign-in attempt')}</SheetTitle><SheetDescription><Time value={open.created_at} /></SheetDescription></SheetHeader>
          <div className="px-4 pb-4"><Properties items={[
            [t('Outcome'), <OutcomeBadge outcome={open.outcome} />],
            ...(open.reason ? [[t('Reason'), reasonLabels[open.reason] ?? open.reason] as [string, React.ReactNode]] : []),
            [t('IP address'), open.ip ? <span className="font-mono text-xs">{open.ip}</span> : '—'],
            [t('Country'), open.country || '—'],
            ...(open.latitude != null && open.longitude != null ? [[t('Location'), <span className="font-mono text-xs">{open.latitude.toFixed(2)}, {open.longitude.toFixed(2)}</span>] as [string, React.ReactNode]] : []),
            [t('Device'), open.device ? t('Device recognised by its id') : t('No device id sent')],
            [t('Browser'), open.user_agent ? <span title={open.user_agent}>{describeUserAgent(open.user_agent, 80)}</span> : '—'],
            [t('Method'), methodLabels[open.method] ?? open.method],
            [t('Surface'), surfaceLabels[open.surface] ?? open.surface],
            [t('Detections'), open.detections?.length ? <span className="flex flex-wrap gap-1">{open.detections.map(d => <Badge key={d} variant="outline">{detectionLabels[d] ?? d}</Badge>)}</span> : t('None')],
            [t('Action'), actionLabels[open.action] ?? open.action ?? '—'],
            [t('CAPTCHA'), open.captcha ? captchaLabels[open.captcha] ?? open.captcha : t('Not checked')],
            [t('User'), open.user_id ? <span className="flex flex-wrap items-center gap-2"><Link className="text-primary hover:underline" to={userLink(open.user_id)}>{t('View user')}</Link><CopyText value={open.user_id} short label={t('Copy user ID')} /></span> : t('Unknown account')],
            [t('Attempt ID'), <CopyText value={open.id} short label={t('Copy attempt ID')} />],
          ]} /></div>
        </>}
      </SheetContent>
    </Sheet>
  </div>
}
