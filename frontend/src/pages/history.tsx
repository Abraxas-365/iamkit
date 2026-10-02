import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, History } from 'lucide-react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { CopyText, DataTable, DetailSection, EmptyState, Time } from '@/components/library/patterns'
import { describeEvent } from './activity'
import { t } from '@/lib/i18n'

interface HistoryEvent { id: number; type: string; actor: { kind: string; id?: string }; data?: { changes?: Record<string, [unknown, unknown]> }; occurred_at: string }
interface HistoryPage { items: HistoryEvent[]; next: number }

const actorKinds: Record<string, string> = { user: t('End user'), service_account: t('Service account'), system: t('System'), directory: t('Directory (SCIM)') }

/** changeValue renders one side of a change compactly. */
export function changeValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '∅'
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

/** Changes lists an update's fields as field: old → new. */
export function Changes({ changes }: { changes?: Record<string, [unknown, unknown]> }) {
  const fields = Object.keys(changes ?? {}).sort()
  if (!changes || fields.length === 0) return null
  return <ul className="mt-1 space-y-0.5 text-xs">
    {fields.map(f => <li key={f} className="break-all"><span className="font-mono text-muted-foreground">{f}</span>{': '}
      <span className="line-through decoration-muted-foreground/60">{changeValue(changes[f][0])}</span>{' → '}<span>{changeValue(changes[f][1])}</span></li>)}
  </ul>
}

/** HistorySection shows one entity's events, newest first, with what each
 * update changed. path is the entity's API path (…/users/:id); a new
 * refresh value (the reloaded entity) fetches the history again. */
export function HistorySection({ path, refresh }: { path: string; refresh?: unknown }) {
  const [cursors, setCursors] = useState<number[]>([0])
  const [state, setState] = useState<{ page: HistoryPage | null; loading: boolean; error: string }>({ page: null, loading: true, error: '' })
  const [version, setVersion] = useState(0)
  const before = cursors[cursors.length - 1]
  useEffect(() => {
    const controller = new AbortController()
    const params = new URLSearchParams({ limit: '20' })
    if (before) params.set('before', String(before))
    setState(s => ({ ...s, loading: true, error: '' }))
    api.get<HistoryPage>(`${path}/history?${params}`, controller.signal)
      .then(page => { if (!controller.signal.aborted) setState({ page, loading: false, error: '' }) })
      .catch(e => { if (!controller.signal.aborted) setState({ page: null, loading: false, error: message(e) }) })
    return () => controller.abort()
  }, [path, before, version, refresh])
  const page = state.page
  return <DetailSection title={t('History')} description={t('Every recorded change and sign-in event, newest first. Secrets and password hashes are never recorded.')}
    actions={<div className="flex gap-2">
      <Button variant="outline" size="icon" className="size-7" disabled={cursors.length === 1} onClick={() => setCursors(c => c.slice(0, -1))} aria-label={t('Newer history')}><ChevronLeft className="size-4" /></Button>
      <Button variant="outline" size="icon" className="size-7" disabled={!page?.next} onClick={() => page && setCursors(c => [...c, page.next])} aria-label={t('Older history')}><ChevronRight className="size-4" /></Button>
    </div>}>
    <DataTable
      columns={[t('Event'), { header: t('By'), hideBelow: 'md' }, { header: t('When'), nowrap: true }]}
      loading={state.loading} error={state.error} retry={() => setVersion(v => v + 1)}
      empty={<EmptyState icon={<History />} title={t('No history')} description={t('Changes appear here once they are made. Events older than the retention period are pruned.')} />}
      rows={(page?.items ?? []).map(e => [
        <div><span className="font-medium">{describeEvent(e.type)}</span><Changes changes={e.data?.changes} /></div>,
        <span className="flex flex-wrap items-center gap-2">{e.actor.id ? <CopyText value={e.actor.id} short label={t('Copy actor ID')} /> : null}{actorKinds[e.actor.kind] && <Badge variant="secondary">{actorKinds[e.actor.kind]}</Badge>}</span>,
        <Time value={e.occurred_at} />,
      ])} />
  </DetailSection>
}
