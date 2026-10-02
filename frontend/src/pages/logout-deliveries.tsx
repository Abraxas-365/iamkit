import { useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { Radio, RotateCw } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { DataTable, EmptyState, EntityRef, PageHeader, Time, selectClass } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

export interface LogoutDelivery {
  id: string; client_id: string; application_name: string; session_id: string; user_id: string; user_email: string
  status: 'pending' | 'delivered' | 'failed'; attempts: number; last_error: string
  created_at: string; next_attempt_at: string | null; delivered_at: string | null; failed_at: string | null
}

const tones: Record<LogoutDelivery['status'], [string, string]> = {
  pending: [t('Retrying'), 'bg-warning/10 text-warning'],
  delivered: [t('Delivered'), 'bg-success/10 text-success'],
  failed: [t('Failed'), 'bg-destructive/10 text-destructive'],
}

/** deliveryDetail summarizes where a notification stands. */
export function deliveryDetail(d: LogoutDelivery) {
  const tries = t('{{count}} attempts', { count: d.attempts })
  if (d.status === 'delivered') return tries
  if (d.status === 'pending' && d.attempts === 0) return t('Queued')
  return d.last_error ? `${tries} · ${d.last_error}` : tries
}

/** LogoutDeliveriesPage lists back-channel logout notifications: which
 * application was told that a session ended, and the ones given up on. */
export default function LogoutDeliveriesPage() {
  const { project, environment } = useParams()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? ''
  const client = params.get('client_id') ?? ''
  const extraParams = useMemo(() => Object.fromEntries(Object.entries({ status, client_id: client }).filter(([, v]) => v)), [status, client])
  const path = `/environments/${environment}/logout-deliveries`
  const list = usePaginatedList<LogoutDelivery>(path, { extraParams })
  const { principal } = useAuth()
  const [busy, setBusy] = useState('')
  const base = `/projects/${project}/environments/${environment}`
  const retry = async (d: LogoutDelivery) => {
    setBusy(d.id)
    try { await api.post(`${path}/${d.id}/retry`, {}); toast.success(t('Delivery queued again')); list.reload() } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const filter = (key: string, value: string) => { const next = new URLSearchParams(params); if (value) next.set(key, value); else next.delete(key); setParams(next, { replace: true }) }
  return <div className="space-y-6">
    <PageHeader title={t('Logout deliveries')} description={t('Back-channel logout notifications sent to applications when their users\' sessions end. Failed deliveries are retried with backoff for about an hour, then given up.')} />
    <div className="flex flex-wrap items-center gap-3">
      <label className="flex items-center gap-2 text-sm">{t('Status')}
        <select aria-label={t('Status')} className={`${selectClass} w-40`} value={status} onChange={e => filter('status', e.target.value)}>
          <option value="">{t('All')}</option><option value="failed">{t('Failed')}</option><option value="pending">{t('Retrying')}</option><option value="delivered">{t('Delivered')}</option>
        </select>
      </label>
      {client && <button type="button" className="text-xs text-primary hover:underline" onClick={() => filter('client_id', '')}>{t('Show all clients')}</button>}
    </div>
    <PaginationBar state={list} noun="deliveries" placeholder={t('Filter by user email or application')} />
    <DataTable
      columns={[t('User'), { header: t('Application'), hideBelow: 'md' }, t('Status'), { header: t('Detail'), hideBelow: 'lg' }, { header: t('Session ended'), nowrap: true }, t('Actions')]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Radio />} title={t('No logout deliveries')} description={t('OAuth clients with a back-channel logout URL are notified here when a session they signed in ends.')} />}
      rows={list.data.map(d => {
        const [label, tone] = tones[d.status]
        return [
          <EntityRef name={d.user_email || d.user_id} id={d.user_id} />,
          <EntityRef name={d.application_name || 'OAuth client'} id={d.client_id} to={`${base}/oauth-clients/${d.client_id}`} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          <span className="block max-w-xs truncate text-xs text-muted-foreground" title={d.last_error}>{deliveryDetail(d)}</span>,
          <Time value={d.created_at} />,
          principal?.role !== 'viewer' && d.status === 'failed' && <RowActions label={t('Actions for delivery to {{value}}', { value: d.application_name || d.client_id })} actions={[{ label: busy === d.id ? t('Retrying…') : t('Retry delivery'), icon: <RotateCw />, onSelect: () => void retry(d) }]} />,
        ]
      })} />
  </div>
}
