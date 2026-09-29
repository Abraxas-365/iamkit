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

export interface LogoutDelivery {
  id: string; client_id: string; application_name: string; session_id: string; user_id: string; user_email: string
  status: 'pending' | 'delivered' | 'failed'; attempts: number; last_error: string
  created_at: string; next_attempt_at: string | null; delivered_at: string | null; failed_at: string | null
}

const tones: Record<LogoutDelivery['status'], [string, string]> = {
  pending: ['Retrying', 'bg-warning/10 text-warning'],
  delivered: ['Delivered', 'bg-success/10 text-success'],
  failed: ['Failed', 'bg-destructive/10 text-destructive'],
}

/** deliveryDetail summarizes where a notification stands. */
export function deliveryDetail(d: LogoutDelivery) {
  const tries = `${d.attempts} ${d.attempts === 1 ? 'attempt' : 'attempts'}`
  if (d.status === 'delivered') return tries
  if (d.status === 'pending' && d.attempts === 0) return 'Queued'
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
    try { await api.post(`${path}/${d.id}/retry`, {}); toast.success('Delivery queued again'); list.reload() } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const filter = (key: string, value: string) => { const next = new URLSearchParams(params); if (value) next.set(key, value); else next.delete(key); setParams(next, { replace: true }) }
  return <div className="space-y-6">
    <PageHeader title="Logout deliveries" description="Back-channel logout notifications sent to applications when their users' sessions end. Failed deliveries are retried with backoff for about an hour, then given up." />
    <div className="flex flex-wrap items-center gap-3">
      <label className="flex items-center gap-2 text-sm">Status
        <select aria-label="Status" className={`${selectClass} w-40`} value={status} onChange={e => filter('status', e.target.value)}>
          <option value="">All</option><option value="failed">Failed</option><option value="pending">Retrying</option><option value="delivered">Delivered</option>
        </select>
      </label>
      {client && <button type="button" className="text-xs text-primary hover:underline" onClick={() => filter('client_id', '')}>Show all clients</button>}
    </div>
    <PaginationBar state={list} noun="deliveries" placeholder="Filter by user email or application" />
    <DataTable
      columns={['User', { header: 'Application', hideBelow: 'md' }, 'Status', { header: 'Detail', hideBelow: 'lg' }, { header: 'Session ended', nowrap: true }, 'Actions']}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Radio />} title="No logout deliveries" description="OAuth clients with a back-channel logout URL are notified here when a session they signed in ends." />}
      rows={list.data.map(d => {
        const [label, tone] = tones[d.status]
        return [
          <EntityRef name={d.user_email || d.user_id} id={d.user_id} />,
          <EntityRef name={d.application_name || 'OAuth client'} id={d.client_id} to={`${base}/oauth-clients/${d.client_id}`} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          <span className="block max-w-xs truncate text-xs text-muted-foreground" title={d.last_error}>{deliveryDetail(d)}</span>,
          <Time value={d.created_at} />,
          principal?.role !== 'viewer' && d.status === 'failed' && <RowActions label={`Actions for delivery to ${d.application_name || d.client_id}`} actions={[{ label: busy === d.id ? 'Retrying…' : 'Retry delivery', icon: <RotateCw />, onSelect: () => void retry(d) }]} />,
        ]
      })} />
  </div>
}
