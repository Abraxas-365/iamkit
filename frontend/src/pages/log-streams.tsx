import { useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { LogStreamsView, type LogStream, type LogStreamDelivery, type LogStreamIssued, type LogStreamTest, type LogStreamsTransport } from '@/components/library/log-streams-view'
import { t } from '@/lib/i18n'

/** LogStreamsPage lists the environment's log streams: its event log and
 * app audit logs sent to Datadog, Splunk, S3 or a signed HTTPS endpoint. */
export default function LogStreamsPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const path = `/environments/${environment}/log-streams`
  const transport = useMemo<LogStreamsTransport>(() => ({
    list: signal => api.get<{ items: LogStream[] }>(path, signal),
    create: body => api.post<LogStreamIssued>(path, body),
    update: (id, body) => api.patch(`${path}/${id}`, body),
    remove: id => api.delete(`${path}/${id}`),
    test: id => api.post<LogStreamTest>(`${path}/${id}/test`, {}),
    enable: id => api.post(`${path}/${id}/enable`, {}),
    rotate: id => api.post<LogStreamIssued>(`${path}/${id}/rotate-secret`, {}),
    deliveries: (id, query, signal) => api.get<{ items: LogStreamDelivery[]; page?: { total: number; limit: number; offset: number } }>(`${path}/${id}/deliveries?${query}`, signal),
    retry: (id, delivery) => api.post(`${path}/${id}/deliveries/${delivery}/retry`, {}),
  }), [path])
  return <LogStreamsView transport={transport} canWrite={principal?.role !== 'viewer'}
    title={t('Log streams')}
    description={t('Send IAMKit\'s event log and your applications\' audit logs to your SIEM or storage, in order, at least once. Failed deliveries are retried with backoff; a stream failing for days is disabled.')} />
}
