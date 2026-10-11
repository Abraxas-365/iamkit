import { useMemo } from 'react'
import { AuditLogView, saveBlob, type AuditPage, type AuditTransport, type ExportFormat } from '@/components/library/audit-log-view'
import { LogStreamsView, type LogStream, type LogStreamDelivery, type LogStreamIssued, type LogStreamTest, type LogStreamsTransport } from '@/components/library/log-streams-view'
import { PageHeader } from '@/components/library/patterns'
import { useAdmin } from './context'
import { t } from '@/lib/i18n'

/** Permissions of the organization's audit logs and log streams. Streams
 * are readable with either; changing them needs the write one. */
export const AUDIT_READ = 'iam:org:audit:read'
export const STREAMS_WRITE = 'iam:org:log-streams:write'

/** AuditLogsPage is the organization's app audit log (/admin/audit-logs):
 * the events recorded with this organization, filtered and exportable. */
export function AuditLogsPage() {
  const { client } = useAdmin()
  const transport = useMemo<AuditTransport>(() => ({
    list: (params, signal) => client.get<AuditPage>(`/audit-logs${params.size ? `?${params}` : ''}`, signal),
    // The export needs the bearer token, so it is fetched and saved here.
    save: async (format: ExportFormat, params) => {
      const p = new URLSearchParams(params); p.set('format', format)
      saveBlob(`audit-logs.${format}`, await client.download(`/audit-logs/export?${p}`))
    },
  }), [client])
  return <div className="space-y-6">
    <PageHeader title={t('Audit logs')} description={t('What your organization\'s applications recorded: who did what to which object.')} />
    <AuditLogView transport={transport} />
  </div>
}

/** LogStreamsPage manages the organization's own log streams (/admin/log-streams):
 * its audit log events sent to Datadog, Splunk, S3 or a signed HTTPS endpoint. */
export function LogStreamsPage() {
  const { client, can } = useAdmin()
  const transport = useMemo<LogStreamsTransport>(() => ({
    list: signal => client.get<{ items: LogStream[] }>('/log-streams', signal),
    create: body => client.post<LogStreamIssued>('/log-streams', body),
    update: (id, body) => client.patch(`/log-streams/${id}`, body),
    remove: id => client.delete(`/log-streams/${id}`),
    test: id => client.post<LogStreamTest>(`/log-streams/${id}/test`, {}),
    enable: id => client.post(`/log-streams/${id}/enable`, {}),
    rotate: id => client.post<LogStreamIssued>(`/log-streams/${id}/rotate-secret`, {}),
    deliveries: (id, query, signal) => client.get<{ items: LogStreamDelivery[]; page?: { total: number; limit: number; offset: number } }>(`/log-streams/${id}/deliveries?${query}`, signal),
    retry: (id, delivery) => client.post(`/log-streams/${id}/deliveries/${delivery}/retry`, {}),
  }), [client])
  return <LogStreamsView transport={transport} canWrite={can(STREAMS_WRITE)} organization
    title={t('Log streams')} description={t('Send your organization\'s audit log events to your SIEM or storage, in order, at least once. Failed deliveries are retried with backoff.')} />
}
