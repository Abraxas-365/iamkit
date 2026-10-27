import { useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, CopyText, DetailSection, ErrorState, Status } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** A protected resource (oauth.ProtectedResource): an OAuth resource server
 * such as a remote MCP server, one per resource. */
export interface ProtectedResource {
  id: string; resource_id: string; uri: string; name: string; default_scopes: string[]
  idle_ttl_seconds: number; max_ttl_seconds: number; active: boolean; created_at: string
}

const days = (seconds: number) => t('{{count}} days', { count: Math.round(seconds / 86400) })

/** ProtectedResourceSection shows the resource's protected resource (its MCP
 * server) and deactivates, reactivates or deletes it. Deactivating and
 * deleting end the sessions of its authorizations, so both first ask
 * …/impact and say how many. */
export function ProtectedResourceSection({ base, resource, canWrite }: { base: string; resource: string; canWrite: boolean }) {
  const [server, setServer] = useState<ProtectedResource | null | undefined>(undefined)
  const [error, setError] = useState('')
  const [ending, setEnding] = useState<{ action: 'deactivate' | 'delete'; sessions: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const load = useCallback(() => {
    setError('')
    api.get<{ items: ProtectedResource[] }>(`${base}/protected-resources?limit=100`)
      .then(r => setServer((r.items ?? []).find(p => p.resource_id === resource) ?? null))
      .catch(e => setError(message(e)))
  }, [base, resource])
  useEffect(load, [load])
  if (server === null) return null
  const title = t('MCP server')
  if (error) return <DetailSection title={title}><ErrorState error={error} retry={load} /></DetailSection>
  if (!server) return null
  const path = `${base}/protected-resources/${server.id}`
  const ask = async (action: 'deactivate' | 'delete') => {
    setBusy(true)
    try {
      const impact = await api.get<{ active_sessions: number }>(`${path}/impact`)
      setEnding({ action, sessions: impact.active_sessions })
    } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
  }
  const actions = canWrite && <>
    {server.active
      ? <Button variant="outline" size="sm" disabled={busy} onClick={() => ask('deactivate')}>{t('Deactivate')}</Button>
      : <Button variant="outline" size="sm" disabled={busy} onClick={async () => {
        setBusy(true)
        try { await api.patch(path, { active: true }); toast.success(t('MCP server activated')); load() } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
      }}>{t('Activate')}</Button>}
    <Button variant="outline" size="sm" disabled={busy} onClick={() => ask('delete')}>{t('Delete')}</Button>
  </>
  const sessions = ending?.sessions ?? 0
  return <DetailSection title={title} description={t('This resource protects an OAuth resource server (RFC 9728), such as a remote MCP server. Clients get tokens for it with the resource parameter.')} actions={actions}>
    <dl className="grid gap-3 text-sm sm:grid-cols-2">
      <div><dt className="text-xs text-muted-foreground">{t('Resource URL')}</dt><dd className="flex items-center gap-2 break-all"><code className="font-mono text-xs">{server.uri}</code><CopyText value={server.uri} label={t('Copy resource URL')} /></dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Status')}</dt><dd><Status active={server.active} /></dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Default scopes')}</dt><dd>{server.default_scopes.length ? server.default_scopes.join(' ') : t('None')}</dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Authorization lifetime')}</dt><dd>{t('{{idle}} idle, {{max}} at most', { idle: days(server.idle_ttl_seconds), max: days(server.max_ttl_seconds) })}</dd></div>
    </dl>
    {ending?.action === 'deactivate' && <ConfirmDialog title={t('Deactivate {{name}}?', { name: server.name })}
      description={t('{{count}} active sessions of its clients end at once and their users must authorize again. Clients cannot get new tokens for it until it is activated again.', { count: sessions })}
      confirmLabel={t('Deactivate')} onClose={() => setEnding(null)}
      confirm={async () => { await api.patch(path, { active: false }); toast.success(t('MCP server deactivated')); load() }} />}
    {ending?.action === 'delete' && <ConfirmDialog title={t('Delete {{name}}?', { name: server.name })}
      description={t('{{count}} active sessions of its clients end at once and their users must authorize again. The resource parameter for its URL is refused from then on; the resource itself stays.', { count: sessions })}
      confirmLabel={t('Delete')} confirmationText={server.uri} onClose={() => setEnding(null)}
      confirm={async () => { await api.delete(path); toast.success(t('MCP server deleted')); load() }} />}
  </DetailSection>
}
