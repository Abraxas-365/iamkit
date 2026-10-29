import { useEffect, useMemo, useState } from 'react'
import { BadgeCheck, Plug, Unplug } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useList } from '@/hooks/use-list'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, Time } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** oauth.ConnectedApp: a client the user let reach a protected resource (an
 * MCP server), in one organization. */
export interface ConnectedApp {
  client: { id: string; client_id: string; source: string; name: string; host: string; logo_uri: string; preset: string; verified_name: string }
  protected_resource_id: string; resource: string; resource_name: string; organization_id: string
  scopes: string[] | null; consented_at: string | null; active_sessions: number; last_used_at: string | null
}

/** AppIdentity names the client as IAMKit can vouch for it: the preset's
 * verified name, else the client_id's host with its own name marked unverified;
 * the server only sends a logo served from the client_id's host. */
export function AppIdentity({ app }: { app: ConnectedApp }) {
  const c = app.client
  return <div className="flex min-w-0 items-start gap-2.5">
    {c.logo_uri ? <img src={c.logo_uri} alt="" className="mt-0.5 size-7 shrink-0 rounded object-contain" referrerPolicy="no-referrer" /> : null}
    <div className="min-w-0 space-y-0.5">
      {c.verified_name
        ? <p className="flex items-center gap-1 text-sm font-semibold">{c.verified_name} <BadgeCheck className="size-3.5 text-success" aria-label={t('Verified')} /></p>
        : <p className="truncate font-mono text-sm font-semibold" title={c.client_id}>{c.host || c.client_id}</p>}
      {c.verified_name
        ? c.host && <p className="font-mono text-xs text-muted-foreground">{c.host}</p>
        : c.name && <p className="text-xs text-muted-foreground">{c.name} <Badge variant="outline" className="ml-1">{t('Unverified')}</Badge></p>}
    </div>
  </div>
}

const label = (a: ConnectedApp) => a.client.verified_name || a.client.host || a.client.client_id

/** UserConnectedApps lists the applications a user connected to MCP servers
 * (…/users/:id/connected-apps) and disconnects one: its consent is revoked and
 * its sessions for the user end at once, so it must ask again. */
export function UserConnectedApps({ base, userId, userLabel, canWrite }: { base: string; userId: string; userLabel: string; canWrite: boolean }) {
  const path = `${base}/users/${userId}/connected-apps`
  const list = useList<ConnectedApp>(path)
  const [orgs, setOrgs] = useState<Record<string, string>>({})
  const [disconnecting, setDisconnecting] = useState<ConnectedApp | null>(null)
  const ids = useMemo(() => [...new Set(list.data.map(a => a.organization_id))].join(','), [list.data])
  useEffect(() => {
    for (const id of ids.split(',').filter(id => id && !orgs[id])) {
      api.get<{ name: string }>(`${base}/organizations/${id}`).then(o => setOrgs(m => ({ ...m, [id]: o.name }))).catch(() => undefined)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids, base])
  return <DetailSection title={t('Connected apps')} description={t('Applications this user let reach an MCP server, such as an AI assistant, and what they agreed to.')}>
    <DataTable
      columns={[t('Application'), t('MCP server'), { header: t('Organization'), hideBelow: 'md' }, { header: t('Scopes'), hideBelow: 'lg' }, { header: t('Connected'), nowrap: true, hideBelow: 'md' }, { header: t('Last used'), nowrap: true, hideBelow: 'lg' }, { header: t('Sessions'), hideBelow: 'md' }, ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Plug />} title={t('No connected apps')} description={t('An app appears here once this user authorizes it for an MCP server.')} />}
      rows={list.data.map(a => [
        <AppIdentity app={a} />,
        <span title={a.resource}>{a.resource_name || a.resource}</span>,
        orgs[a.organization_id] ?? <span className="font-mono text-xs">{a.organization_id}</span>,
        a.scopes?.length ? <span className="break-all font-mono text-xs">{a.scopes.join(' ')}</span> : <span className="text-muted-foreground">{t('Granted by an administrator')}</span>,
        <Time value={a.consented_at} />,
        <Time value={a.last_used_at} />,
        String(a.active_sessions),
        ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: label(a) })} actions={[{ label: t('Disconnect'), icon: <Unplug />, destructive: true, onSelect: () => setDisconnecting(a) }]} />] : []),
      ])} />
    {disconnecting && <ConfirmDialog title={t('Disconnect {{name}}?', { name: label(disconnecting) })}
      description={t('{{user}}\'s consent is revoked and its {{count}} active sessions end at once. The app must ask {{user}} again to reconnect.', { user: userLabel, count: disconnecting.active_sessions })}
      confirmLabel={t('Disconnect')} onClose={() => setDisconnecting(null)}
      confirm={async () => {
        await api.delete(`${path}/${disconnecting.client.id}?organization_id=${encodeURIComponent(disconnecting.organization_id)}`)
        toast.success(t('{{name}} disconnected', { name: label(disconnecting) })); list.reload()
      }} />}
  </DetailSection>
}
