import { useCallback, useEffect, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Link, useParams } from 'react-router-dom'
import { ConfirmDialog, CopyText, DetailSection, ErrorState, Status, SwitchField, selectClass } from '@/components/library/patterns'
import { rich, t } from '@/lib/i18n'
import { ClientsSection } from './resource-clients'
import { TemplateClientDialog, type ClientPreset } from './mcp-presets'
import { useList } from '@/hooks/use-list'
import { ProtectPrompt, type ProtectableResource } from './resource-protect'

/** A protected resource (oauth.ProtectedResource): an OAuth resource server
 * such as a remote MCP server, one per resource. */
export interface ProtectedResource {
  id: string; resource_id: string; uri: string; name: string; default_scopes: string[]
  idle_ttl_seconds: number; max_ttl_seconds: number; active: boolean; created_at: string
  /** Whether clients may name themselves with a metadata document URL. */
  allow_client_metadata?: boolean
  /** Whether clients registered at /oauth/register (RFC 7591) may ask for it. */
  allow_dynamic_registration?: boolean
  /** How a new external client is admitted: only through the allowlist (or an approval), or any. */
  client_admission?: 'allowlist' | 'open'
}

/** DynamicRegistrationOff tells that the environment's feature is off, so the
 * server's switch has no effect until it is turned on. */
function DynamicRegistrationOff({ base }: { base: string }) {
  const [on, setOn] = useState<boolean | null>(null)
  useEffect(() => { api.get<{ enabled: boolean }>(`${base}/features/dynamic_client_registration`).then(f => setOn(f.enabled)).catch(() => setOn(null)) }, [base])
  const { project, environment } = useParams()
  if (on !== false) return null
  return <p role="status" className="text-xs text-warning">
    {rich('The {{feature}} feature is off for this environment, so this has no effect. Turn it on under {{link}}.', { feature: <code>{'dynamic_client_registration'}</code>, link: <Link className="underline" to={`/projects/${project}/environments/${environment}/features`}>{t('Features (beta)')}</Link> })}
  </p>
}

/** TemplatePicker offers the template presets (Cursor, Antigravity, Gemini CLI)
 * and creates their fixed client on this server. */
function TemplatePicker({ base, server, onDone }: { base: string; server: ProtectedResource; onDone: () => void }) {
  const presets = useList<ClientPreset>(`${base}/oauth-client-presets`)
  const templates = presets.data.filter(p => p.mechanism === 'template')
  const [key, setKey] = useState('')
  const [open, setOpen] = useState<ClientPreset | null>(null)
  if (templates.length === 0) return null
  return <div className="flex flex-wrap items-center gap-2">
    <select aria-label={t('Client template')} className={`${selectClass} w-auto`} value={key || templates[0].key} onChange={e => setKey(e.target.value)}>
      {templates.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}
    </select>
    <Button type="button" variant="outline" size="sm" onClick={() => setOpen(templates.find(p => p.key === (key || templates[0].key)) ?? null)}>{t('Create client from template')}</Button>
    {open && <TemplateClientDialog base={base} preset={open} server={server} onClose={() => setOpen(null)} onDone={onDone} />}
  </div>
}

const days = (seconds: number) => t('{{count}} days', { count: Math.round(seconds / 86400) })

/** ProtectedResourceSection shows the resource's protected resource (its MCP
 * server) and deactivates, reactivates or deletes it. Deactivating and
 * deleting end the sessions of its authorizations, so both first ask
 * …/impact and say how many. A resource without one offers to protect it
 * (ProtectPrompt). */
export function ProtectedResourceSection({ base, resource: target, canWrite }: { base: string; resource: ProtectableResource; canWrite: boolean }) {
  const resource = target.id
  const [server, setServer] = useState<ProtectedResource | null | undefined>(undefined)
  const [error, setError] = useState('')
  const [ending, setEnding] = useState<{ action: 'deactivate' | 'delete'; sessions: number; clients: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [opening, setOpening] = useState(false)
  const [version, setVersion] = useState(0)
  const { project, environment } = useParams()
  const load = useCallback(() => {
    setError('')
    api.get<{ items: ProtectedResource[] }>(`${base}/protected-resources?limit=100`)
      .then(r => setServer((r.items ?? []).find(p => p.resource_id === resource) ?? null))
      .catch(e => setError(message(e)))
  }, [base, resource])
  useEffect(load, [load])
  if (server === null) return canWrite ? <ProtectPrompt base={base} resource={target} onCreated={load} /> : null
  const title = t('MCP server')
  if (error) return <DetailSection title={title}><ErrorState error={error} retry={load} /></DetailSection>
  if (!server) return null
  const path = `${base}/protected-resources/${server.id}`
  const ask = async (action: 'deactivate' | 'delete') => {
    setBusy(true)
    try {
      const impact = await api.get<{ active_sessions: number; external_clients?: number }>(`${path}/impact`)
      setEnding({ action, sessions: impact.active_sessions, clients: impact.external_clients ?? 0 })
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
  // The server's metadata-document clients are forgotten with it, and blocked from it when it is
  // deactivated. Clients made from templates belong to the application: they stay, only their sessions end.
  const clients = (action: 'deactivate' | 'delete') => !ending || ending.clients === 0 ? '' : ' ' + (action === 'delete'
    ? t('{{count}} clients with a metadata document are forgotten with it; clients created from templates stay.', { count: ending.clients })
    : t('{{count}} clients with a metadata document cannot use it until it is activated again.', { count: ending.clients }))
  const patch = async (body: Record<string, unknown>, done: string) => {
    setBusy(true)
    try { await api.patch(path, body); toast.success(done); load(); setVersion(v => v + 1) } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
  }
  const allowlistHref = `/projects/${project}/environments/${environment}/mcp-clients`
  return <><DetailSection title={title} description={t('This resource protects an OAuth resource server (RFC 9728), such as a remote MCP server. Clients get tokens for it with the resource parameter.')} actions={actions}>
    <dl className="grid gap-3 text-sm sm:grid-cols-2">
      <div><dt className="text-xs text-muted-foreground">{t('Resource URL')}</dt><dd className="flex items-center gap-2 break-all"><code className="font-mono text-xs">{server.uri}</code><CopyText value={server.uri} label={t('Copy resource URL')} /></dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Status')}</dt><dd><Status active={server.active} /></dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Default scopes')}</dt><dd>{server.default_scopes.length ? server.default_scopes.join(' ') : t('None')}</dd></div>
      <div><dt className="text-xs text-muted-foreground">{t('Authorization lifetime')}</dt><dd>{t('{{idle}} idle, {{max}} at most', { idle: days(server.idle_ttl_seconds), max: days(server.max_ttl_seconds) })}</dd></div>
    </dl>
    <div className="space-y-3 border-t pt-4">
      <h3 className="text-sm font-semibold">{t('Client settings')}</h3>
      <SwitchField label={t('Allow clients with a metadata document')} hint={t('Clients such as Claude or VS Code name themselves with a URL (client_id) that serves their metadata. Off, only registered clients and the ones you create from templates can use this server.')}
        checked={server.allow_client_metadata ?? false} disabled={!canWrite || busy} onCheckedChange={v => void patch({ allow_client_metadata: v }, v ? t('Metadata-document clients allowed') : t('Metadata-document clients refused'))} />
      <SwitchField label={t('Allow dynamically registered clients')} hint={t('Clients without a metadata document register themselves at /oauth/register (RFC 7591) and get a dcr_ client ID. IAMKit cannot verify who they are, so no allowlist entry admits them: each waits for an approval unless admission is open.')}
        checked={server.allow_dynamic_registration ?? false} disabled={!canWrite || busy} onCheckedChange={v => void patch({ allow_dynamic_registration: v }, v ? t('Dynamically registered clients allowed') : t('Dynamically registered clients refused'))} />
      {server.allow_dynamic_registration && <DynamicRegistrationOff base={base} />}
      {(server.allow_client_metadata || server.allow_dynamic_registration) && <div className="space-y-1.5">
        <label htmlFor="client-admission" className="text-sm font-medium">{t('Client admission')}</label>
        <select id="client-admission" className={`${selectClass} max-w-md`} value={server.client_admission ?? 'allowlist'} disabled={!canWrite || busy}
          onChange={e => e.target.value === 'open' ? setOpening(true) : void patch({ client_admission: 'allowlist' }, t('Admission set to allowlist'))}>
          <option value="allowlist">{t('Allowlist: others wait for approval')}</option>
          <option value="open">{t('Open: any client is admitted')}</option>
        </select>
        {(server.client_admission ?? 'allowlist') === 'open'
          ? <p className="text-xs text-warning">{t('Any client that serves a valid metadata document is admitted without review. Anyone on the internet can have their client ask your users for access.')}</p>
          : <p className="text-xs text-muted-foreground">{rich('Clients on the {{link}} are admitted at once; any other waits until an operator approves it below.', { link: <Link className="underline" to={allowlistHref}>{t('MCP client allowlist')}</Link> })}</p>}
      </div>}
    </div>
    {canWrite && <TemplatePicker base={base} server={server} onDone={() => setVersion(v => v + 1)} />}
    {opening && <ConfirmDialog title={t('Admit any client?')} description={t('Every client that serves a valid metadata document is admitted without review. Anyone can then make their client ask your users for access. Use it for development only.')}
      confirmLabel={t('Admit any client')} onClose={() => setOpening(false)}
      confirm={async () => { await api.patch(path, { client_admission: 'open' }); toast.success(t('Admission set to open')); load() }} />}
    {ending?.action === 'deactivate' && <ConfirmDialog title={t('Deactivate {{name}}?', { name: server.name })}
      description={t('{{count}} active sessions of its clients end at once and their users must authorize again. Clients cannot get new tokens for it until it is activated again.', { count: sessions }) + clients('deactivate')}
      confirmLabel={t('Deactivate')} onClose={() => setEnding(null)}
      confirm={async () => { await api.patch(path, { active: false }); toast.success(t('MCP server deactivated')); load() }} />}
    {ending?.action === 'delete' && <ConfirmDialog title={t('Delete {{name}}?', { name: server.name })}
      description={t('{{count}} active sessions of its clients end at once and their users must authorize again. The resource parameter for its URL is refused from then on; the resource itself stays.', { count: sessions }) + clients('delete')}
      confirmLabel={t('Delete')} confirmationText={server.uri} onClose={() => setEnding(null)}
      confirm={async () => { await api.delete(path); toast.success(t('MCP server deleted')); load() }} />}
  </DetailSection>
  <ClientsSection path={path} canWrite={canWrite} refresh={`${server.allow_client_metadata}${server.allow_dynamic_registration}${version}`} />
  </>
}
