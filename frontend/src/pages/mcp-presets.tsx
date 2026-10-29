import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { CopyField, ErrorState, selectClass } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** oauth.PresetView: a known MCP client the environment can enable. */
export interface ClientPreset {
  key: string; name: string; mechanism: 'metadata_document' | 'template'
  metadata_url?: string; redirect_uris?: string[]; loopback_any_port?: boolean
  network: 'public' | 'local'; source_ranges?: string[]; development_only: boolean
  notes?: string; warnings: string[]
}

/** oauth.PresetResult: what enabling a preset did. */
export interface PresetResult {
  preset: string; name: string; mechanism: string; network: string; warnings: string[]
  allowlist_entry: { id: string } | null
  client: { client_id: string; redirect_uris: string[]; loopback_any_port: boolean; created: boolean } | null
}

export interface McpServer { id: string; name: string; uri: string }

/** clientSnippet is the configuration to put in the MCP client so it uses the
 * fixed client_id of a template preset. */
export function clientSnippet(preset: string, serverName: string, serverUrl: string, clientId: string): { file: string; code: string } | null {
  const name = serverName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'mcp'
  const json = (value: unknown) => JSON.stringify(value, null, 2)
  switch (preset) {
    case 'cursor': return { file: '~/.cursor/mcp.json', code: json({ mcpServers: { [name]: { url: serverUrl, auth: { CLIENT_ID: clientId } } } }) }
    case 'gemini_cli': return { file: '~/.gemini/settings.json', code: json({ mcpServers: { [name]: { httpUrl: serverUrl, oauth: { enabled: true, clientId } } } }) }
    case 'antigravity': return { file: 'mcp_config.json', code: json({ mcpServers: { [name]: { serverUrl, oauth: { clientId } } } }) }
    default: return null
  }
}

/** TemplateClientDialog creates the fixed client of a template preset
 * (Cursor, Antigravity, Gemini CLI) at a protected resource and then shows its
 * client_id and the configuration snippet. `server` fixes the server; without
 * it the dialog asks which one. */
export function TemplateClientDialog({ base, preset, server, onClose, onDone }: { base: string; preset: ClientPreset; server?: McpServer; onClose: () => void; onDone?: () => void }) {
  const servers = useList<McpServer>(server ? null : `${base}/protected-resources?limit=100`)
  const [chosen, setChosen] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<PresetResult | null>(null)
  const target = server ?? servers.data.find(s => s.id === (chosen || servers.data[0]?.id))
  const snippet = result?.client && target ? clientSnippet(preset.key, target.name, target.uri, result.client.client_id) : null
  const create = async () => {
    if (!target) return
    setBusy(true); setError('')
    try {
      const out = await api.post<PresetResult>(`${base}/protected-resources/${target.id}/client-templates`, { preset: preset.key })
      setResult(out); onDone?.()
    } catch (e) { setError(message(e)) } finally { setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{t('Create a client for {{name}}', { name: preset.name })}</DialogTitle>
    {!result && <>
      <DialogDescription className="text-muted-foreground">{t('{{name}} cannot name itself with a metadata document, so IAMKit creates a fixed public client for it, with the redirect addresses it uses. You then give its client ID to {{name2}}.', { name: preset.name, name2: preset.name })}</DialogDescription>
      {!server && <div className="space-y-1.5">
        <label htmlFor="template-server" className="text-sm font-medium">{t('MCP server')}</label>
        <select id="template-server" className={selectClass} value={chosen || servers.data[0]?.id || ''} disabled={busy || servers.loading} onChange={e => setChosen(e.target.value)}>
          {servers.data.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        {!servers.loading && !servers.error && servers.data.length === 0 && <p className="text-xs text-muted-foreground">{t('Register an MCP server on one of your resources first.')}</p>}
        {servers.error && <ErrorState error={servers.error} retry={servers.reload} />}
      </div>}
      {preset.redirect_uris && preset.redirect_uris.length > 0 && <div className="space-y-1">
        <p className="text-sm font-medium">{t('Redirect addresses')}</p>
        <ul className="space-y-0.5 text-xs">{preset.redirect_uris.map(u => <li key={u}><code className="font-mono">{u}</code></li>)}{preset.loopback_any_port && <li className="text-muted-foreground">{t('Any port on localhost is accepted.')}</li>}</ul>
      </div>}
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
        <Button type="button" disabled={busy || !target} onClick={() => void create()}>{busy ? t('Working…') : t('Create client')}</Button>
      </div>
    </>}
    {result?.client && <>
      <DialogDescription className="text-muted-foreground">{result.client.created ? t('The client is ready. Put its client ID in {{name}}.', { name: preset.name }) : t('This server already had a client for {{name}}. Put its client ID in {{name2}}.', { name: preset.name, name2: preset.name })}</DialogDescription>
      <CopyField label={t('Client ID')} value={result.client.client_id} hint={t('A public client: it has no secret.')} />
      {snippet && <div className="space-y-1.5">
        <p className="text-sm font-medium">{t('Configuration for {{name}}', { name: preset.name })} <code className="font-mono text-xs font-normal text-muted-foreground">{snippet.file}</code></p>
        <CopyField label={t('Configuration snippet')} value={snippet.code} />
      </div>}
      {preset.notes && <p className="text-xs text-muted-foreground">{preset.notes}</p>}
      <div className="flex justify-end border-t pt-4"><Button type="button" onClick={onClose}>{t('Done')}</Button></div>
    </>}
  </DialogContent></Dialog>
}

/** useEnablePreset enables a metadata-document preset in the environment. */
export function useEnablePreset(base: string, onDone: () => void) {
  const [busy, setBusy] = useState('')
  return useMemo(() => ({
    busy,
    enable: async (preset: ClientPreset) => {
      setBusy(preset.key)
      try {
        await api.post<PresetResult>(`${base}/oauth-client-presets`, { preset: preset.key })
        toast.success(t('{{name}} enabled', { name: preset.name })); onDone()
      } catch (e) { toast.error(message(e)) } finally { setBusy('') }
    },
  }), [base, busy, onDone])
}
