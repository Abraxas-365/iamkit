import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Cloud, Laptop, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, ErrorState, FormDialog, PageHeader, Time } from '@/components/library/patterns'
import { t } from '@/lib/i18n'
import { TemplateClientDialog, useEnablePreset, type ClientPreset } from './mcp-presets'

/** oauth.AllowlistEntry. */
export interface AllowlistEntry {
  id: string; environment_id: string; protected_resource_id: string | null
  origin: string; path_prefix: string; preset: string; created_at: string
}

/** NetworkBadge says where a client connects from: "Requires public
 * exposure" for clients that run in their vendor's cloud (the MCP server and
 * IAMKit must be reachable from the internet), "Local client" for those that
 * run on the user's machine (they work on-premises behind a VPN). */
export function NetworkBadge({ preset }: { preset: Pick<ClientPreset, 'network' | 'source_ranges'> }) {
  return preset.network === 'public'
    ? <Badge variant="secondary" className="bg-warning/10 text-warning"><Cloud /> {t('Requires public exposure')}</Badge>
    : <Badge variant="secondary"><Laptop /> {t('Local client')}</Badge>
}

function PresetCard({ preset, enabled, busy, canWrite, onEnable, onCreate }: { preset: ClientPreset; enabled: boolean; busy: boolean; canWrite: boolean; onEnable: () => void; onCreate: () => void }) {
  const template = preset.mechanism === 'template'
  return <li className="flex flex-col gap-2 rounded-lg border bg-card p-4">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <h3 className="text-sm font-semibold">{preset.name}</h3>
      <div className="flex flex-wrap gap-1.5">
        <NetworkBadge preset={preset} />
        {preset.development_only && <Badge variant="outline">{t('Development')}</Badge>}
      </div>
    </div>
    {preset.network === 'public' && <p className="text-xs text-warning">
      {t('It connects from its vendor\'s cloud: your MCP server and IAMKit must be reachable from the internet. A server on-premises behind a VPN will not work.')}
      {preset.source_ranges && preset.source_ranges.length > 0 && <> {t('Source addresses:')} <code className="font-mono">{preset.source_ranges.join(', ')}</code></>}
    </p>}
    {preset.network === 'local' && <p className="text-xs text-muted-foreground">{t('It runs on the user\'s machine, so it also works with a server on-premises behind a VPN.')}</p>}
    {preset.notes && <p className="text-xs text-muted-foreground">{preset.notes}</p>}
    <p className="text-xs text-muted-foreground">{template
      ? t('Has no metadata document: you create a fixed client for it on each MCP server.')
      : t('Names itself with a metadata document: enabling it approves that document without review.')}</p>
    <div className="mt-auto pt-1">
      {template
        ? canWrite && <Button size="sm" variant="outline" disabled={busy} onClick={onCreate}><Plus className="size-3.5" /> {t('Create client from template')}</Button>
        : enabled
          ? <Badge variant="secondary" className="bg-success/10 text-success"><ShieldCheck /> {t('Enabled')}</Badge>
          : canWrite && <Button size="sm" disabled={busy} onClick={onEnable}>{busy ? t('Working…') : t('Enable')}</Button>}
    </div>
  </li>
}

function PresetGallery({ base, canWrite, entries, onChanged }: { base: string; canWrite: boolean; entries: AllowlistEntry[]; onChanged: () => void }) {
  const presets = useList<ClientPreset>(`${base}/oauth-client-presets`)
  const [template, setTemplate] = useState<ClientPreset | null>(null)
  const { busy, enable } = useEnablePreset(base, onChanged)
  const enabled = new Set(entries.filter(e => !e.protected_resource_id).map(e => e.preset))
  return <DetailSection title={t('Known clients')} description={t('Enable the clients your people use in one step.')}>
    {presets.error ? <ErrorState error={presets.error} retry={presets.reload} /> : presets.loading ? <p role="status" className="text-sm text-muted-foreground">{t('Loading data…')}</p> :
      <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {presets.data.map(p => <PresetCard key={p.key} preset={p} enabled={enabled.has(p.key)} busy={busy === p.key} canWrite={canWrite} onEnable={() => void enable(p)} onCreate={() => setTemplate(p)} />)}
      </ul>}
    {template && <TemplateClientDialog base={base} preset={template} onClose={() => setTemplate(null)} />}
  </DetailSection>
}

/** McpClientsPage is the environment's "MCP client allowlist": the metadata
 * documents admitted without review, and the catalog of known clients. */
export default function McpClientsPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const entries = useList<AllowlistEntry>(`${base}/oauth-client-allowlist?limit=100`)
  const servers = useList<{ id: string; name: string }>(`${base}/protected-resources?limit=100`)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<AllowlistEntry | null>(null)
  const serverName = (id: string | null) => id ? servers.data.find(s => s.id === id)?.name ?? id : t('Every MCP server')

  return <div className="space-y-6">
    <PageHeader title={t('MCP client allowlist')}
      description={t('MCP clients name themselves with a URL that serves their metadata. A client on this list is admitted without review; any other waits until an operator approves it on the MCP server.')}
      actions={canWrite && <Button type="button" size="sm" onClick={() => setAdding(true)}><Plus className="size-3.5" /> {t('Add entry')}</Button>} />

    <DetailSection title={t('Allowlist')} description={t('A client is admitted when its metadata URL has exactly the origin and a path under the prefix.')}>
      <DataTable
        columns={[t('Origin'), t('Path prefix'), t('Applies to'), { header: t('Added'), hideBelow: 'sm', nowrap: true }, ...(canWrite ? [t('Actions')] : [])]}
        loading={entries.loading} error={entries.error} retry={entries.reload}
        empty={<EmptyState icon={<ShieldCheck />} title={t('The allowlist is empty')} description={t('Every new client waits for an operator to approve it. Enable a known client below or add an origin.')} />}
        rows={entries.data.map(e => [
          <span className="font-medium">{e.origin}{e.preset && <Badge variant="outline" className="ml-2">{e.preset}</Badge>}</span>,
          <code className="font-mono text-xs">{e.path_prefix}</code>,
          <span className="text-sm text-muted-foreground">{serverName(e.protected_resource_id)}</span>,
          <Time value={e.created_at} />,
          ...(canWrite ? [<RowActions label={t('Actions for {{origin}}', { origin: e.origin + e.path_prefix })} actions={[
            { label: t('Remove'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(e) },
          ]} />] : []),
        ])} />
    </DetailSection>

    <PresetGallery base={base} canWrite={canWrite} entries={entries.data} onChanged={entries.reload} />

    {adding && <FormDialog title={t('Add an allowlist entry')} description={t('Clients whose metadata URL starts with this origin and path are admitted without review.')}
      submitLabel={t('Add')} success={t('Entry added')} onClose={() => setAdding(false)}
      fields={[
        { name: 'origin', label: t('Origin'), hint: t('https://host, with no port or path. For example https://tools.example.com.') },
        { name: 'path_prefix', label: t('Path prefix'), value: '/', hint: t('For example /oauth/. Use / for the whole origin.') },
        { name: 'protected_resource_id', label: t('Applies to'), type: 'dropdown', value: '', options: [{ label: t('Every MCP server'), value: '' }, ...servers.data.map(s => ({ label: s.name, value: s.id }))] },
      ]}
      submit={async d => {
        await api.post(`${base}/oauth-client-allowlist`, { origin: String(d.origin).trim(), path_prefix: String(d.path_prefix).trim(), ...(d.protected_resource_id ? { protected_resource_id: d.protected_resource_id } : {}) })
        entries.reload()
      }} />}
    {removing && <ConfirmDialog title={t('Remove {{origin}}?', { origin: removing.origin + removing.path_prefix })}
      description={t('New clients under it wait for approval again. Clients it already approved stay approved.')} confirmLabel={t('Remove')} onClose={() => setRemoving(null)}
      confirm={async () => {
        try { await api.delete(`${base}/oauth-client-allowlist/${removing.id}`) } catch (e) { toast.error(message(e)); throw e }
        toast.success(t('Entry removed')); entries.reload()
      }} />}
  </div>
}
