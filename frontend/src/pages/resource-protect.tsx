import { useEffect, useId, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { DetailSection, ErrorState, selectClass } from '@/components/library/patterns'
import { rich, t } from '@/lib/i18n'

const DAY = 86400

/** The resource fields the create form needs (authorization.Resource). */
export interface ProtectableResource { id: string; name: string; audience: string; permissions: string[] }

interface Policy { max_idle_ttl_seconds: number; max_lifetime_ttl_seconds: number }

/** ProtectPrompt is the MCP server section of a resource that has none yet:
 * it explains what protecting does and opens ProtectDialog. */
export function ProtectPrompt({ base, resource, onCreated }: { base: string; resource: ProtectableResource; onCreated: () => void }) {
  const [open, setOpen] = useState(false)
  return <DetailSection title={t('MCP server')} description={t('Protect this resource as an OAuth resource server (RFC 9728), such as a remote MCP server. Clients like Claude Code, Codex or VS Code then get tokens for its URL with the resource parameter.')}
    actions={<Button variant="outline" size="sm" onClick={() => setOpen(true)}>{t('Protect as MCP server')}</Button>}>
    <p className="text-sm text-muted-foreground">{t('This resource is not an MCP server.')}</p>
    {open && <ProtectDialog base={base} resource={resource} onClose={() => setOpen(false)} onCreated={onCreated} />}
  </DetailSection>
}

/** ProtectDialog creates the resource's protected resource (POST
 * …/protected-resources). Its URL is the resource's audience; the
 * application must already be linked to the resource. */
export function ProtectDialog({ base, resource, onClose, onCreated }: { base: string; resource: ProtectableResource; onClose: () => void; onCreated: () => void }) {
  const id = useId()
  const { project, environment } = useParams()
  const applications = useList<{ id: string; name: string }>(`${base}/applications?resource_id=${encodeURIComponent(resource.id)}&limit=100`)
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [application, setApplication] = useState('')
  const [name, setName] = useState(resource.name)
  const [scopes, setScopes] = useState<string[]>([])
  const [idle, setIdle] = useState(7)
  const [max, setMax] = useState(30)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    api.get<Policy>(`${base}/protected-resource-policy`, controller.signal).then(setPolicy).catch(() => { /* the server checks the ceilings anyway */ })
    return () => controller.abort()
  }, [base])
  const chosen = application || applications.data[0]?.id || ''
  const idleCap = policy ? Math.floor(policy.max_idle_ttl_seconds / DAY) : undefined
  const maxCap = policy ? Math.floor(policy.max_lifetime_ttl_seconds / DAY) : undefined
  const none = !applications.loading && !applications.error && applications.data.length === 0
  const toggle = (p: string) => setScopes(s => s.includes(p) ? s.filter(x => x !== p) : [...s, p])
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (busy || !chosen) return
    setBusy(true); setError('')
    try {
      await api.post(`${base}/protected-resources`, { application_id: chosen, resource_id: resource.id, name: name.trim(), default_scopes: scopes, idle_ttl_seconds: idle * DAY, max_ttl_seconds: max * DAY })
      toast.success(t('MCP server created'))
      onCreated(); onClose()
    } catch (e) { setError(message(e)) } finally { setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{t('Protect as MCP server')}</DialogTitle>
    <DialogDescription className="text-muted-foreground">{t('Its URL is the resource audience: MCP clients ask for tokens with it, and only the clients of the application you choose can use it until you allow others.')}</DialogDescription>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1">
        <p className="text-sm font-medium">{t('Resource URL')}</p>
        <code className="block break-all font-mono text-xs">{resource.audience}</code>
        <p className="text-xs text-muted-foreground">{t('It must be the exact URL the server answers at: https (http only on localhost), lowercase host, no query or fragment. A resource keeps its audience: for another URL, create a resource with it.')}</p>
      </div>
      <div className="space-y-1.5">
        <label htmlFor={`${id}-application`} className="text-sm font-medium">{t('Application')}</label>
        {applications.error ? <ErrorState error={applications.error} retry={applications.reload} /> :
          none ? <p className="text-xs text-muted-foreground">{rich('No application uses this resource yet. Link it to one in {{link}} first.', { link: <Link className="underline" to={`/projects/${project}/environments/${environment}/applications`}>{t('Applications')}</Link> })}</p> :
            <select id={`${id}-application`} className={selectClass} value={chosen} disabled={busy || applications.loading} onChange={e => setApplication(e.target.value)}>
              {applications.data.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>}
      </div>
      <div className="space-y-1.5">
        <label htmlFor={`${id}-name`} className="text-sm font-medium">{t('Name')}</label>
        <Input id={`${id}-name`} value={name} required disabled={busy} autoComplete="off" onChange={e => setName(e.target.value)} />
        <p className="text-xs text-muted-foreground">{t('Users see it when they authorize a client.')}</p>
      </div>
      <fieldset className="space-y-1.5">
        <legend className="text-sm font-medium">{t('Default scopes')}</legend>
        {resource.permissions.length === 0 ? <p className="text-xs text-muted-foreground">{t('This resource has no permissions.')}</p> :
          <div className="flex flex-wrap gap-x-4 gap-y-1">{resource.permissions.map(p => <label key={p} className="flex items-center gap-1.5 text-xs">
            <input type="checkbox" className="accent-primary" checked={scopes.includes(p)} disabled={busy} onChange={() => toggle(p)} /><code className="font-mono">{p}</code>
          </label>)}</div>}
        <p className="text-xs text-muted-foreground">{t('Granted when a client asks for no scope. Clients may still ask for any permission the user holds.')}</p>
      </fieldset>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <label htmlFor={`${id}-idle`} className="text-sm font-medium">{t('Idle lifetime (days)')}</label>
          <Input id={`${id}-idle`} type="number" inputMode="numeric" min={1} max={idleCap} required value={Number.isNaN(idle) ? '' : idle} disabled={busy} onChange={e => setIdle(e.target.valueAsNumber)} />
          <p className="text-xs text-muted-foreground">{t('An authorization unused this long ends.')}</p>
        </div>
        <div className="space-y-1.5">
          <label htmlFor={`${id}-max`} className="text-sm font-medium">{t('Maximum lifetime (days)')}</label>
          <Input id={`${id}-max`} type="number" inputMode="numeric" min={1} max={maxCap} required value={Number.isNaN(max) ? '' : max} disabled={busy} onChange={e => setMax(e.target.valueAsNumber)} />
          <p className="text-xs text-muted-foreground">{t('Users authorize again after this, however active.')}</p>
        </div>
      </div>
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
        <Button type="submit" disabled={busy || !chosen || !name.trim()}>{busy ? t('Working…') : t('Protect')}</Button>
      </div>
    </form>
  </DialogContent></Dialog>
}
