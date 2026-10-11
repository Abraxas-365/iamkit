import { useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { DetailSection, ErrorState } from '@/components/library/patterns'
import type { KeyPolicy } from '@/components/library/api-keys'
import { t } from '@/lib/i18n'

export interface APIKeyPermissions { user: string[]; organization: string[] }

/** ApiKeyAllowlist chooses which of the resource's permissions user keys and
 * organization keys may carry (PUT …/resources/:id/api-key-permissions).
 * An empty column means no key of that kind for the resource. */
export function ApiKeyAllowlist({ base, resource, canWrite, system, onSaved }: {
  base: string
  resource: { id: string; permissions: string[]; api_key_permissions?: APIKeyPermissions }
  canWrite: boolean
  /** The IAM resource: its own API is called by service accounts and machine users. */
  system: boolean
  onSaved: () => void
}) {
  const title = t('API keys')
  const saved = resource.api_key_permissions ?? { user: [], organization: [] }
  const [draft, setDraft] = useState<APIKeyPermissions>(saved)
  const [policy, setPolicy] = useState<KeyPolicy | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  useEffect(() => setDraft({ user: resource.api_key_permissions?.user ?? [], organization: resource.api_key_permissions?.organization ?? [] }), [resource])
  useEffect(() => { if (!system) api.get<KeyPolicy>(`${base}/api-key-policy`).then(setPolicy).catch(() => {}) }, [base, system])
  if (system) return <DetailSection title={title}>
    <p className="text-sm text-muted-foreground">{t('Not available for the IAM resource: IAMKit\'s own API is called with a service account or a machine user.')}</p>
  </DetailSection>
  const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every(p => b.includes(p))
  const changed = !sameSet(draft.user, saved.user) || !sameSet(draft.organization, saved.organization)
  const toggle = (kind: keyof APIKeyPermissions, permission: string) => setDraft(d => ({ ...d, [kind]: d[kind].includes(permission) ? d[kind].filter(p => p !== permission) : [...d[kind], permission] }))
  const columns: [keyof APIKeyPermissions, string, boolean | undefined][] = [['user', t('User keys'), policy?.user_keys], ['organization', t('Organization keys'), policy?.organization_keys]]
  return <DetailSection title={title} description={t('The permissions keys created by users and by organizations may carry on this resource. Keys also never exceed what their owner can do. Leave a column empty to allow no keys of that kind.')}>
    <div className="space-y-4">
      {policy && columns.filter(([, , on]) => on === false).map(([kind, label]) => <p key={kind} role="note" className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t('{{kind}} are turned off in the environment\'s API key policy (Settings), so none can be created yet.', { kind: label })}</p>)}
      {resource.permissions.length === 0
        ? <p className="text-sm text-muted-foreground">{t('This resource has no permissions yet. Add some to let keys carry them.')}</p>
        : <div className="grid gap-4 sm:grid-cols-2">
          {columns.map(([kind, label]) => <fieldset key={kind} className="space-y-1.5" disabled={!canWrite || busy}>
            <legend className="text-sm font-medium">{label}</legend>
            <div className="grid max-h-56 gap-1 overflow-auto rounded-lg border p-2">
              {resource.permissions.map(p => <label key={p} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-accent">
                <input type="checkbox" className="accent-primary" aria-label={`${label}: ${p}`} checked={draft[kind].includes(p)} onChange={() => toggle(kind, p)} />
                <code className="font-mono text-xs">{p}</code>
              </label>)}
            </div>
          </fieldset>)}
        </div>}
      {error && <ErrorState error={error} />}
      {canWrite && resource.permissions.length > 0 && <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !changed} onClick={async () => {
          if (pending.current) return
          pending.current = true; setBusy(true); setError('')
          try { await api.put(`${base}/resources/${resource.id}/api-key-permissions`, draft); toast.success(t('API key permissions saved')); onSaved() }
          catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
        }}>{busy ? t('Saving…') : t('Save API key permissions')}</Button>
        {changed && <Button variant="outline" disabled={busy} onClick={() => setDraft(saved)}>{t('Discard changes')}</Button>}
      </div>}
    </div>
  </DetailSection>
}
