import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, PageHeader, SwitchField, Time } from '@/components/library/patterns'
import type { KeyPolicy } from '@/components/library/api-keys'
import { rich, t } from '@/lib/i18n'

/** APIKeyPolicyPage edits the environment's API key policy: which kinds of
 * key may exist, their longest lifetime and how many each owner may hold. */
export default function APIKeyPolicyPage() {
  const { project, environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/api-key-policy`
  const [saved, setSaved] = useState<KeyPolicy | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(() => { setError(''); api.get<KeyPolicy>(path).then(setSaved).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])
  const header = <PageHeader title={t('API key policy')} description={t('Which API keys this environment allows, how long they last and how many each owner may hold.')} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!saved) return <div role="status" className="space-y-6">{header}<Skeleton className="h-64" /><span className="sr-only">{t('Loading policy…')}</span></div>
  return <div className="space-y-6">{header}<APIKeyPolicyCard path={path} saved={saved} canWrite={canWrite} onSaved={setSaved}
    footer={<p className="text-xs text-muted-foreground">{rich('Choose each resource\'s permissions for these keys on its page, under {{link}}.', { link: <Link className="underline" to={`/projects/${project}/environments/${environment}/resources`}>{t('Resources & scopes')}</Link> })}</p>} /></div>
}

interface Draft { user_keys: boolean; organization_keys: boolean; limited: boolean; days: number; max_per_user: number; max_per_organization: number }
const toDraft = (p: KeyPolicy): Draft => ({ user_keys: p.user_keys, organization_keys: p.organization_keys, limited: p.max_ttl_days != null, days: p.max_ttl_days ?? 90, max_per_user: p.max_per_user, max_per_organization: p.max_per_organization })

/** APIKeyPolicyCard is the policy form (GET|PUT …/api-key-policy). */
export function APIKeyPolicyCard({ path, saved, canWrite, onSaved, footer }: { path: string; saved: KeyPolicy; canWrite: boolean; onSaved: (p: KeyPolicy) => void; footer?: React.ReactNode }) {
  const [draft, setDraft] = useState<Draft>(() => toDraft(saved))
  const [busy, setBusy] = useState(false)
  const [saveError, setSaveError] = useState('')
  const pending = useRef(false)
  useEffect(() => setDraft(toDraft(saved)), [saved])
  const changed = JSON.stringify(draft) !== JSON.stringify(toDraft(saved))
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft(d => ({ ...d, [key]: value }))
  const number = (key: 'max_per_user' | 'max_per_organization', label: string, hint: string, max: number) => <div className="space-y-1.5">
    <label htmlFor={`policy-${key}`} className="text-sm font-medium">{label}</label>
    <Input id={`policy-${key}`} type="number" inputMode="numeric" min={1} max={max} required value={Number.isNaN(draft[key]) ? '' : draft[key]} disabled={!canWrite || busy} aria-describedby={`policy-${key}-hint`} onChange={e => set(key, e.target.valueAsNumber)} />
    <p id={`policy-${key}-hint`} className="text-xs text-muted-foreground">{hint}</p>
  </div>
  return <form className="space-y-6" onSubmit={async event => {
    event.preventDefault(); if (pending.current) return
    pending.current = true; setBusy(true); setSaveError('')
    try {
      const out = await api.put<KeyPolicy>(path, {
        user_keys: draft.user_keys, organization_keys: draft.organization_keys, max_ttl_days: draft.limited ? draft.days : null,
        max_per_user: draft.max_per_user, max_per_organization: draft.max_per_organization,
      })
      onSaved(out); toast.success(t('API key policy saved'))
    } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
  }}>
    <DetailSection title={t('API keys')} description={saved.updated_at ? rich('Updated {{time}}.', { time: <Time value={saved.updated_at} /> }) : t('Defaults: no user or organization keys.')}>
      <div className="space-y-3">
        <SwitchField label={t('User keys')} hint={t('Members create personal keys, limited to what they may do in their organization. Needs the resource to allow them.')} checked={draft.user_keys} disabled={!canWrite || busy} onCheckedChange={v => set('user_keys', v)} />
        <SwitchField label={t('Organization keys')} hint={t('Organization administrators create keys that belong to the organization and outlive their creator.')} checked={draft.organization_keys} disabled={!canWrite || busy} onCheckedChange={v => set('organization_keys', v)} />
        <SwitchField label={t('Limit the lifetime of keys')} hint={t('Off: keys may never expire. On: no key lives longer than the maximum.')} checked={draft.limited} disabled={!canWrite || busy} onCheckedChange={v => set('limited', v)} />
        {draft.limited && <div className="space-y-1.5">
          <label htmlFor="policy-max-days" className="text-sm font-medium">{t('Maximum lifetime (days)')}</label>
          <Input id="policy-max-days" type="number" inputMode="numeric" min={1} max={365} required value={Number.isNaN(draft.days) ? '' : draft.days} disabled={!canWrite || busy} onChange={e => set('days', e.target.valueAsNumber)} />
        </div>}
        <div className="grid gap-4 sm:grid-cols-2">
          {number('max_per_user', t('Keys per user'), t('Active keys one member may hold in an organization: 1 to 100.'), 100)}
          {number('max_per_organization', t('Keys per organization'), t('Active keys an organization may hold: 1 to 500.'), 500)}
        </div>
      </div>
    </DetailSection>
    {saveError && <ErrorState error={saveError} />}
    {canWrite && <div className="flex flex-wrap gap-2">
      <Button type="submit" disabled={busy || !changed}>{busy ? t('Saving…') : t('Save policy')}</Button>
      {changed && <Button type="button" variant="outline" disabled={busy} onClick={() => setDraft(toDraft(saved))}>{t('Discard changes')}</Button>}
    </div>}
    {footer}
  </form>
}
