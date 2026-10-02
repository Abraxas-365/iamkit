import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, DetailSection, ErrorState, SwitchField, Time } from '@/components/library/patterns'
import { rich, t } from '@/lib/i18n'

/** GET/PUT /organizations/:id/password-policy
 * (authentication.PasswordRequirements). */
export interface PasswordRequirements {
  min_length: number
  require_upper: boolean
  require_lower: boolean
  require_digit: boolean
  require_symbol: boolean
  max_age_days: number
  breach_check: boolean
  custom?: boolean
  updated_at?: string
}

type Flag = 'require_upper' | 'require_lower' | 'require_digit' | 'require_symbol' | 'breach_check'
const flags: [Flag, string][] = [
  ['require_upper', t('Require an uppercase letter')],
  ['require_lower', t('Require a lowercase letter')],
  ['require_digit', t('Require a digit')],
  ['require_symbol', t('Require a symbol')],
  ['breach_check', t('Reject breached passwords')],
]

/** OrganizationPasswordRequirements edits what an organization adds to the
 * environment's password policy for its members. It only tightens: users
 * are environment-wide, so a member of several organizations meets all of
 * them. */
/** RequirementsStore reads and writes the requirements; the console uses its
 * operator API (default), the organization admin portal its bearer client. */
export interface RequirementsStore {
  get: () => Promise<PasswordRequirements>
  put: (body: Omit<PasswordRequirements, 'custom' | 'updated_at'>) => Promise<PasswordRequirements>
  remove: () => Promise<void>
}

export function OrganizationPasswordRequirements({ organization, canWrite, store }: { organization: string; canWrite: boolean; store?: RequirementsStore }) {
  const { environment } = useParams()
  const path = `/environments/${environment}/organizations/${organization}/password-policy`
  const [saved, setSaved] = useState<PasswordRequirements | null>(null)
  const [draft, setDraft] = useState<PasswordRequirements | null>(null)
  const [error, setError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState(false)
  const pending = useRef(false)
  const io = useMemo<RequirementsStore>(() => store ?? { get: () => api.get<PasswordRequirements>(path), put: body => api.put<PasswordRequirements>(path, body), remove: () => api.delete(path) }, [store, path])
  const load = useCallback(() => {
    setError('')
    io.get().then(p => { setSaved(p); setDraft(p) }).catch(e => setError(message(e)))
  }, [io])
  useEffect(load, [load])

  const description = t('Stricter rules for members\' new passwords and a shorter expiry. They add to the environment\'s password policy and never loosen it; a member of several organizations meets all of them. Existing passwords are not re-checked; a shorter expiry makes members choose a new one at their next password sign-in.')
  if (error) return <DetailSection title={t('Password requirements')} description={description}><ErrorState error={error} retry={load} /></DetailSection>
  if (!saved || !draft) return <DetailSection title={t('Password requirements')} description={description}><Skeleton className="h-40" /></DetailSection>
  const set = <K extends keyof PasswordRequirements>(key: K, value: PasswordRequirements[K]) => setDraft(d => d && { ...d, [key]: value })
  const changed = (Object.keys(draft) as (keyof PasswordRequirements)[]).some(k => draft[k] !== saved[k])
  const disabled = !canWrite || busy

  return <DetailSection title={t('Password requirements')} description={<>{description}{saved.custom && saved.updated_at && <> {rich('Updated {{time}}.', { time: <Time value={saved.updated_at} /> })}</>}</>}>
    <form className="space-y-3" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      pending.current = true; setBusy(true); setSaveError('')
      try {
        const { custom: _custom, updated_at: _updated, ...body } = draft
        const out = await io.put(body)
        setSaved(out); setDraft(out); toast.success(t('Password requirements saved'))
      } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="grid gap-4 sm:grid-cols-2">
        <NumberInput id="org-min-length" label={t('Minimum length')} hint={t('0 keeps the environment\'s minimum; otherwise 8 to 72.')} min={0} max={72} value={draft.min_length} disabled={disabled} onChange={v => set('min_length', v)} />
        <NumberInput id="org-max-age" label={t('Expires after (days)')} hint={t('0 keeps the environment\'s expiry; otherwise the shorter one applies.')} min={0} max={3650} value={draft.max_age_days} disabled={disabled} onChange={v => set('max_age_days', v)} />
      </div>
      {flags.map(([key, label]) => <SwitchField key={key} label={label} checked={draft[key]} disabled={disabled} onCheckedChange={v => set(key, v)} />)}
      {saveError && <ErrorState error={saveError} />}
      {canWrite && <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !changed}>{busy ? t('Saving…') : t('Save requirements')}</Button>
        {changed && <Button type="button" variant="outline" disabled={busy} onClick={() => setDraft(saved)}>{t('Discard changes')}</Button>}
        {saved.custom && <Button type="button" variant="outline" disabled={busy} onClick={() => setRemoving(true)}>{t('Remove requirements')}</Button>}
      </div>}
    </form>
    {removing && <ConfirmDialog title={t('Remove the organization\'s password requirements?')} description={t('Members follow only the environment\'s password policy.')} confirmLabel={t('Remove')} onClose={() => setRemoving(false)} confirm={async () => { await io.remove(); toast.success(t('Password requirements removed')); load() }} />}
  </DetailSection>
}

function NumberInput({ id, label, hint, min, max, value, disabled, onChange }: { id: string; label: string; hint: string; min: number; max: number; value: number; disabled: boolean; onChange: (v: number) => void }) {
  return <div className="space-y-1.5">
    <label htmlFor={id} className="text-sm font-medium">{label}</label>
    <Input id={id} type="number" inputMode="numeric" min={min} max={max} required value={Number.isNaN(value) ? '' : value} disabled={disabled} aria-describedby={`${id}-hint`} onChange={e => onChange(e.target.valueAsNumber)} />
    <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>
  </div>
}
