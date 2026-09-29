import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, DetailSection, ErrorState, SwitchField, Time } from '@/components/library/patterns'

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
  ['require_upper', 'Require an uppercase letter'],
  ['require_lower', 'Require a lowercase letter'],
  ['require_digit', 'Require a digit'],
  ['require_symbol', 'Require a symbol'],
  ['breach_check', 'Reject breached passwords'],
]

/** OrganizationPasswordRequirements edits what an organization adds to the
 * environment's password policy for its members. It only tightens: users
 * are environment-wide, so a member of several organizations meets all of
 * them. */
export function OrganizationPasswordRequirements({ organization, canWrite }: { organization: string; canWrite: boolean }) {
  const { environment } = useParams()
  const path = `/environments/${environment}/organizations/${organization}/password-policy`
  const [saved, setSaved] = useState<PasswordRequirements | null>(null)
  const [draft, setDraft] = useState<PasswordRequirements | null>(null)
  const [error, setError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState(false)
  const pending = useRef(false)
  const load = useCallback(() => {
    setError('')
    api.get<PasswordRequirements>(path).then(p => { setSaved(p); setDraft(p) }).catch(e => setError(message(e)))
  }, [path])
  useEffect(load, [load])

  const description = 'Stricter rules for members\' new passwords and a shorter expiry. They add to the environment\'s password policy and never loosen it; a member of several organizations meets all of them. Existing passwords are not re-checked; a shorter expiry makes members choose a new one at their next password sign-in.'
  if (error) return <DetailSection title="Password requirements" description={description}><ErrorState error={error} retry={load} /></DetailSection>
  if (!saved || !draft) return <DetailSection title="Password requirements" description={description}><Skeleton className="h-40" /></DetailSection>
  const set = <K extends keyof PasswordRequirements>(key: K, value: PasswordRequirements[K]) => setDraft(d => d && { ...d, [key]: value })
  const changed = (Object.keys(draft) as (keyof PasswordRequirements)[]).some(k => draft[k] !== saved[k])
  const disabled = !canWrite || busy

  return <DetailSection title="Password requirements" description={<>{description}{saved.custom && saved.updated_at && <> Updated <Time value={saved.updated_at} />.</>}</>}>
    <form className="space-y-3" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      pending.current = true; setBusy(true); setSaveError('')
      try {
        const { custom: _custom, updated_at: _updated, ...body } = draft
        const out = await api.put<PasswordRequirements>(path, body)
        setSaved(out); setDraft(out); toast.success('Password requirements saved')
      } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="grid gap-4 sm:grid-cols-2">
        <NumberInput id="org-min-length" label="Minimum length" hint="0 keeps the environment's minimum; otherwise 8 to 72." min={0} max={72} value={draft.min_length} disabled={disabled} onChange={v => set('min_length', v)} />
        <NumberInput id="org-max-age" label="Expires after (days)" hint="0 keeps the environment's expiry; otherwise the shorter one applies." min={0} max={3650} value={draft.max_age_days} disabled={disabled} onChange={v => set('max_age_days', v)} />
      </div>
      {flags.map(([key, label]) => <SwitchField key={key} label={label} checked={draft[key]} disabled={disabled} onCheckedChange={v => set(key, v)} />)}
      {saveError && <ErrorState error={saveError} />}
      {canWrite && <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !changed}>{busy ? 'Saving…' : 'Save requirements'}</Button>
        {changed && <Button type="button" variant="outline" disabled={busy} onClick={() => setDraft(saved)}>Discard changes</Button>}
        {saved.custom && <Button type="button" variant="outline" disabled={busy} onClick={() => setRemoving(true)}>Remove requirements</Button>}
      </div>}
    </form>
    {removing && <ConfirmDialog title="Remove the organization's password requirements?" description="Members follow only the environment's password policy." confirmLabel="Remove" onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success('Password requirements removed'); load() }} />}
  </DetailSection>
}

function NumberInput({ id, label, hint, min, max, value, disabled, onChange }: { id: string; label: string; hint: string; min: number; max: number; value: number; disabled: boolean; onChange: (v: number) => void }) {
  return <div className="space-y-1.5">
    <label htmlFor={id} className="text-sm font-medium">{label}</label>
    <Input id={id} type="number" inputMode="numeric" min={min} max={max} required value={Number.isNaN(value) ? '' : value} disabled={disabled} aria-describedby={`${id}-hint`} onChange={e => onChange(e.target.valueAsNumber)} />
    <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>
  </div>
}
