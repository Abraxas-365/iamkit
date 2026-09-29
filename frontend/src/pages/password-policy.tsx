import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, DetailSection, ErrorState, PageHeader, SwitchField, Time } from '@/components/library/patterns'

/** GET/PUT /password-policy (authentication.PasswordPolicy). */
export interface PasswordPolicy {
  min_length: number
  require_upper: boolean
  require_lower: boolean
  require_digit: boolean
  require_symbol: boolean
  max_age_days: number
  lockout_threshold: number
  lockout_minutes: number
  breach_check: boolean
  custom?: boolean
  updated_at?: string
}

type Numbers = 'min_length' | 'max_age_days' | 'lockout_threshold' | 'lockout_minutes'
type Flags = 'require_upper' | 'require_lower' | 'require_digit' | 'require_symbol' | 'breach_check'

const numbers: { key: Numbers; label: string; hint: string; min: number; max: number }[] = [
  { key: 'min_length', label: 'Minimum length', hint: 'Characters (bytes) a new password needs: 8 to 72.', min: 8, max: 72 },
  { key: 'max_age_days', label: 'Expires after (days)', hint: 'Users choose a new password at their next password sign-in after this many days. 0 never expires.', min: 0, max: 3650 },
  { key: 'lockout_threshold', label: 'Lock after wrong passwords', hint: 'Wrong passwords in a row that lock the account. 0 never locks; failures are still counted.', min: 0, max: 100 },
  { key: 'lockout_minutes', label: 'Lockout duration (minutes)', hint: 'The first lockout; each further one doubles, up to 24 hours.', min: 1, max: 1440 },
]
const flags: { key: Flags; label: string; hint?: string }[] = [
  { key: 'require_upper', label: 'Require an uppercase letter' },
  { key: 'require_lower', label: 'Require a lowercase letter' },
  { key: 'require_digit', label: 'Require a digit' },
  { key: 'require_symbol', label: 'Require a symbol' },
  { key: 'breach_check', label: 'Reject breached passwords', hint: 'Checks new passwords against Have I Been Pwned (k-anonymity: only 5 characters of a hash leave the server). If the service is unreachable the password is accepted.' },
]

/** PasswordPolicyPage edits the environment's end-user password policy:
 * composition, breach check, expiry and lockout. */
export default function PasswordPolicyPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/password-policy`
  const [saved, setSaved] = useState<PasswordPolicy | null>(null)
  const [draft, setDraft] = useState<PasswordPolicy | null>(null)
  const [error, setError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState(false)
  const pending = useRef(false)
  const load = useCallback(() => {
    setError('')
    api.get<PasswordPolicy>(path).then(p => { setSaved(p); setDraft(p) }).catch(e => setError(message(e)))
  }, [path])
  useEffect(load, [load])

  const header = <PageHeader title="Password policy" description="Rules for end-user passwords in this environment: new passwords (sign-up, invitations, resets, expiry), sign-in lockout and expiry." />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!saved || !draft) return <div role="status" className="space-y-6">{header}<Skeleton className="h-64" /><span className="sr-only">Loading policy…</span></div>
  const set = <K extends keyof PasswordPolicy>(key: K, value: PasswordPolicy[K]) => setDraft(d => d && { ...d, [key]: value })
  const changed = (Object.keys(draft) as (keyof PasswordPolicy)[]).some(k => draft[k] !== saved[k])

  return <div className="space-y-6">{header}
    <form className="space-y-6" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      pending.current = true; setBusy(true); setSaveError('')
      try {
        const { custom: _custom, updated_at: _updated, ...body } = draft
        const out = await api.put<PasswordPolicy>(path, body)
        setSaved(out); setDraft(out); toast.success('Password policy saved')
      } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <DetailSection title="New passwords" description={saved.custom ? <>Custom policy{saved.updated_at && <>, updated <Time value={saved.updated_at} /></>}.</> : 'The default policy: at least 12 characters, no lockout, no expiry.'}>
        <div className="space-y-3">
          <NumberField spec={numbers[0]} value={draft.min_length} disabled={!canWrite || busy} onChange={v => set('min_length', v)} />
          {flags.map(f => <SwitchField key={f.key} label={f.label} hint={f.hint} checked={draft[f.key]} disabled={!canWrite || busy} onCheckedChange={v => set(f.key, v)} />)}
        </div>
      </DetailSection>
      <DetailSection title="Expiry and lockout" description="Locked accounts get the same answer as a wrong password. Operators can unlock a user from their page; a password reset also unlocks.">
        <div className="grid gap-4 sm:grid-cols-3">
          {numbers.slice(1).map(n => <NumberField key={n.key} spec={n} value={draft[n.key]} disabled={!canWrite || busy} onChange={v => set(n.key, v)} />)}
        </div>
      </DetailSection>
      {saveError && <ErrorState error={saveError} />}
      {canWrite && <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !changed}>{busy ? 'Saving…' : 'Save policy'}</Button>
        {changed && <Button type="button" variant="outline" disabled={busy} onClick={() => setDraft(saved)}>Discard changes</Button>}
        {saved.custom && <Button type="button" variant="outline" disabled={busy} onClick={() => setReset(true)}>Restore default</Button>}
      </div>}
    </form>
    {reset && <ConfirmDialog title="Restore the default policy?" description="New passwords need at least 12 characters; lockout and expiry are turned off." confirmLabel="Restore default" onClose={() => setReset(false)} confirm={async () => { await api.delete(path); toast.success('Default policy restored'); load() }} />}
  </div>
}

function NumberField({ spec, value, disabled, onChange }: { spec: (typeof numbers)[number]; value: number; disabled: boolean; onChange: (v: number) => void }) {
  const id = `policy-${spec.key}`
  return <div className="space-y-1.5">
    <label htmlFor={id} className="text-sm font-medium">{spec.label}</label>
    <Input id={id} type="number" inputMode="numeric" min={spec.min} max={spec.max} required value={Number.isNaN(value) ? '' : value} disabled={disabled} aria-describedby={`${id}-hint`} onChange={e => onChange(e.target.valueAsNumber)} />
    <p id={`${id}-hint`} className="text-xs text-muted-foreground">{spec.hint}</p>
  </div>
}
