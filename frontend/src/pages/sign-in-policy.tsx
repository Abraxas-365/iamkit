import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, DetailSection, ErrorState, PageHeader, SwitchField, Time } from '@/components/library/patterns'
import { SearchSelect } from '@/components/ui/search-select'
import { FACTORS, toggleFactor } from '@/lib/factors'

/** GET/PUT /sign-in-policy (authentication.SignInPolicy). */
export interface SignInPolicy {
  allow_password: boolean
  allow_email_code: boolean
  allow_social: boolean
  allow_passkey: boolean
  allow_password_reset: boolean
  mfa_required: boolean
  mfa_for_federated: boolean
  allow_signup: boolean
  signup_organization_id: string
  signup_group_id: string
  allowed_factors: string[]
  custom?: boolean
  updated_at?: string
}

type Flag = Exclude<keyof SignInPolicy, 'custom' | 'updated_at' | 'signup_organization_id' | 'signup_group_id' | 'allowed_factors'>
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id), inactive: item.active === false })

const methods: { key: Flag; label: string; hint: string }[] = [
  { key: 'allow_password', label: 'Password', hint: 'Email and password, headless and on the hosted pages.' },
  { key: 'allow_password_reset', label: 'Password reset', hint: '"Forgot password" by emailed code. Needs password sign-in.' },
  { key: 'allow_email_code', label: 'Email code', hint: 'A one-time code sent by email (passwordless).' },
  { key: 'allow_social', label: 'Social connections', hint: 'Environment connections such as Google or Microsoft, under Sign-in providers.' },
  { key: 'allow_passkey', label: 'Passkeys', hint: 'Sign in with a passkey alone: no password, no second factor (the passkey verified the user). Needs security keys among the allowed second factors.' },
]
const mfa: { key: Flag; label: string; hint: string }[] = [
  { key: 'mfa_required', label: 'Require a second factor everywhere', hint: 'Every organization, on top of its own MFA setting. Users without a factor enroll while signing in.' },
  { key: 'mfa_for_federated', label: 'Also after social and SSO sign-ins', hint: 'By default the identity provider is trusted to have done its own MFA.' },
]

/** SignInPolicyPage edits which sign-in methods the environment allows and
 * its default second-factor rules. */
export default function SignInPolicyPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/sign-in-policy`
  const [saved, setSaved] = useState<SignInPolicy | null>(null)
  const [draft, setDraft] = useState<SignInPolicy | null>(null)
  const [error, setError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState(false)
  const pending = useRef(false)
  // generation remounts the pickers (they keep their own selection) when the
  // draft is replaced from outside: load, save, discard.
  const [generation, setGeneration] = useState(0)
  const replace = (p: SignInPolicy) => { setSaved(p); setDraft(p); setGeneration(g => g + 1) }
  const load = useCallback(() => {
    setError('')
    api.get<SignInPolicy>(path).then(p => { setSaved(p); setDraft(p); setGeneration(g => g + 1) }).catch(e => setError(message(e)))
  }, [path])
  useEffect(load, [load])

  const header = <PageHeader title="Sign-in methods" description="Which ways users can sign in to this environment. Organizations can turn methods off for their members; applications can hide them on their hosted pages. Organization SSO follows its own enforcement." />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!saved || !draft) return <div role="status" className="space-y-6">{header}<Skeleton className="h-64" /><span className="sr-only">Loading policy…</span></div>
  const set = (key: Flag, value: boolean) => setDraft(d => {
    if (!d) return d
    const next = { ...d, [key]: value }
    if (key === 'allow_password' && !value) next.allow_password_reset = false
    return next
  })
  const changed = (Object.keys(draft) as (keyof SignInPolicy)[]).some(k => k === 'allowed_factors' ? (draft.allowed_factors ?? []).join() !== (saved.allowed_factors ?? []).join() : (draft[k] ?? '') !== (saved[k] ?? ''))
  const factors = draft.allowed_factors ?? []
  const passkeys = draft.allow_passkey && factors.includes('webauthn')
  const none = !draft.allow_password && !draft.allow_email_code && !draft.allow_social && !passkeys
  const signupMethod = draft.allow_password || draft.allow_email_code
  const signupIncomplete = draft.allow_signup && (!draft.signup_organization_id || !signupMethod)

  return <div className="space-y-6">{header}
    <form className="space-y-6" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      pending.current = true; setBusy(true); setSaveError('')
      try {
        const { custom: _custom, updated_at: _updated, ...body } = draft
        if (!body.signup_organization_id) body.signup_group_id = ''
        const out = await api.put<SignInPolicy>(path, body)
        replace(out); toast.success('Sign-in methods saved')
      } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <DetailSection title="Methods" description={saved.custom ? <>Custom policy{saved.updated_at && <>, updated <Time value={saved.updated_at} /></>}. Refused methods answer METHOD_NOT_ALLOWED before any account lookup.</> : 'The default: every method allowed.'}>
        <div className="space-y-3">
          {methods.map(m => <SwitchField key={m.key} label={m.label} hint={m.hint} checked={draft[m.key]} disabled={!canWrite || busy || (m.key === 'allow_password_reset' && !draft.allow_password) || (m.key === 'allow_passkey' && !factors.includes('webauthn'))} onCheckedChange={v => set(m.key, v)} />)}
          {none && <p role="note" className="text-sm text-muted-foreground">Only organization SSO connections will be able to sign users in.</p>}
        </div>
      </DetailSection>
      <DetailSection title="Multi-factor authentication" description="Environment-wide defaults; an organization can require more but not less.">
        <div className="space-y-3">
          {mfa.map(m => <SwitchField key={m.key} label={m.label} hint={m.hint} checked={draft[m.key]} disabled={!canWrite || busy} onCheckedChange={v => set(m.key, v)} />)}
          <div className="space-y-3 border-t pt-4">
            <p className="text-sm font-medium">Allowed second factors</p>
            <p className="text-xs text-muted-foreground">Which factors users may enroll and sign in with. Organizations can narrow the list. A factor turned off here stops being accepted, even for users who already enrolled it.</p>
            {FACTORS.map(f => {
              const on = factors.includes(f.kind)
              return <SwitchField key={f.kind} label={f.label} hint={f.hint} checked={on} disabled={!canWrite || busy || (on && factors.length === 1)} onCheckedChange={v => setDraft(d => d && ({ ...d, allowed_factors: toggleFactor(d.allowed_factors ?? [], f.kind, v) }))} />
            })}
            {factors.includes('email') && <p role="note" className="text-sm text-muted-foreground">Email codes use the environment's email delivery with purpose <code className="text-xs">mfa</code>; a custom webhook must handle it.</p>}
          </div>
        </div>
      </DetailSection>
      <DetailSection title="Self sign-up" description="Let people create their own account from the hosted pages or POST /identity/v1/signup. They confirm their email with a code before the account exists.">
        <div className="space-y-4">
          <SwitchField label="Allow sign-up" hint={'Hosted pages show "Create account" unless the application hides it. New accounts use password or email code, as allowed here and by the organization.'} checked={draft.allow_signup} disabled={!canWrite || busy} onCheckedChange={v => set('allow_signup', v)} />
          {(draft.allow_signup || draft.signup_organization_id) && <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="signup-organization">Organization new accounts join</label>
              <SearchSelect key={`org-${generation}`} id="signup-organization" name="signup_organization_id" path={`/environments/${environment}/organizations`} mapItem={named} defaultValue={draft.signup_organization_id} required={draft.allow_signup} disabled={!canWrite || busy} placeholder="Search organizations…" onChange={value => setDraft(d => d && ({ ...d, signup_organization_id: value, signup_group_id: '' }))} />
            </div>
            {draft.signup_organization_id && <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="signup-group">Default group (optional)</label>
              <SearchSelect key={`${draft.signup_organization_id}-${generation}`} id="signup-group" name="signup_group_id" path={`/environments/${environment}/organizations/${draft.signup_organization_id}/groups`} mapItem={named} defaultValue={draft.signup_group_id} disabled={!canWrite || busy} placeholder="Search groups…" onChange={value => setDraft(d => d && ({ ...d, signup_group_id: value }))} />
              <p className="text-xs text-muted-foreground">New accounts join this group and get its roles. Only groups managed here (not by directory sync) qualify.</p>
            </div>}
          </div>}
          {draft.allow_signup && !signupMethod && <p role="note" className="text-sm text-destructive">Sign-up needs password or email-code sign-in.</p>}
        </div>
      </DetailSection>
      {saveError && <ErrorState error={saveError} />}
      {canWrite && <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !changed || signupIncomplete}>{busy ? 'Saving…' : 'Save methods'}</Button>
        {changed && <Button type="button" variant="outline" disabled={busy} onClick={() => replace(saved)}>Discard changes</Button>}
        {saved.custom && <Button type="button" variant="outline" disabled={busy} onClick={() => setReset(true)}>Restore default</Button>}
      </div>}
    </form>
    {reset && <ConfirmDialog title="Restore the default?" description="Every sign-in method is allowed again, the environment-wide second-factor requirement is turned off and the allowed factors go back to authenticator apps and security keys." confirmLabel="Restore default" onClose={() => setReset(false)} confirm={async () => { await api.delete(path); toast.success('Default sign-in methods restored'); load() }} />}
  </div>
}
