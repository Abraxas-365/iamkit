import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { FileCheck, Fingerprint, Globe, KeyRound, Mail, MessageSquare, Network, RotateCcw, ShieldCheck, Smartphone, TriangleAlert, UserPlus, Usb } from 'lucide-react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, ErrorState, PageHeader, SettingsList, SettingsSection, SwitchField, Time } from '@/components/library/patterns'
import { UnsavedChangesGuard } from '@/components/library/unsaved-changes'
import { SearchSelect } from '@/components/ui/search-select'
import { FACTORS, toggleFactor } from '@/lib/factors'
import { rich, t } from '@/lib/i18n'

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
  /** Sign-up records the acceptance of the terms (accept_terms). */
  require_terms: boolean
  signup_organization_id: string
  signup_group_id: string
  allowed_factors: string[]
  custom?: boolean
  updated_at?: string
}

type Flag = Exclude<keyof SignInPolicy, 'custom' | 'updated_at' | 'signup_organization_id' | 'signup_group_id' | 'allowed_factors'>
const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id), inactive: item.active === false })

type Row = { key: Flag; label: string; hint: string; icon: ReactNode }
const methods: Row[] = [
  { key: 'allow_password', label: t('Password'), hint: t('Email and password, headless and on the hosted pages.'), icon: <KeyRound /> },
  { key: 'allow_password_reset', label: t('Password reset'), hint: t('"Forgot password" by emailed code.'), icon: <RotateCcw /> },
  { key: 'allow_email_code', label: t('Email code'), hint: t('A one-time code sent by email (passwordless).'), icon: <Mail /> },
  { key: 'allow_social', label: t('Social connections'), hint: t('Environment connections such as Google or Microsoft, under Sign-in providers.'), icon: <Globe /> },
  { key: 'allow_passkey', label: t('Passkeys'), hint: t('A passkey alone signs the user in and counts as the second factor too.'), icon: <Fingerprint /> },
]
const mfa: Row[] = [
  { key: 'mfa_required', label: t('Require a second factor everywhere'), hint: t('Every organization, on top of its own MFA setting. Users without a factor enroll while signing in.'), icon: <ShieldCheck /> },
  { key: 'mfa_for_federated', label: t('Also after social and SSO sign-ins'), hint: t('By default the identity provider is trusted to have done its own MFA.'), icon: <Network /> },
]
const factorIcons: Record<string, ReactNode> = { totp: <Smartphone />, webauthn: <Usb />, sms: <MessageSquare />, email: <Mail /> }

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

  const header = <PageHeader title={t('Sign-in methods')} description={t('How users sign in to this environment. Organizations can turn methods off for their members, and applications can hide them on their hosted pages.')} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!saved || !draft) return <div role="status" className="space-y-6">{header}<Skeleton className="h-64" /><span className="sr-only">{t('Loading policy…')}</span></div>
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
  const locked = !canWrite || busy
  // Why a switch cannot be turned on right now, shown under its hint.
  const lockedNote = (key: Flag) =>
    key === 'allow_password_reset' && !draft.allow_password ? t('Turn on password sign-in first.')
      : key === 'allow_passkey' && !factors.includes('webauthn') ? t('Allow security keys and passkeys as a second factor first.')
        : undefined
  const enabled = methods.filter(m => draft[m.key] && !lockedNote(m.key)).length
  const save = async () => {
    if (pending.current) return
    pending.current = true; setBusy(true); setSaveError('')
    try {
      const { custom: _custom, updated_at: _updated, ...body } = draft
      if (!body.signup_organization_id) body.signup_group_id = ''
      const out = await api.put<SignInPolicy>(path, body)
      replace(out); toast.success(t('Sign-in methods saved'))
    } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
  }

  return <div className={cn('space-y-8', canWrite && changed && 'pb-20')}>
    <PageHeader title={t('Sign-in methods')} description={t('How users sign in to this environment. Organizations can turn methods off for their members, and applications can hide them on their hosted pages.')}
      actions={canWrite && saved.custom && <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => setReset(true)}><RotateCcw className="size-3.5" /> {t('Restore default')}</Button>} />
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {saved.custom ? <Badge variant="secondary">{t('Custom policy')}</Badge> : <Badge variant="outline">{t('Default policy')}</Badge>}
      <span>{saved.custom && saved.updated_at ? rich('Updated {{time}}.', { time: <Time value={saved.updated_at} /> }) : t('Every method is allowed until you change something.')}</span>
      {!canWrite && <span>{t('You can view this policy but not change it.')}</span>}
    </div>
    <UnsavedChangesGuard when={canWrite && changed} />
    <form className="space-y-8" onSubmit={event => { event.preventDefault(); void save() }}>
      <SettingsSection title={t('Methods')} description={t('A refused method answers METHOD_NOT_ALLOWED before any account lookup. Organization SSO follows its own enforcement.')}>
        <SettingsList label={t('{{count}} of {{total}} allowed', { count: enabled, total: methods.length })}>
          {methods.map(m => <SwitchField key={m.key} variant="row" icon={m.icon} label={m.label} hint={m.hint} note={lockedNote(m.key)} checked={draft[m.key]} disabled={locked || !!lockedNote(m.key)} onCheckedChange={v => set(m.key, v)} />)}
        </SettingsList>
        {none && <p role="note" className="flex gap-2 border-t bg-warning/5 px-4 py-3 text-sm text-warning"><TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />{t('Only organization SSO connections will be able to sign users in.')}</p>}
      </SettingsSection>

      <SettingsSection title={t('Multi-factor authentication')} description={t('Environment-wide defaults; an organization can require more but not less.')}>
        <SettingsList>
          {mfa.map(m => <SwitchField key={m.key} variant="row" icon={m.icon} label={m.label} hint={m.hint} checked={draft[m.key]} disabled={locked} onCheckedChange={v => set(m.key, v)} />)}
        </SettingsList>
        <div className="border-t">
          <div className="space-y-0.5 px-4 pt-4 pb-1">
            <p className="text-sm font-medium">{t('Allowed second factors')}</p>
            <p className="text-xs text-muted-foreground">{t('Which factors users may enroll and sign in with. Organizations can narrow the list. A factor turned off here stops being accepted, even for users who already enrolled it.')}</p>
          </div>
          <SettingsList>
            {FACTORS.map(f => {
              const on = factors.includes(f.kind)
              const last = on && factors.length === 1
              return <SwitchField key={f.kind} variant="row" icon={factorIcons[f.kind]} label={f.label} hint={f.hint} note={last ? t('At least one second factor stays allowed.') : undefined} checked={on} disabled={locked || last} onCheckedChange={v => setDraft(d => d && ({ ...d, allowed_factors: toggleFactor(d.allowed_factors ?? [], f.kind, v) }))} />
            })}
          </SettingsList>
          {factors.includes('email') && <p role="note" className="border-t px-4 py-3 text-xs text-muted-foreground">{rich('Email codes use the environment\'s email delivery with purpose {{code}}; a custom webhook must handle it.', { code: <code className="text-xs">{'mfa'}</code> })}</p>}
        </div>
      </SettingsSection>

      <SettingsSection title={t('Self sign-up')} description={t('Let people create their own account from the hosted pages or POST /identity/v1/signup. They confirm their email with a code before the account exists.')}>
        <SettingsList>
          <SwitchField variant="row" icon={<UserPlus />} label={t('Allow sign-up')} hint={t('Hosted pages show "Create account" unless the application hides it. New accounts use password or email code, as allowed here and by the organization.')} note={draft.allow_signup && !signupMethod ? t('Sign-up needs password or email-code sign-in.') : undefined} checked={draft.allow_signup} disabled={locked} onCheckedChange={v => set('allow_signup', v)} />
          {draft.allow_signup && <SwitchField variant="row" icon={<FileCheck />} label={t('Require accepting the terms')} hint={t('Sign-up asks people to accept the terms and records when they did. The hosted page links the terms and privacy URLs set under Branding → Legal links.')} checked={!!draft.require_terms} disabled={locked} onCheckedChange={v => set('require_terms', v)} />}
        </SettingsList>
        {(draft.allow_signup || draft.signup_organization_id) && <div className="grid gap-4 border-t p-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor="signup-organization">{t('Organization new accounts join')}</label>
            <SearchSelect key={`org-${generation}`} id="signup-organization" name="signup_organization_id" path={`/environments/${environment}/organizations`} mapItem={named} defaultValue={draft.signup_organization_id} required={draft.allow_signup} disabled={locked} placeholder={t('Search organizations…')} onChange={value => setDraft(d => d && ({ ...d, signup_organization_id: value, signup_group_id: '' }))} />
            {draft.allow_signup && !draft.signup_organization_id && <p className="text-xs text-warning">{t('Pick an organization to save.')}</p>}
          </div>
          {draft.signup_organization_id && <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor="signup-group">{t('Default group (optional)')}</label>
            <SearchSelect key={`${draft.signup_organization_id}-${generation}`} id="signup-group" name="signup_group_id" path={`/environments/${environment}/organizations/${draft.signup_organization_id}/groups`} mapItem={named} defaultValue={draft.signup_group_id} disabled={locked} placeholder={t('Search groups…')} onChange={value => setDraft(d => d && ({ ...d, signup_group_id: value }))} />
            <p className="text-xs text-muted-foreground">{t('New accounts join this group and get its roles. Only groups managed here (not by directory sync) qualify.')}</p>
          </div>}
        </div>}
      </SettingsSection>

      {canWrite && changed && <div data-save-bar className="fixed inset-x-0 bottom-0 z-40 border-t bg-background/95 backdrop-blur md:left-(--sidebar-width)">
        <div className="mx-auto flex max-w-screen-2xl flex-wrap items-center justify-between gap-3 px-6 py-3">
          <span className="text-sm text-muted-foreground">{saveError ? <span role="alert" className="text-destructive">{saveError}</span> : t('Unsaved changes')}</span>
          <div className="flex gap-2">
            <Button type="button" variant="outline" disabled={busy} onClick={() => { setSaveError(''); replace(saved) }}>{t('Discard changes')}</Button>
            <Button type="submit" disabled={busy || signupIncomplete}>{busy ? t('Saving…') : t('Save methods')}</Button>
          </div>
        </div>
      </div>}
    </form>
    {reset && <ConfirmDialog title={t('Restore the default?')} description={t('Every sign-in method is allowed again, the environment-wide second-factor requirement is turned off and the allowed factors go back to authenticator apps and security keys.')} confirmLabel={t('Restore default')} onClose={() => setReset(false)} confirm={async () => { await api.delete(path); toast.success(t('Default sign-in methods restored')); load() }} />}
  </div>
}
