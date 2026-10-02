import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState } from '@/components/library/patterns'
import { providerLabel } from './federation-connection-form'
import { t } from '@/lib/i18n'

export interface SignIn {
  client_id: string; password: boolean; email_code: boolean; organization_sso: boolean
  all_connections: boolean; connection_ids: string[]; signup: boolean; passkey: boolean; custom: boolean
}
interface Connection { id: string; name: string; provider: string; organization_id: string | null; active: boolean }

export const everyMethod = (client: string): SignIn => ({ client_id: client, password: true, email_code: true, organization_sso: true, all_connections: true, connection_ids: [], signup: true, passkey: true, custom: false })

// summary is a short description of what a client offers.
export function summary(s: SignIn, connections: Connection[]): string {
  if (!s.custom) return t('All methods')
  const parts: string[] = []
  if (s.password) parts.push(t('Password'))
  if (s.email_code) parts.push(t('Email code'))
  if (s.organization_sso) parts.push(t('Organization SSO'))
  if (s.passkey) parts.push(t('Passkey'))
  if (s.all_connections) parts.push(t('All social'))
  else parts.push(...s.connection_ids.map(id => connections.find(c => c.id === id)?.name ?? t('Unknown connection')))
  if (!s.signup) parts.push(t('No sign-up'))
  return parts.join(' · ')
}

// signInBody is the PUT body: the listed connections only matter when not
// every connection is offered.
export function signInBody(s: SignIn) {
  return { password: s.password, email_code: s.email_code, organization_sso: s.organization_sso, all_connections: s.all_connections, connection_ids: s.all_connections ? [] : s.connection_ids, signup: s.signup, passkey: s.passkey }
}

export function SignInDialog({ base, client, name, readOnly, onClose, onSaved }: { base: string; client: string; name: string; readOnly: boolean; onClose: () => void; onSaved: () => void }) {
  const [value, setValue] = useState<SignIn | null>(null)
  const [connections, setConnections] = useState<Connection[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    Promise.all([
      api.get<SignIn>(`${base}/login-settings/clients/${client}/sign-in`),
      api.get<{ items: Connection[] }>(`${base}/federation-connections?limit=100`),
    ]).then(([s, c]) => { setValue(s); setConnections(c.items.filter(x => x.active && !x.organization_id)) }).catch(e => setError(message(e)))
  }, [base, client])

  const set = (patch: Partial<SignIn>) => setValue(v => v ? { ...v, ...patch } : v)
  const none = value && !value.password && !value.email_code && !value.organization_sso && !value.passkey && !value.all_connections && value.connection_ids.length === 0
  const toggle = (id: string) => value && set({ connection_ids: value.connection_ids.includes(id) ? value.connection_ids.filter(x => x !== id) : [...value.connection_ids, id] })
  const box = (key: 'password' | 'email_code' | 'organization_sso' | 'passkey' | 'signup', label: string, hint: string) => <label className="flex items-start gap-2 text-sm">
    <input type="checkbox" className="mt-0.5 accent-primary" checked={!!value?.[key]} disabled={busy || readOnly} onChange={e => set({ [key]: e.target.checked })} />
    <span><span className="font-medium">{label}</span><span className="block text-xs text-muted-foreground">{hint}</span></span>
  </label>

  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <DialogTitle className="pr-6 text-base font-semibold">{t('Sign-in methods · {{name}}', { name })}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Choose what this client\'s sign-in page offers. Methods that are off are hidden and refused.')}</DialogDescription>
      {!value ? (error ? <ErrorState error={error} /> : <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p>) : <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); if (busy || none || readOnly) return
        setBusy(true); setError('')
        try { await api.put(`${base}/login-settings/clients/${client}/sign-in`, signInBody(value)); toast.success(t('Sign-in methods saved')); onSaved(); onClose() } catch (err) { setError(message(err)) } finally { setBusy(false) }
      }}>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">{t('Email')}</legend>
          {box('password', t('Password'), t('Including "Forgot password?".'))}
          {box('email_code', t('Email code'), t('A one-time code sent to the email.'))}
          {box('organization_sso', t('Organization SSO'), t("Emails of an organization's verified domain continue with its identity provider. When off, members of organizations that enforce SSO cannot sign in to this client."))}
        </fieldset>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">{t('Passkeys')}</legend>
          {box('passkey', t('Sign in with a passkey'), t('A button and browser autofill; no password or second factor. Needs passkeys allowed under Sign-in methods.'))}
        </fieldset>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">{t('Social login buttons')}</legend>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-0.5 accent-primary" checked={value.all_connections} onChange={e => set({ all_connections: e.target.checked })} />
            <span><span className="font-medium">{t('Every environment connection')}</span><span className="block text-xs text-muted-foreground">{t('Connections added later appear automatically.')}</span></span>
          </label>
          {!value.all_connections && <div className="space-y-2 rounded-md border p-3">
            {connections.length === 0 && <p className="text-xs text-muted-foreground">{t('No active environment connections. Add Google, Microsoft, GitHub or Apple under Sign-in providers.')}</p>}
            {connections.map(c => <label key={c.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="accent-primary" checked={value.connection_ids.includes(c.id)} onChange={() => toggle(c.id)} />
              <span className="font-medium">{c.name}</span>{c.name !== providerLabel(c.provider) && <span className="text-xs text-muted-foreground">{providerLabel(c.provider)}</span>}
            </label>)}
          </div>}
        </fieldset>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">{t('New accounts')}</legend>
          {box('signup', t('Create account'), t('Shown when sign-up is on under Sign-in methods and this page offers password or email code.'))}
        </fieldset>
        {none && <p className="text-xs text-destructive">{t('Offer at least one method.')}</p>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{readOnly ? t('Close') : t('Cancel')}</Button>
          {!readOnly && <Button type="submit" disabled={busy || !!none}>{busy ? t('Saving…') : t('Save')}</Button>}
        </div>
      </form>}
    </DialogContent>
  </Dialog>
}
