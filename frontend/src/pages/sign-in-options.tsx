import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState } from '@/components/library/patterns'
import { providerLabel } from './federation-connection-form'

export interface SignIn {
  client_id: string; password: boolean; email_code: boolean; organization_sso: boolean
  all_connections: boolean; connection_ids: string[]; custom: boolean
}
interface Connection { id: string; name: string; provider: string; organization_id: string | null; active: boolean }

export const everyMethod = (client: string): SignIn => ({ client_id: client, password: true, email_code: true, organization_sso: true, all_connections: true, connection_ids: [], custom: false })

// summary is a short description of what a client offers.
export function summary(s: SignIn, connections: Connection[]): string {
  if (!s.custom) return 'All methods'
  const parts: string[] = []
  if (s.password) parts.push('Password')
  if (s.email_code) parts.push('Email code')
  if (s.organization_sso) parts.push('Organization SSO')
  if (s.all_connections) parts.push('All social')
  else parts.push(...s.connection_ids.map(id => connections.find(c => c.id === id)?.name ?? 'Unknown connection'))
  return parts.join(' · ')
}

// signInBody is the PUT body: the listed connections only matter when not
// every connection is offered.
export function signInBody(s: SignIn) {
  return { password: s.password, email_code: s.email_code, organization_sso: s.organization_sso, all_connections: s.all_connections, connection_ids: s.all_connections ? [] : s.connection_ids }
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
  const none = value && !value.password && !value.email_code && !value.organization_sso && !value.all_connections && value.connection_ids.length === 0
  const toggle = (id: string) => value && set({ connection_ids: value.connection_ids.includes(id) ? value.connection_ids.filter(x => x !== id) : [...value.connection_ids, id] })
  const box = (key: 'password' | 'email_code' | 'organization_sso', label: string, hint: string) => <label className="flex items-start gap-2 text-sm">
    <input type="checkbox" className="mt-0.5 accent-primary" checked={!!value?.[key]} disabled={busy || readOnly} onChange={e => set({ [key]: e.target.checked })} />
    <span><span className="font-medium">{label}</span><span className="block text-xs text-muted-foreground">{hint}</span></span>
  </label>

  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <DialogTitle className="pr-6 text-base font-semibold">Sign-in methods · {name}</DialogTitle>
      <DialogDescription className="text-muted-foreground">Choose what this client's sign-in page offers. Methods that are off are hidden and refused.</DialogDescription>
      {!value ? (error ? <ErrorState error={error} /> : <p role="status" className="text-sm text-muted-foreground">Loading…</p>) : <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); if (busy || none || readOnly) return
        setBusy(true); setError('')
        try { await api.put(`${base}/login-settings/clients/${client}/sign-in`, signInBody(value)); toast.success('Sign-in methods saved'); onSaved(); onClose() } catch (err) { setError(message(err)) } finally { setBusy(false) }
      }}>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">Email</legend>
          {box('password', 'Password', 'Including "Forgot password?".')}
          {box('email_code', 'Email code', 'A one-time code sent to the email.')}
          {box('organization_sso', 'Organization SSO', "Emails of an organization's verified domain continue with its identity provider. When off, members of organizations that enforce SSO cannot sign in to this client.")}
        </fieldset>
        <fieldset className="space-y-3" disabled={busy || readOnly}>
          <legend className="mb-2 text-sm font-medium">Social login buttons</legend>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-0.5 accent-primary" checked={value.all_connections} onChange={e => set({ all_connections: e.target.checked })} />
            <span><span className="font-medium">Every environment connection</span><span className="block text-xs text-muted-foreground">Connections added later appear automatically.</span></span>
          </label>
          {!value.all_connections && <div className="space-y-2 rounded-md border p-3">
            {connections.length === 0 && <p className="text-xs text-muted-foreground">No active environment connections. Add Google, Microsoft, GitHub or Apple under Sign-in providers.</p>}
            {connections.map(c => <label key={c.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="accent-primary" checked={value.connection_ids.includes(c.id)} onChange={() => toggle(c.id)} />
              <span className="font-medium">{c.name}</span>{c.name !== providerLabel(c.provider) && <span className="text-xs text-muted-foreground">{providerLabel(c.provider)}</span>}
            </label>)}
          </div>}
        </fieldset>
        {none && <p className="text-xs text-destructive">Offer at least one method.</p>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{readOnly ? 'Close' : 'Cancel'}</Button>
          {!readOnly && <Button type="submit" disabled={busy || !!none}>{busy ? 'Saving…' : 'Save'}</Button>}
        </div>
      </form>}
    </DialogContent>
  </Dialog>
}
