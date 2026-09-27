import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState, PageHeader } from '@/components/library/patterns'

interface LoginSettings { environment_id: string; display_name: string; logo_url: string; accent_color: string; updated_at?: string }

const defaultAccent = '#2563eb'
const description = 'Branding for the sign-in and invitation pages IAMKit hosts for OAuth clients with hosted login enabled.'

export default function HostedLoginPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/login-settings`
  const [settings, setSettings] = useState<LoginSettings | null>(null)
  const [error, setError] = useState('')
  const [formError, setFormError] = useState('')
  const [busy, setBusy] = useState(false)
  const [accent, setAccent] = useState(defaultAccent)
  const pending = useRef(false)

  const load = () => {
    setError('')
    api.get<LoginSettings>(path).then(s => { setSettings(s); setAccent(s.accent_color || defaultAccent) }).catch(e => setError(message(e)))
  }
  useEffect(load, [path])

  if (error) return <div className="space-y-6"><PageHeader title="Hosted login" description={description} /><ErrorState error={error} retry={load} /></div>
  if (!settings) return <div className="space-y-6"><PageHeader title="Hosted login" description={description} /><p role="status" className="text-sm text-muted-foreground">Loading…</p></div>

  return <div className="space-y-6">
    <PageHeader title="Hosted login" description={description} />
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="p-6">
        <form key={settings.updated_at ?? 'unsaved'} className="space-y-4" onSubmit={async event => {
          event.preventDefault(); if (pending.current) return
          const form = new FormData(event.currentTarget)
          const body = {
            display_name: String(form.get('display_name') ?? '').trim(),
            logo_url: String(form.get('logo_url') ?? '').trim(),
            accent_color: String(form.get('accent_color') ?? '').trim(),
          }
          pending.current = true; setBusy(true); setFormError('')
          try { const saved = await api.put<LoginSettings>(path, body); setSettings(saved); setAccent(saved.accent_color || defaultAccent); toast.success('Branding saved') } catch (e) { setFormError(message(e)) } finally { pending.current = false; setBusy(false) }
        }}>
          <h2 className="font-mono font-medium">Branding</h2>
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor="display-name">Display name</label>
            <Input id="display-name" name="display_name" maxLength={100} disabled={!canWrite || busy} defaultValue={settings.display_name} placeholder="Acme" />
            <p className="text-xs text-muted-foreground">Shown as the page heading. Empty shows “Sign in”.</p>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor="logo-url">Logo URL</label>
            <Input id="logo-url" name="logo_url" type="url" disabled={!canWrite || busy} defaultValue={settings.logo_url} placeholder="https://cdn.example.com/logo.png" />
            <p className="text-xs text-muted-foreground">HTTPS only.</p>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor="accent-color">Accent color</label>
            <div className="flex gap-2">
              <Input id="accent-color" name="accent_color" pattern="#[0-9a-fA-F]{6}" disabled={!canWrite || busy} value={accent} onChange={e => setAccent(e.target.value)} placeholder={defaultAccent} />
              <input aria-label="Pick accent color" type="color" className="h-8 w-10 rounded-md border" disabled={!canWrite || busy} value={/^#[0-9a-fA-F]{6}$/.test(accent) ? accent : defaultAccent} onChange={e => setAccent(e.target.value)} />
            </div>
          </div>
          {formError && <ErrorState error={formError} />}
          {canWrite && <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button>}
        </form>
      </Card>
      <Card className="border-dashed">
        <CardHeader><CardDescription>How it works</CardDescription><CardTitle className="text-sm font-normal">Enable “Hosted pages” on an OAuth client</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p><code className="text-xs">/oauth/authorize</code> then sends the browser to <code className="text-xs">/hosted/login</code> instead of returning the authorization ticket.</p>
          <p>Users sign in with a password, an email code or single sign-on (enforced SSO is applied automatically), pick an organization when they belong to several, and return to your redirect URI with an authorization code.</p>
          <p>Invitation links can point to <code className="text-xs">/hosted/invite</code>: set it as the invitation page in Notifications.</p>
        </CardContent>
      </Card>
    </div>
  </div>
}
