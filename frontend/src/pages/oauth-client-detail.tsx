import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Ban, Palette, Pencil } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button, buttonVariants } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { TagInput } from '@/components/ui/tag-input'
import { BackLink, ConfirmDialog, CopyField, DetailSection, EntityRef, ErrorState, PageHeader, Properties, RadioCards, Status } from '@/components/library/patterns'
import { SignInDialog, summary, type SignIn } from './sign-in-options'
import { signInModes, type OAuthClient } from './integrations'

interface Connection { id: string; name: string; provider: string; organization_id: string | null; active: boolean }

/** OAuthClientDetailPage shows one client: credentials, redirect URIs, the
 * sign-in experience and the actions that change them. */
export default function OAuthClientDetailPage() {
  const { project, environment, clientId } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/oauth-clients/${clientId}`
  const [client, setClient] = useState<OAuthClient | null>(null)
  const [signIn, setSignIn] = useState<SignIn | null>(null)
  const [connections, setConnections] = useState<Connection[]>([])
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [redirects, setRedirects] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [methods, setMethods] = useState(false)
  const [disable, setDisable] = useState(false)

  const load = useCallback(() => {
    setError('')
    api.get<OAuthClient>(path).then(c => { setClient(c); setRedirects(c.redirect_uris ?? []) }).catch(e => setError(message(e)))
    api.get<SignIn>(`${base}/login-settings/clients/${clientId}/sign-in`).then(setSignIn).catch(() => setSignIn(null))
    api.get<{ items: Connection[] }>(`${base}/federation-connections?limit=100`).then(r => setConnections(r.items)).catch(() => setConnections([]))
  }, [path, base, clientId])
  useEffect(load, [load])

  const back = <BackLink to={`${console}/oauth-clients`}>OAuth clients</BackLink>
  if (error && !client) return <div className="space-y-4">{back}<ErrorState error={error} retry={load} /></div>
  if (!client) return <div className="space-y-4">{back}<Skeleton className="h-10 w-64" /><Skeleton className="h-40" /><Skeleton className="h-40" /></div>

  const editable = canWrite && client.active
  const save = async (body: Record<string, unknown>, done: string) => {
    setBusy(true)
    try { await api.patch(path, body); toast.success(done); load(); return true } catch (e) { toast.error(message(e)); return false } finally { setBusy(false) }
  }
  const name = client.application_name || 'OAuth client'

  return <div className="space-y-6">
    {back}
    <PageHeader title={name} description={`OAuth client for ${client.resource_name || 'a resource'} · ${client.public ? 'Public' : 'Confidential'}`} actions={<Status active={client.active} label={client.active ? 'Active' : 'Disabled'} />} />
    {!client.active && <p className="rounded-lg border bg-muted/50 p-3 text-sm text-muted-foreground">This client is disabled. It can no longer start sign-ins, and its settings are read-only.</p>}

    <DetailSection title="Credentials" description="Use these in your application's OAuth/OIDC library.">
      <div className="space-y-4">
        <CopyField label="Client ID" value={client.id} />
        <Properties items={[
          ['Client type', client.public ? 'Public — no secret, PKCE required' : 'Confidential — authenticates with its client secret (shown once at creation)'],
          ['Application', <EntityRef name={client.application_name} id={client.application_id} to={`${console}/applications/${client.application_id}`} />],
          ['Resource (audience)', <EntityRef name={client.resource_name} id={client.resource_id} />],
          ['Discovery URL', <code className="text-xs break-all">{`${window.location.origin}/.well-known/openid-configuration`}</code>],
        ]} />
      </div>
    </DetailSection>

    <DetailSection title="Redirect URIs" description="Users can only be sent back to these exact URLs after signing in."
      actions={editable && !editing && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      {editing ? <form className="space-y-3" onSubmit={async e => {
        e.preventDefault()
        if (await save({ redirect_uris: redirects }, 'Redirect URIs saved')) setEditing(false)
      }}>
        <TagInput name="redirect_uris" defaultValue={client.redirect_uris ?? []} onChange={setRedirects} disabled={busy} placeholder="https://app.example.com/callback — press Enter" />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={() => { setEditing(false); setRedirects(client.redirect_uris ?? []) }}>Cancel</Button>
          <Button type="submit" disabled={busy || redirects.length === 0}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </form> : <ul className="space-y-1.5">{(client.redirect_uris ?? []).map(u => <li key={u}><code className="text-xs break-all">{u}</code></li>)}</ul>}
    </DetailSection>

    <DetailSection title="Sign-in experience" description="Who renders the login form when this client starts an authorization.">
      <div className="space-y-4">
        <RadioCards name="sign_in" label="Sign-in pages" value={client.hosted_login ? 'hosted' : 'custom'} disabled={!editable || busy} options={signInModes}
          onChange={v => void save({ hosted_login: v === 'hosted' }, v === 'hosted' ? 'Now using the hosted sign-in page' : 'Now using your own sign-in UI')} />
        {client.hosted_login && <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">Sign-in methods</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{signIn ? summary(signIn, connections) : 'All methods'}</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setMethods(true)}>{canWrite ? 'Choose methods' : 'View methods'}</Button>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">Look & feel</p>
            <p className="mt-0.5 text-xs text-muted-foreground">Logo, colors and texts of this client's pages.</p>
            <Link to={`${console}/hosted-login/clients/${client.id}`} className={buttonVariants({ variant: 'outline', size: 'sm', className: 'mt-3' })}><Palette /> Customize style</Link>
          </div>
        </div>}
      </div>
    </DetailSection>

    {editable && <DetailSection danger title="Danger zone" description="Disabling is permanent: the client can no longer sign users in. Existing sessions keep working until they expire.">
      <Button variant="destructive" onClick={() => setDisable(true)}><Ban /> Disable client</Button>
    </DetailSection>}

    {methods && <SignInDialog base={base} client={client.id} name={name} readOnly={!canWrite} onClose={() => setMethods(false)} onSaved={load} />}
    {disable && <ConfirmDialog title={`Disable ${name}?`} description="The application can no longer sign users in with this client. This cannot be undone." confirmLabel="Disable client" onClose={() => setDisable(false)} confirm={async () => { await api.delete(path); toast.success('OAuth client disabled'); load() }} />}
  </div>
}
