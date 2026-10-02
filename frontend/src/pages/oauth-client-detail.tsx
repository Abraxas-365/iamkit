import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Ban, Palette, Pencil, Radio } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { TagInput } from '@/components/ui/tag-input'
import { BackLink, ConfirmDialog, CopyField, DetailSection, EntityRef, ErrorState, PageHeader, Properties, RadioCards, Status, SwitchField } from '@/components/library/patterns'
import { SignInDialog, summary, type SignIn } from './sign-in-options'
import { defaultGrants, deviceGrant, exchangeGrant, loopbackWarnings, redirectHint, RedirectWarnings, signInModes, tokenFormats, type OAuthClient } from './integrations'
import { ClientAuthDialog, authSummary } from '@/components/library/client-auth'
import { HistorySection } from './history'
import { t } from '@/lib/i18n'

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
  const [editingLogout, setEditingLogout] = useState(false)
  const [logoutURIs, setLogoutURIs] = useState<string[]>([])
  const [editingOrigins, setEditingOrigins] = useState(false)
  const [origins, setOrigins] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [methods, setMethods] = useState(false)
  const [disable, setDisable] = useState(false)
  const [auth, setAuth] = useState(false)
  const [opaque, setOpaque] = useState(false)
  const [editingBackchannel, setEditingBackchannel] = useState(false)

  const load = useCallback(() => {
    setError('')
    api.get<OAuthClient>(path).then(c => { setClient(c); setRedirects(c.redirect_uris ?? []); setLogoutURIs(c.post_logout_redirect_uris ?? []); setOrigins(c.allowed_origins ?? []) }).catch(e => setError(message(e)))
    api.get<SignIn>(`${base}/login-settings/clients/${clientId}/sign-in`).then(setSignIn).catch(() => setSignIn(null))
    api.get<{ items: Connection[] }>(`${base}/federation-connections?limit=100`).then(r => setConnections(r.items)).catch(() => setConnections([]))
  }, [path, base, clientId])
  useEffect(load, [load])

  const back = <BackLink to={`${console}/oauth-clients`}>{t('OAuth clients')}</BackLink>
  if (error && !client) return <div className="space-y-4">{back}<ErrorState error={error} retry={load} /></div>
  if (!client) return <div className="space-y-4">{back}<Skeleton className="h-10 w-64" /><Skeleton className="h-40" /><Skeleton className="h-40" /></div>

  const editable = canWrite && client.active
  const save = async (body: Record<string, unknown>, done: string) => {
    setBusy(true)
    try { await api.patch(path, body); toast.success(done); load(); return true } catch (e) { toast.error(message(e)); return false } finally { setBusy(false) }
  }
  const name = client.application_name || t('OAuth client')
  const grants = client.grant_types?.length ? client.grant_types : defaultGrants
  const toggleGrant = (grant: string, on: boolean, done: string) => {
    const next = on ? [...grants, grant] : grants.filter(g => g !== grant)
    void save({ grant_types: next }, done)
  }

  return <div className="space-y-6">
    {back}
    <PageHeader title={name} description={t('OAuth client for {{resource}} · {{kind}}', { resource: client.resource_name || t('a resource'), kind: client.public ? t('Public') : t('Confidential') })} actions={<Status active={client.active} label={client.active ? t('Active') : t('Disabled')} />} />
    {!client.active && <p className="rounded-lg border bg-muted/50 p-3 text-sm text-muted-foreground">{t('This client is disabled. It can no longer start sign-ins, and its settings are read-only.')}</p>}

    <DetailSection title={t('Credentials')} description={t('Use these in your application\'s OAuth/OIDC library.')}>
      <div className="space-y-4">
        <CopyField label={t('Client ID')} value={client.id} />
        <Properties items={[
          [t('Client type'), client.public ? t('Public — no secret, PKCE required') : client.token_endpoint_auth_method === 'private_key_jwt' ? t('Confidential — authenticates with a signed JWT (private_key_jwt)') : t('Confidential — authenticates with its client secret (shown once at creation)')],
          ...(client.public ? [] : [[t('Token endpoint authentication'), <span className="flex flex-wrap items-center gap-2">{authSummary(client)}{editable && <Button variant="outline" size="sm" onClick={() => setAuth(true)}><Pencil /> {t('Change')}</Button>}</span>] as [string, React.ReactNode]]),
          [t('Application'), <EntityRef name={client.application_name} id={client.application_id} to={`${console}/applications/${client.application_id}`} />],
          [t('Resource (audience)'), <EntityRef name={client.resource_name} id={client.resource_id} />],
          [t('Discovery URL'), <code className="text-xs break-all">{`${window.location.origin}/.well-known/openid-configuration`}</code>],
          [t('Sign-out URL'), <code className="text-xs break-all">{`${window.location.origin}/oauth/end_session`}</code>],
        ]} />
      </div>
    </DetailSection>

    <DetailSection title={t('Redirect URIs')} description={t('Users can only be sent back to these exact URLs after signing in.')}
      actions={editable && !editing && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>}>
      {editing ? <form className="space-y-3" onSubmit={async e => {
        e.preventDefault()
        if (await save({ redirect_uris: redirects }, t('Redirect URIs saved'))) setEditing(false)
      }}>
        <TagInput name="redirect_uris" defaultValue={client.redirect_uris ?? []} onChange={setRedirects} disabled={busy} placeholder="https://app.example.com/callback — press Enter" />
        <p className="text-xs text-muted-foreground">{redirectHint}</p>
        <RedirectWarnings warnings={loopbackWarnings(redirects)} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={() => { setEditing(false); setRedirects(client.redirect_uris ?? []) }}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy || redirects.length === 0}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form> : <div className="space-y-3"><ul className="space-y-1.5">{(client.redirect_uris ?? []).map(u => <li key={u}><code className="text-xs break-all">{u}</code></li>)}</ul><RedirectWarnings warnings={client.warnings} /></div>}
    </DetailSection>

    <DetailSection title={t('Post-logout redirect URIs')} description={t('Where /oauth/end_session may send users after signing out (post_logout_redirect_uri, exact match). Without one, IAMKit shows a signed-out page.')}
      actions={editable && !editingLogout && <Button variant="outline" size="sm" aria-label={t('Edit post-logout redirect URIs')} onClick={() => setEditingLogout(true)}><Pencil /> {t('Edit')}</Button>}>
      {editingLogout ? <form className="space-y-3" onSubmit={async e => {
        e.preventDefault()
        if (await save({ post_logout_redirect_uris: logoutURIs }, t('Post-logout redirect URIs saved'))) setEditingLogout(false)
      }}>
        <TagInput name="post_logout_redirect_uris" defaultValue={client.post_logout_redirect_uris ?? []} onChange={setLogoutURIs} disabled={busy} placeholder="https://app.example.com/signed-out — press Enter" />
        <RedirectWarnings warnings={loopbackWarnings([], logoutURIs)} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={() => { setEditingLogout(false); setLogoutURIs(client.post_logout_redirect_uris ?? []) }}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form> : (client.post_logout_redirect_uris ?? []).length
        ? <ul className="space-y-1.5">{(client.post_logout_redirect_uris ?? []).map(u => <li key={u}><code className="text-xs break-all">{u}</code></li>)}</ul>
        : <p className="text-sm text-muted-foreground">{t('None — users see IAMKit\'s signed-out page.')}</p>}
    </DetailSection>

    <DetailSection title={t('Allowed origins')} description={t('Browser origins of your own sign-in UI or single-page app (https://app.example.com, http only for localhost). They may call the identity API and the browser-facing OAuth endpoints from JavaScript (CORS).')}
      actions={editable && !editingOrigins && <Button variant="outline" size="sm" aria-label={t('Edit allowed origins')} onClick={() => setEditingOrigins(true)}><Pencil /> {t('Edit')}</Button>}>
      {editingOrigins ? <form className="space-y-3" onSubmit={async e => {
        e.preventDefault()
        if (await save({ allowed_origins: origins }, t('Allowed origins saved'))) setEditingOrigins(false)
      }}>
        <TagInput name="allowed_origins" defaultValue={client.allowed_origins ?? []} onChange={setOrigins} disabled={busy} placeholder="https://login.example.com — press Enter" />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={() => { setEditingOrigins(false); setOrigins(client.allowed_origins ?? []) }}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form> : (client.allowed_origins ?? []).length
        ? <ul className="space-y-1.5">{(client.allowed_origins ?? []).map(u => <li key={u}><code className="text-xs break-all">{u}</code></li>)}</ul>
        : <p className="text-sm text-muted-foreground">{t('None — only same-origin pages and the deployment\'s CORS origins can call IAMKit from a browser.')}</p>}
    </DetailSection>

    <DetailSection title={t('Sign-in experience')} description={t('Who renders the login form when this client starts an authorization.')}>
      <div className="space-y-4">
        <RadioCards name="sign_in" label={t('Sign-in pages')} value={client.hosted_login ? 'hosted' : 'custom'} disabled={!editable || busy} options={signInModes}
          onChange={v => void save({ hosted_login: v === 'hosted' }, v === 'hosted' ? t('Now using the hosted sign-in page') : t('Now using your own sign-in UI'))} />
        {client.hosted_login && <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">{t('Sign-in methods')}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{signIn ? summary(signIn, connections) : t('All methods')}</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setMethods(true)}>{canWrite ? t('Choose methods') : t('View methods')}</Button>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-sm font-medium">{t('Look & feel')}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{t('Logo, colors and texts of this client\'s pages.')}</p>
            <Link to={`${console}/hosted-login/clients/${client.id}`} className={buttonVariants({ variant: 'outline', size: 'sm', className: 'mt-3' })}><Palette /> {t('Customize style')}</Link>
          </div>
        </div>}
      </div>
    </DetailSection>

    <DetailSection title={t('Grant types')} description={t('How this client obtains tokens. Clients without a browser (TVs, CLIs, IoT) use the device flow: they show a short code the user enters at /hosted/device.')}>
      <div className="space-y-3">
        <SwitchField label={t('Authorization code')} hint={t('Browser sign-in with PKCE through the redirect URIs above.')} checked={grants.includes('authorization_code')} disabled={!editable || busy}
          onCheckedChange={on => toggleGrant('authorization_code', on, on ? t('Authorization code grant enabled') : t('Authorization code grant disabled'))} />
        <SwitchField label={t('Device authorization')} hint={client.hosted_login ? t('RFC 8628: the device polls /oauth/token while the user approves it on another screen.') : t('Needs the hosted sign-in page — the user approves the device there.')} checked={grants.includes(deviceGrant)} disabled={!editable || busy || (!client.hosted_login && !grants.includes(deviceGrant))}
          onCheckedChange={on => toggleGrant(deviceGrant, on, on ? t('Device authorization enabled') : t('Device authorization disabled'))} />
        <SwitchField label={t('Token exchange')} hint={client.public ? t('Needs a confidential client — exchanging tokens requires client authentication.') : t('RFC 8693: your backend exchanges a user\'s access token for one scoped to another resource of this application.')} checked={grants.includes(exchangeGrant)} disabled={!editable || busy || (client.public && !grants.includes(exchangeGrant))}
          onCheckedChange={on => toggleGrant(exchangeGrant, on, on ? t('Token exchange enabled') : t('Token exchange disabled'))} />
        <SwitchField label={t('Refresh tokens')} hint={t('Issued when the offline_access scope is granted.')} checked={grants.includes('refresh_token')} disabled={!editable || busy}
          onCheckedChange={on => toggleGrant('refresh_token', on, on ? t('Refresh tokens enabled') : t('Refresh tokens disabled'))} />
      </div>
    </DetailSection>

    <DetailSection title={t('Access tokens')} description={t('The format of the access tokens this client receives. ID tokens are always signed JWTs.')}>
      <RadioCards name="access_token_format" label={t('Access token format')} value={client.access_token_format ?? 'jwt'} disabled={!editable || busy} options={tokenFormats}
        hint={(client.access_token_format ?? 'jwt') === 'opaque' ? t('Opaque tokens are not accepted by /api/v1, /identity/v1 or SDK local validation — your APIs must call /oauth/introspect.') : undefined}
        onChange={v => { if (v === 'opaque') setOpaque(true); else void save({ access_token_format: 'jwt' }, t('Now issuing JWT access tokens')) }} />
    </DetailSection>

    <DetailSection title={t('Back-channel logout')} description={t('IAMKit POSTs a signed logout_token (OpenID Connect Back-Channel Logout) to this URL whenever a session this client signed in ends — sign-out, revocation, suspension or deletion.')}
      actions={editable && !editingBackchannel && <Button variant="outline" size="sm" aria-label={t('Edit back-channel logout')} onClick={() => setEditingBackchannel(true)}><Pencil /> {t('Edit')}</Button>}>
      {editingBackchannel ? <form className="space-y-3" onSubmit={async e => {
        e.preventDefault()
        const data = new FormData(e.currentTarget)
        const body = { backchannel_logout_uri: String(data.get('backchannel_logout_uri') ?? '').trim(), backchannel_logout_session_required: data.get('backchannel_logout_session_required') === 'on' }
        if (await save(body, body.backchannel_logout_uri ? t('Back-channel logout saved') : t('Back-channel logout turned off'))) setEditingBackchannel(false)
      }}>
        <label className="block space-y-1.5 text-sm font-medium" htmlFor="backchannel_logout_uri">{t('Logout URL')}
          <Input id="backchannel_logout_uri" name="backchannel_logout_uri" type="url" defaultValue={client.backchannel_logout_uri ?? ''} disabled={busy} placeholder="https://app.example.com/backchannel-logout — empty turns it off" />
        </label>
        <SwitchField name="backchannel_logout_session_required" label={t('Requires sid')} hint={t('The logout token always carries the session ID (sid); this records that your app relies on it.')} defaultChecked={client.backchannel_logout_session_required} disabled={busy} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={() => setEditingBackchannel(false)}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form> : client.backchannel_logout_uri
        ? <Properties items={[
          [t('Logout URL'), <code className="text-xs break-all">{client.backchannel_logout_uri}</code>],
          [t('Requires sid'), client.backchannel_logout_session_required ? t('Yes') : t('No')],
          [t('Deliveries'), <Link className="inline-flex items-center gap-1 text-primary hover:underline" to={`${console}/logout-deliveries?client_id=${client.id}`}><Radio className="size-3.5" /> {t('View delivery log')}</Link>],
        ]} />
        : <p className="text-sm text-muted-foreground">{t('Off — the application is not told when sessions end.')}</p>}
    </DetailSection>

    <HistorySection path={path} refresh={client} />

    {editable && <DetailSection danger title={t('Danger zone')} description={t('Disabling is permanent: the client can no longer sign users in. Existing sessions keep working until they expire.')}>
      <Button variant="destructive" onClick={() => setDisable(true)}><Ban /> {t('Disable client')}</Button>
    </DetailSection>}

    {auth && <ClientAuthDialog title={t('Token endpoint authentication')} current={client} onClose={() => setAuth(false)} save={async body => { await api.patch(path, body); load() }} />}
    {opaque && <ConfirmDialog title={t('Issue opaque access tokens?')} description={t('New access tokens become opaque handles. The IAMKit APIs (/api/v1, /identity/v1) and the SDKs\' local validation accept only JWTs, so your resource servers must call /oauth/introspect (or /oauth/userinfo) instead. Tokens already issued keep working.')} confirmLabel={t('Use opaque tokens')} onClose={() => setOpaque(false)} confirm={async () => { await api.patch(path, { access_token_format: 'opaque' }); toast.success(t('Now issuing opaque access tokens')); load() }} />}
    {methods && <SignInDialog base={base} client={client.id} name={name} readOnly={!canWrite} onClose={() => setMethods(false)} onSaved={load} />}
    {disable && <ConfirmDialog title={t('Disable {{name}}?', { name })} description={t('The application can no longer sign users in with this client. This cannot be undone.')} confirmLabel={t('Disable client')} onClose={() => setDisable(false)} confirm={async () => { await api.delete(path); toast.success(t('OAuth client disabled')); load() }} />}
  </div>
}
