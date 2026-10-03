import type { ReactNode } from 'react'
import { useEffect, useId, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowRight, Ban, Bot, Building2, Globe, KeyRound, Link2, LogIn, Plus, RotateCcw, Server, TriangleAlert, UserCog } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { SearchSelect } from '@/components/ui/search-select'
import { CollapsibleScopes } from '@/components/ui/collapsible-scopes'
import { PermissionPicker } from '@/components/ui/permission-picker'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, CopyText, DataTable, DetailSection, EmptyState, EntityRef, FormDialog, PageHeader, RadioCards, Status, SwitchField, ErrorState, Time, selectClass, shortId, splitList } from '@/components/library/patterns'
import type { Field } from '@/components/library/patterns'
import { CreateConnectionDialog, providerLabel, type ConnectionKind } from './federation-connection-form'
import { ClientAuthDialog, authSummary, type ClientAuth } from '@/components/library/client-auth'
import { rich, t } from '@/lib/i18n'

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id) })

// --- Service Accounts ---
interface ServiceAccount extends ClientAuth { id: string; name: string; application_id: string; application_name: string; resource_id: string; resource_name: string; permissions: string[]; expires_at: string; revoked_at: string | null; can_impersonate?: boolean }
interface Credential { id: string; secret: string; expires_at: string }

function ServiceAccountForm({ base, path, onClose, onCreated }: { base: string; path: string; onClose: () => void; onCreated: (cred: Credential) => void }) {
  const id = useId()
  const [resourceId, setResourceId] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Create service account')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Credentials are scoped to a single application and resource.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data = {
          name: String(form.get('name') ?? '').trim(),
          application_id: String(form.get('application_id') ?? '').trim(),
          resource_id: String(form.get('resource_id') ?? '').trim(),
          permissions: splitList(String(form.get('permissions') ?? '')),
          expires_in: String(form.get('expires_in') ?? '24h'),
        }
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<Credential>(path, data)
          toast.success(t('Service account created')); onCreated(result); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-app`}>{t('Application')}</label>
          <SearchSelect id={`${id}-app`} name="application_id" path={`${base}/applications`} mapItem={named} required disabled={busy} placeholder={t('Search applications…')} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-res`}>{t('Resource')}</label>
          <SearchSelect id={`${id}-res`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder={t('Search resources…')} onChange={setResourceId} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{t('Permissions')}</label>
          <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>{t('Expires in')}</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="24h">
            <option value="1h">{t('1 hour')}</option>
            <option value="24h">{t('24 hours')}</option>
            <option value="168h">{t('7 days')}</option>
            <option value="720h">{t('30 days')}</option>
            <option value="2160h">{t('90 days')}</option>
            <option value="8760h">{t('1 year')}</option>
            <option value="never">{t('No expiry')}</option>
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Creating…') : t('Create')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

export function ServiceAccountsPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/service-accounts`
  const list = usePaginatedList<ServiceAccount>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const isOwner = principal?.role === 'owner'
  const [add, setAdd] = useState(false)
  const [revoke, setRevoke] = useState<ServiceAccount | null>(null)
  const [impersonation, setImpersonation] = useState<ServiceAccount | null>(null)
  const [auth, setAuth] = useState<ServiceAccount | null>(null)
  const [secret, setSecret] = useState<Credential | null>(null)
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> {t('Create service account')}</Button>

  return <div className="space-y-6">
    <PageHeader title={t('Service accounts')} description={t('Credentials for your backend services to call a resource without a user (client credentials).')} actions={create} />
    <PaginationBar state={list} noun={t('service accounts')} />
    <DataTable columns={[t('Name'), { header: t('Access'), hideBelow: 'md' }, { header: t('Permissions'), hideBelow: 'lg' }, { header: t('Authentication'), hideBelow: 'lg' }, { header: t('Expires'), nowrap: true, hideBelow: 'sm' }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Bot />} title={t('No service accounts yet')} description={t('Create one for each backend service that calls your APIs on its own behalf. The secret is shown once.')} action={create} />}
      rows={list.data.map(sa => {
        const state = credentialState(sa)
        const cells: ReactNode[] = [
          <EntityRef name={sa.name} secondary={<span className="inline-flex items-center gap-2"><CopyText value={sa.id} short />{sa.can_impersonate && <Badge variant="outline">{t('Can impersonate')}</Badge>}</span>} />,
          <EntityRef name={sa.application_name} id={sa.application_id} to={`${console}/applications/${sa.application_id}`} secondary={sa.resource_name ? `→ ${sa.resource_name}` : undefined} />,
          sa.permissions?.length ? <CollapsibleScopes key={sa.id} scopes={sa.permissions} /> : <span className="text-xs text-muted-foreground">—</span>,
          <span className="text-xs text-muted-foreground">{authSummary(sa)}</span>,
          <Time value={sa.expires_at} />,
          <CredentialStatus state={state} />,
        ]
        if (canWrite) cells.push(state === 'active' ? <RowActions label={t('Actions for {{name}}', { name: sa.name })} actions={[{ label: t('Authentication'), icon: <KeyRound />, onSelect: () => setAuth(sa) }, ...(isOwner ? [{ label: sa.can_impersonate ? t('Stop impersonation') : t('Allow impersonation'), icon: <UserCog />, onSelect: () => setImpersonation(sa) }] : []), { label: t('Revoke'), icon: <Ban />, destructive: true, onSelect: () => setRevoke(sa) }]} /> : null)
        return cells
      })} />
    {add && <ServiceAccountForm base={base} path={path} onClose={() => setAdd(false)} onCreated={cred => { setSecret(cred); list.reload() }} />}
    {auth && <ClientAuthDialog title={t('Authentication of {{name}}', { name: auth.name })} current={auth} onClose={() => setAuth(null)} save={async body => { await api.put(`${path}/${auth.id}/authentication`, body); list.reload() }} />}
    {impersonation && <ConfirmDialog title={impersonation.can_impersonate ? t('Stop {{name}} impersonating users?', { name: impersonation.name }) : t('Let {{name}} impersonate users?', { name: impersonation.name })}
      description={impersonation.can_impersonate ? t('Sessions it opened as users end now, and it can no longer exchange a user ID for that user\'s token.') : t('It may exchange a user ID for that user\'s access token at /oauth/token (token exchange), with a reason. Every impersonation is audited. Only workspace owners can change this.')}
      confirmLabel={impersonation.can_impersonate ? t('Stop impersonation') : t('Allow impersonation')} onClose={() => setImpersonation(null)}
      confirm={async () => { const allowed = !impersonation.can_impersonate; await api.put(`${path}/${impersonation.id}/impersonation`, { allowed }); toast.success(allowed ? t('{{name}} may impersonate users', { name: impersonation.name }) : t('{{name}} can no longer impersonate users', { name: impersonation.name })); list.reload() }} />}
    {revoke && <ConfirmDialog title={t('Revoke {{name}}?', { name: revoke.name })} description={t('Services using this secret stop working immediately. This cannot be undone.')} confirmLabel={t('Revoke')} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); toast.success(t('Service account revoked')); list.reload() }} />}
    {secret && <SecretDialog title={t('Service account created')} description={t('Copy the secret now — it is shown only once.')} onClose={() => setSecret(null)} confirm={t('I have saved the secret')}>
      <CopyField label={t('Client ID')} value={secret.id} />
      <CopyField label={t('Client secret')} value={secret.secret} secret hint={<>{rich('Expires {{time}}. Use it on POST /oauth/token (grant_type=client_credentials) or /identity/v1/machine-token.', { time: <Time value={secret.expires_at} /> })}</>} />
    </SecretDialog>}
  </div>
}

export type CredentialState = 'active' | 'expired' | 'revoked'
export function credentialState(c: { revoked_at: string | null; expires_at: string }): CredentialState {
  return c.revoked_at ? 'revoked' : Date.parse(c.expires_at) <= Date.now() ? 'expired' : 'active'
}
export function CredentialStatus({ state }: { state: CredentialState }) {
  return state === 'active' ? <Status active /> : <Status active={false} label={state === 'revoked' ? t('Revoked') : t('Expired')} />
}

/** SecretDialog shows credentials that cannot be retrieved again. */
export function SecretDialog({ title, description, confirm, onClose, children }: { title: string; description: string; confirm: string; onClose: () => void; children: ReactNode }) {
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{title}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
      <div className="space-y-4">{children}</div>
      <div className="flex justify-end border-t pt-4"><Button onClick={onClose}>{confirm}</Button></div>
    </DialogContent>
  </Dialog>
}

// --- Sign-in providers (federation connections) ---
interface FederationConnection { id: string; organization_id: string | null; organization_name: string; name: string; provider: string; issuer: string; client_id: string; active: boolean; linked: number; jit_provisioning: boolean; enforcement: string; signup: boolean; link_email: boolean }

const socialScope = { scope: 'environment' }
const ssoScope = { scope: 'organization' }

/** FederationPage lists every outside sign-in provider, split into the two
 * kinds operators need to tell apart: social login for everyone, and
 * organization SSO for one company's employees. */
export function FederationPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/federation-connections`
  const social = usePaginatedList<FederationConnection>(path, { extraParams: socialScope })
  const sso = usePaginatedList<FederationConnection>(path, { extraParams: ssoScope })
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState<ConnectionKind | null>(null)
  const [disable, setDisable] = useState<FederationConnection | null>(null)
  const navigate = useNavigate()
  const detailPath = (id: string) => `${console}/federation/${id}`
  const addSocial = canWrite && <Button variant="outline" onClick={() => setAdd('social')}><Plus /> {t('Add social login')}</Button>
  const addSSO = canWrite && <Button variant="outline" onClick={() => setAdd('sso')}><Plus /> {t('Add organization SSO')}</Button>
  const columns = (who: string) => [t('Provider'), { header: who, hideBelow: 'md' as const }, { header: t('Users'), hideBelow: 'sm' as const, nowrap: true, align: 'right' as const }, t('Status'), ...(canWrite ? [t('Actions')] : [])]
  const row = (c: FederationConnection, who: ReactNode) => {
    const cells: ReactNode[] = [
      <div className="flex items-center gap-3"><ProviderMark provider={c.provider} /><EntityRef name={c.name} to={detailPath(c.id)} secondary={c.provider === 'oidc' ? <span className="break-all">{c.issuer}</span> : providerLabel(c.provider)} /></div>,
      who,
      <span className="tabular-nums">{c.linked}</span>,
      <Status active={c.active} label={c.active ? t('Active') : t('Disabled')} />,
    ]
    if (canWrite) cells.push(<RowActions label={t('Actions for {{name}}', { name: c.name })} actions={[
      { label: t('Open'), icon: <ArrowRight />, onSelect: () => navigate(detailPath(c.id)) },
      ...(c.active ? [{ label: t('Disable'), icon: <Ban />, destructive: true, onSelect: () => setDisable(c) }] : [{ label: t('Enable'), icon: <RotateCcw />, onSelect: () => enable(c) }]),
    ]} />)
    return cells
  }
  const enable = async (c: FederationConnection) => {
    try {
      await api.post(`${path}/${c.id}/enable`)
      toast.success(t('{{name}} enabled', { name: c.name }))
      social.reload(); sso.reload()
    } catch (e) { toast.error(message(e)) }
  }

  return <div className="space-y-8">
    <PageHeader title={t('Sign-in providers')} description={t('Let users sign in with an account they already have, instead of a new password. There are two kinds: social login for everyone, and organization SSO for one company\'s employees.')} />
    <div className="grid gap-3 sm:grid-cols-2">
      <Explainer icon={<Globe />} title={t('Social login')} example={t('"Continue with Google" on the sign-in page')}
        points={[t('For anyone: customers, the public'), t('Personal accounts: Google, Microsoft, GitHub, Apple'), t('Users click the button to use it')]} />
      <Explainer icon={<Building2 />} title={t('Organization SSO (single sign-on)')} example={t('Globex employees sign in with their Globex work account')}
        points={[t("For one organization's employees"), t("The company's own login: Entra ID, Google Workspace, Okta…"), t('Work emails are sent to it automatically; it can be made mandatory')]} />
    </div>

    <DetailSection title={t('Social login')} description={t('Buttons like "Continue with Google" on the sign-in page. Anyone with an account at the provider can use them.')} actions={social.data.length > 0 && addSocial}>
      <div className="space-y-3">
        {(social.total > 10 || social.rawSearch) && <PaginationBar state={social} noun="providers" />}
        <DataTable columns={columns(t('New users'))} loading={social.loading} error={social.error} retry={social.reload} rowHref={i => detailPath(social.data[i].id)}
          empty={<EmptyState icon={<Globe />} title={t('No social login yet')} description={t('Add Google, Microsoft, GitHub or Apple so users can sign in with their personal account.')} action={addSocial} />}
          rows={social.data.map(c => row(c, <span className="text-sm text-muted-foreground">{c.signup ? t('Can sign up') : t('Existing users only')}{c.link_email ? (' ' + t('· links by email')) : ''}</span>))} />
      </div>
    </DetailSection>

    <DetailSection title={t('Organization SSO')} description={t('Each organization\'s own company login. Employees whose email is on the organization\'s verified domains are sent to it. You can also add these from the organization\'s SSO tab.')} actions={sso.data.length > 0 && addSSO}>
      <div className="space-y-3">
        {(sso.total > 10 || sso.rawSearch) && <PaginationBar state={sso} noun="connections" />}
        <DataTable columns={columns(t('Organization'))} loading={sso.loading} error={sso.error} retry={sso.reload} rowHref={i => detailPath(sso.data[i].id)}
          empty={<EmptyState icon={<Building2 />} title={t('No organization SSO yet')} description={t('Connect a company\'s Entra ID, Google Workspace or Okta so its employees sign in with their work account.')} action={addSSO} />}
          rows={sso.data.map(c => row(c, <EntityRef name={c.organization_name} id={c.organization_id ?? undefined} secondary={c.enforcement === 'enforced' ? <span className="font-medium text-primary">{t('SSO required')}</span> : t('SSO optional')} />))} />
      </div>
    </DetailSection>

    {add && <CreateConnectionDialog base={base} kind={add} onClose={() => setAdd(null)} onCreated={() => (add === 'sso' ? sso : social).reload()} />}
    {disable && <ConfirmDialog title={t('Disable {{name}}?', { name: disable.name })} description={t('Users can no longer sign in with it. Their accounts and links are kept.')} confirmLabel={t('Disable')} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); toast.success(`${disable.name} disabled`); social.reload(); sso.reload() }} />}
  </div>
}

function Explainer({ icon, title, example, points }: { icon: ReactNode; title: string; example: string; points: string[] }) {
  return <div className="rounded-lg border bg-muted/30 p-4 text-sm">
    <p className="flex items-center gap-2 font-medium [&_svg]:size-4 [&_svg]:text-muted-foreground">{icon}{title}</p>
    <p className="mt-1 text-xs text-muted-foreground">{t('Example: {{example}}', { example })}</p>
    <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">{points.map(p => <li key={p}>{p}</li>)}</ul>
  </div>
}

const marks: Record<string, [string, string]> = { google: ['G', 'bg-[#4285F4]/15 text-[#4285F4]'], microsoft: ['M', 'bg-[#00A4EF]/15 text-[#00A4EF]'], github: ['GH', 'bg-foreground/10 text-foreground'], apple: ['', 'bg-foreground/10 text-foreground'] }
/** ProviderMark is a small initial badge standing in for the provider logo. */
function ProviderMark({ provider }: { provider: string }) {
  const [text, tone] = marks[provider] ?? ['', 'bg-primary/10 text-primary']
  return <span aria-hidden className={`flex size-8 shrink-0 items-center justify-center rounded-md text-xs font-semibold ${tone}`}>{text || <KeyRound className="size-4" />}</span>
}

// --- OAuth Clients ---
/** ClientWarning is an accepted setting to review (code loopback_redirect). */
export interface ClientWarning { code: string; field: string; value: string }
export interface OAuthClient extends ClientAuth { id: string; application_id: string; application_name: string; resource_id: string; resource_name: string; redirect_uris: string[]; post_logout_redirect_uris?: string[] | null; allowed_origins?: string[] | null; public: boolean; hosted_login: boolean; active: boolean; access_token_format?: 'jwt' | 'opaque'; backchannel_logout_uri?: string; backchannel_logout_session_required?: boolean; grant_types?: string[]; warnings?: ClientWarning[] | null }
export const redirectHint = t('Where users return after signing in. HTTPS; http only for localhost, 127.0.0.1 or [::1] (development and native apps).')

/** loopbackWarnings mirrors the server's warnings for URIs being edited. */
export function loopbackWarnings(redirects: string[], postLogout: string[] = []): ClientWarning[] {
  const loopback = (raw: string) => { try { const u = new URL(raw); return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname.toLowerCase()) } catch { return false } }
  return [...redirects.filter(loopback).map(value => ({ code: 'loopback_redirect', field: 'redirect_uris', value })),
    ...postLogout.filter(loopback).map(value => ({ code: 'loopback_redirect', field: 'post_logout_redirect_uris', value }))]
}

/** RedirectWarnings explains http loopback redirect URIs: allowed for
 * development and native apps, but not for a deployed web app. */
export function RedirectWarnings({ warnings }: { warnings?: ClientWarning[] | null }) {
  const loopback = (warnings ?? []).filter(w => w.code === 'loopback_redirect')
  if (!loopback.length) return null
  return <div role="note" aria-label={t('Redirect URI warning')} className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
    <TriangleAlert aria-hidden className="mt-px size-4 shrink-0 text-warning" />
    <div className="space-y-1">
      <p className="font-medium">{t('Unencrypted http redirect URIs')}</p>
      <p className="text-muted-foreground">{t('Fine for local development and native or CLI apps that receive the code on this device (a 127.0.0.1 or [::1] URI matches any port). A web app in production must use https.')}</p>
      <ul className="space-y-0.5">{loopback.map(w => <li key={w.field + w.value}><code className="break-all">{w.value}</code>{w.field === 'post_logout_redirect_uris' && <span className="text-muted-foreground"> · {t('post-logout')}</span>}</li>)}</ul>
    </div>
  </div>
}
export const signInModes = [
  { value: 'hosted', label: t('Hosted sign-in page'), description: t('IAMKit shows the sign-in pages (branding, social login, MFA) and returns to your redirect URI.') },
  { value: 'custom', label: t('Your own sign-in UI'), description: t('Your app renders the login form and completes the authorization with the ticket.') },
]
/** deviceGrant is the RFC 8628 device authorization grant type. */
export const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code'
/** exchangeGrant is the RFC 8693 token exchange grant type. */
export const exchangeGrant = 'urn:ietf:params:oauth:grant-type:token-exchange'
/** defaultGrants are the grants of clients created without grant_types. */
export const defaultGrants = ['authorization_code', 'refresh_token']
export const tokenFormats = [
  { value: 'jwt', label: 'JWT', description: t('Signed tokens your APIs and the IAMKit SDKs validate locally with the JWKS.') },
  { value: 'opaque', label: t('Opaque'), description: t('Random handles that reveal nothing; resolved only with /oauth/introspect and /oauth/userinfo.') },
]
export const clientTypes = [
  { value: 'public', label: t('Public'), description: t('Browser or mobile app. No secret; PKCE protects the flow.') },
  { value: 'confidential', label: t('Confidential'), description: t('Server-side app that can keep a client secret.') },
]

export function OAuthClientsPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/oauth-clients`
  const list = usePaginatedList<OAuthClient>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  // ?create=<application> opens the create form for that application (from its page).
  const [params, setParams] = useSearchParams()
  const preset = params.get('create') ?? ''
  const [add, setAdd] = useState(!!preset)
  const [disable, setDisable] = useState<OAuthClient | null>(null)
  const [secret, setSecret] = useState<{ id: string; client_id: string; client_secret: string; warnings?: ClientWarning[] | null } | null>(null)
  const go = useNavigate()
  const detailPath = (id: string) => `${console}/oauth-clients/${id}`

  const createFields: Field[] = [
    { name: 'application_id', label: t('Application'), type: 'select', selectPath: `${base}/applications`, selectMap: named, value: preset, hint: t('The product users sign in to.') },
    { name: 'resource_id', label: t('Resource'), type: 'select', selectPath: `${base}/resources`, selectMap: named, hint: t('The API the issued access tokens are for. It must be linked to the application.') },
    { name: 'redirect_uris', label: t('Redirect URIs'), type: 'tags', hint: redirectHint },
    { name: 'type', label: t('Client type'), type: 'radio', value: 'public', options: clientTypes },
    { name: 'sign_in', label: t('Sign-in experience'), type: 'radio', value: 'hosted', options: signInModes },
  ]
  const toggleHosted = async (c: OAuthClient) => {
    try { await api.patch(`${path}/${c.id}`, { hosted_login: !c.hosted_login }); toast.success(c.hosted_login ? t('Now using your own sign-in UI') : t('Now using the hosted sign-in page')); list.reload() } catch (e) { toast.error(message(e)) }
  }
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> {t('Create client')}</Button>

  return <div className="space-y-6">
    <PageHeader title={t('OAuth clients')} description={t('How an application signs users in: its redirect URIs, client type and sign-in experience.')} actions={create} />
    <PaginationBar state={list} noun="clients" placeholder={t('Search by application or resource…')} />
    <DataTable columns={[t('Application'), { header: t('Sign-in'), hideBelow: 'md' }, { header: t('Redirect URIs'), hideBelow: 'lg' }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload} rowHref={i => detailPath(list.data[i].id)}
      empty={<EmptyState icon={<Link2 />} title={t('No OAuth clients yet')} description={t('Create a client to let an application sign users in. You need an application and a resource linked to it first.')} action={create} />}
      rows={list.data.map(c => {
        const cells: ReactNode[] = [
          <EntityRef name={c.application_name || shortId(c.application_id)} to={detailPath(c.id)} secondary={<span className="inline-flex flex-wrap items-center gap-x-2">{c.resource_name && <span>→ {c.resource_name}</span>}<span>{c.public ? t('Public') : t('Confidential')}</span><CopyText value={c.id} short label={t('Copy client ID')} /></span>} />,
          <Badge variant="outline">{c.hosted_login ? t('Hosted page') : t('Your UI')}</Badge>,
          <RedirectList uris={c.redirect_uris} warned={!!c.warnings?.length} />,
          <Status active={c.active} label={c.active ? t('Active') : t('Disabled')} />,
        ]
        if (canWrite) cells.push(<RowActions label={t('Actions for {{value}}', { value: c.application_name || c.id })} actions={[
          { label: t('Open'), icon: <ArrowRight />, onSelect: () => go(detailPath(c.id)) },
          ...(c.active ? [
            { label: c.hosted_login ? t('Switch to your own UI') : t('Switch to hosted page'), icon: <LogIn />, onSelect: () => void toggleHosted(c) },
            { label: t('Disable client'), icon: <Ban />, destructive: true, onSelect: () => setDisable(c) },
          ] : []),
        ]} />)
        return cells
      })} />
    {add && <FormDialog title={t('Create OAuth client')} description={t('Connect an application to sign-in.')} fields={createFields} submitLabel={t('Create client')} success={t('OAuth client created')} onClose={() => { setAdd(false); if (preset) setParams({}, { replace: true }) }} submit={async values => {
      const data = { application_id: values.application_id, resource_id: values.resource_id, redirect_uris: splitList(values.redirect_uris), public: values.type === 'public', hosted_login: values.sign_in === 'hosted' }
      const result = await api.post<{ id: string; client_id: string; client_secret: string; warnings?: ClientWarning[] | null }>(path, data)
      setSecret(result)
      list.reload()
    }} />}
    {disable && <ConfirmDialog title={t('Disable this OAuth client?')} description={t('{{application}} can no longer sign users in with this client. Existing sessions keep working until they expire.', { application: disable.application_name || t('The application') })} confirmLabel={t('Disable client')} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); toast.success(t('OAuth client disabled')); list.reload() }} />}
    {secret && <SecretDialog title={t('OAuth client created')} description={secret.client_secret ? t('Copy the client secret now — it is shown only once.') : t('This is a public client, so it has no secret.')} confirm={secret.client_secret ? t('I have saved the secret') : t('Done')} onClose={() => { setSecret(null); go(detailPath(secret.id)) }}>
      <CopyField label={t('Client ID')} value={secret.client_id} />
      {secret.client_secret && <CopyField label={t('Client secret')} value={secret.client_secret} secret />}
      <RedirectWarnings warnings={secret.warnings} />
    </SecretDialog>}
  </div>
}

/** RedirectList shows the first redirect URI and how many more exist;
 * `warned` marks a client with http loopback redirects. */
export function RedirectList({ uris, warned }: { uris: string[] | null; warned?: boolean }) {
  if (!uris?.length) return <span className="text-muted-foreground">—</span>
  return <span className="block max-w-xs text-xs" title={uris.join('\n')}><span className="flex items-center gap-1">{warned && <TriangleAlert role="img" aria-label={t('Uses http redirect URIs')} className="size-3.5 shrink-0 text-warning" />}<span className="truncate font-mono">{uris[0]}</span></span>{uris.length > 1 && <span className="text-muted-foreground">{t('+{{count}} more', { count: uris.length - 1 })}</span>}</span>
}

// --- Provisioning (SCIM) Credentials ---
interface ProvCredential { id: string; name: string; organization_id: string; organization_name: string; connection_id: string; connection_name: string; expires_at: string; revoked_at: string | null; adopt_existing_members?: boolean; adopt_scope?: 'any' | 'verified_domains'; map_phone?: boolean }
const lifetimes = [
  { label: t('1 hour'), value: '1h' }, { label: t('24 hours'), value: '24h' }, { label: t('7 days'), value: '168h' }, { label: t('30 days'), value: '720h' },
  { label: t('90 days'), value: '2160h' }, { label: t('1 year'), value: '8760h' }, { label: t('No expiry'), value: 'never' },
]

export function ProvisioningPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/provisioning-credentials`
  const list = usePaginatedList<ProvCredential>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState<ProvCredential | true | null>(null)
  const [revoke, setRevoke] = useState<ProvCredential | null>(null)
  const [secret, setSecret] = useState<{ id: string; secret: string; expires_at: string; connection_id: string } | null>(null)
  const [link, setLink] = useState<ProvCredential | null>(null)
  const scimURL = `${window.location.origin}/scim/v2`
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> {t('Connect a directory')}</Button>

  return <div className="space-y-6">
    <PageHeader title={t('SCIM provisioning')} description={t('Let an organization\'s directory (Microsoft Entra ID, Okta, …) create, update and remove its users automatically.')} actions={create} />
    <div className="rounded-lg border bg-muted/30 p-3"><CopyField label={t('SCIM base URL')} value={scimURL} hint={t('Paste this into your directory\'s provisioning settings together with a token issued below.')} /></div>
    <PaginationBar state={list} noun="tokens" />
    <DataTable columns={[t('Token'), { header: t('Organization'), hideBelow: 'sm' }, { header: t('Existing members'), hideBelow: 'lg' }, { header: t('Expires'), nowrap: true, hideBelow: 'md' }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Server />} title={t('No directories connected')} description={t('Issue a token for an organization, then paste it and the SCIM base URL into its directory.')} action={create} />}
      rows={list.data.map(c => {
        const state = credentialState(c)
        const cells: ReactNode[] = [
          <EntityRef name={c.name} secondary={<span className="inline-flex flex-wrap items-center gap-x-2"><span>{t('Connection:')} {c.connection_name || shortId(c.connection_id)}</span><CopyText value={c.connection_id} short label={t('Copy connection ID')} /></span>} />,
          <EntityRef name={c.organization_name} id={c.organization_id} to={`${console}/organizations/${c.organization_id}/members`} />,
          <span className="text-sm">{c.adopt_existing_members ? (c.adopt_scope === 'verified_domains' ? t('Adopted (verified domains)') : t('Adopted by email')) : t('Not adopted')}</span>,
          <Time value={c.expires_at} />,
          <CredentialStatus state={state} />,
        ]
        if (canWrite) cells.push(<RowActions label={t('Actions for {{name}}', { name: c.name })} actions={[
          { label: t('Issue another token'), icon: <Plus />, onSelect: () => setAdd(c) },
          { label: t('Link a user manually'), icon: <Link2 />, onSelect: () => setLink(c) },
          ...(state === 'active' ? [{ label: t('Revoke token'), icon: <Ban />, destructive: true, onSelect: () => setRevoke(c) }] : []),
        ]} />)
        return cells
      })} />
    {add && <IssueTokenDialog base={base} path={path} existing={add === true ? null : add} onClose={() => setAdd(null)} onIssued={result => { setSecret(result); list.reload() }} />}
    {revoke && <ConfirmDialog title={t('Revoke {{name}}?', { name: revoke.name })} description={t('The directory using this token can no longer provision users. Users already provisioned are kept.')} confirmLabel={t('Revoke token')} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); toast.success(t('Token revoked')); list.reload() }} />}
    {link && <FormDialog title={t('Link a user manually')} description={t('Tell {{connection}} that a directory user is an existing user here, so SCIM updates that user instead of creating a new one.', { connection: link.connection_name || t('this connection') })} submitLabel={t('Link user')} success={t('User linked')} fields={[
      { name: 'user_id', label: t('User'), type: 'select', selectPath: `${base}/users`, selectMap: named },
      { name: 'external_id', label: t('Directory user ID'), hint: t('The user\'s externalId in the directory (Entra: object ID).') },
    ]} onClose={() => setLink(null)} submit={async values => { await api.post(`${base}/provisioned-identities`, { ...values, connection_id: link.connection_id }) }} />}
    {secret && <SecretDialog title={t('Token issued')} description={t('Copy the token now — it is shown only once. Paste both values into the directory\'s provisioning settings.')} confirm={t('I have saved the token')} onClose={() => setSecret(null)}>
      <CopyField label={t('SCIM base URL (Tenant URL)')} value={scimURL} />
      <CopyField label={t('Bearer token (Secret token)')} value={secret.secret} secret hint={<>{rich('Expires {{time}}.', { time: <Time value={secret.expires_at} /> })}</>} />
    </SecretDialog>}
  </div>
}

function IssueTokenDialog({ base, path, existing, onClose, onIssued }: { base: string; path: string; existing: ProvCredential | null; onClose: () => void; onIssued: (r: { id: string; secret: string; expires_at: string; connection_id: string }) => void }) {
  const id = useId()
  const [organization, setOrganization] = useState(existing?.organization_id ?? '')
  const [connection, setConnection] = useState(existing?.connection_id ?? '')
  const [connections, setConnections] = useState<ProvCredential[]>([])
  const [adopt, setAdopt] = useState(existing?.adopt_existing_members ?? false)
  const [scope, setScope] = useState<string>(existing?.adopt_scope ?? 'verified_domains')
  const [mapPhone, setMapPhone] = useState(existing?.map_phone ?? false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  useEffect(() => {
    if (!organization || existing) return
    const controller = new AbortController()
    // Existing SCIM connections of the organization, derived from its tokens.
    api.list<ProvCredential>(path, controller.signal).then(r => {
      const seen = new Map<string, ProvCredential>()
      for (const c of r.data) if (c.organization_id === organization && !seen.has(c.connection_id)) seen.set(c.connection_id, c)
      setConnections([...seen.values()])
    }).catch(() => setConnections([]))
    return () => controller.abort()
  }, [organization, path, existing])
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? t('Issue another token for {{connection}}', { connection: existing.connection_name || t('this directory') }) : t('Connect a directory')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{existing ? t('Use this to rotate the token. Revoke the old one once the directory uses the new token.') : t('The token lets one organization\'s directory provision users with SCIM.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const body: Record<string, unknown> = {
          name: String(form.get('name') ?? '').trim(), organization_id: organization, expires_in: String(form.get('expires_in') ?? '8760h'),
          adopt_existing_members: adopt, adopt_scope: adopt ? scope : 'any', map_phone: mapPhone,
        }
        if (connection) body.connection_id = connection
        pending.current = true; setBusy(true); setError('')
        try { onIssued(await api.post(path, body)); toast.success(t('Token issued')); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} placeholder={t('e.g. Acme Entra ID')} defaultValue={existing ? `${existing.connection_name || existing.name} (rotated)` : ''} />
        </div>
        {!existing && <>
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor={`${id}-org`}>{t('Organization')}</label>
            <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder={t('Search organizations…')} onChange={v => { setOrganization(v); setConnection('') }} />
            <p className="text-xs text-muted-foreground">{t('Users from the directory become members of this organization.')}</p>
          </div>
          {organization && connections.length > 0 && <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor={`${id}-conn`}>{t('Directory')}</label>
            <select id={`${id}-conn`} className={selectClass} value={connection} onChange={e => {
              const picked = connections.find(c => c.connection_id === e.target.value)
              setConnection(e.target.value); setAdopt(picked?.adopt_existing_members ?? false); setScope(picked?.adopt_scope ?? 'verified_domains'); setMapPhone(picked?.map_phone ?? false)
            }} disabled={busy}>
              <option value="">{t('New directory connection')}</option>
              {connections.map(c => <option key={c.connection_id} value={c.connection_id}>{c.connection_name || shortId(c.connection_id)} {t('(add a token)')}</option>)}
            </select>
          </div>}
        </>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>{t('Token expires in')}</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="8760h" disabled={busy}>{lifetimes.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
        </div>
        <SwitchField label={t('Adopt existing members')} hint={t('When the directory sends a user whose email already belongs to a member, link to that member instead of rejecting the user.')} checked={adopt} onCheckedChange={setAdopt} disabled={busy} />
        {adopt && <RadioCards name="adopt_scope" label={t('Which emails can be adopted')} value={scope} onChange={setScope} disabled={busy} options={[
          { value: 'verified_domains', label: t('Verified domains only'), description: t('Only emails on the organization\'s verified domains. Safer.') },
          { value: 'any', label: t('Any email'), description: t('Any member with a matching email.') },
        ]} />}
        <SwitchField label={t('Sync mobile phone numbers')} hint={t('Take each user\'s phone number from the directory\'s mobile number. Off: phone numbers set here are left alone.')} checked={mapPhone} onCheckedChange={setMapPhone} disabled={busy} />
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy || !organization}>{busy ? t('Issuing…') : t('Issue token')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
