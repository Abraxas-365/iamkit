import type { ReactNode } from 'react'
import { useEffect, useId, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowRight, Ban, Bot, Globe, KeyRound, Link2, LogIn, Plus, Server } from 'lucide-react'
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
import { ConfirmDialog, CopyField, CopyText, DataTable, EmptyState, EntityRef, FormDialog, PageHeader, RadioCards, Status, SwitchField, ErrorState, Time, selectClass, shortId, splitList } from '@/components/library/patterns'
import type { Field } from '@/components/library/patterns'
import { CreateConnectionDialog, providerLabel } from './federation-connection-form'

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id) })

// --- Service Accounts ---
interface ServiceAccount { id: string; name: string; application_id: string; application_name: string; resource_id: string; resource_name: string; permissions: string[]; expires_at: string; revoked_at: string | null }
interface Credential { id: string; secret: string; expires_at: string }

function ServiceAccountForm({ base, path, onClose, onCreated }: { base: string; path: string; onClose: () => void; onCreated: (cred: Credential) => void }) {
  const id = useId()
  const [resourceId, setResourceId] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">Create service account</DialogTitle>
      <DialogDescription className="text-muted-foreground">Credentials are scoped to a single application and resource.</DialogDescription>
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
          toast.success('Service account created'); onCreated(result); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>Name</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-app`}>Application</label>
          <SearchSelect id={`${id}-app`} name="application_id" path={`${base}/applications`} mapItem={named} required disabled={busy} placeholder="Search applications…" />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-res`}>Resource</label>
          <SearchSelect id={`${id}-res`} name="resource_id" path={`${base}/resources`} mapItem={named} required disabled={busy} placeholder="Search resources…" onChange={setResourceId} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">Permissions</label>
          <PermissionPicker resourcesPath={`${base}/resources`} resourceId={resourceId} name="permissions" disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>Expires in</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="24h">
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="168h">7 days</option>
            <option value="720h">30 days</option>
            <option value="2160h">90 days</option>
            <option value="8760h">1 year</option>
            <option value="never">No expiry</option>
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create'}</Button>
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
  const [add, setAdd] = useState(false)
  const [revoke, setRevoke] = useState<ServiceAccount | null>(null)
  const [secret, setSecret] = useState<Credential | null>(null)
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> Create service account</Button>

  return <div className="space-y-6">
    <PageHeader title="Service accounts" description="Credentials for your backend services to call a resource without a user (client credentials)." actions={create} />
    <PaginationBar state={list} noun="service accounts" />
    <DataTable columns={['Name', { header: 'Access', hideBelow: 'md' }, { header: 'Permissions', hideBelow: 'lg' }, { header: 'Expires', nowrap: true, hideBelow: 'sm' }, 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Bot />} title="No service accounts yet" description="Create one for each backend service that calls your APIs on its own behalf. The secret is shown once." action={create} />}
      rows={list.data.map(sa => {
        const state = credentialState(sa)
        const cells: ReactNode[] = [
          <EntityRef name={sa.name} secondary={<CopyText value={sa.id} short />} />,
          <EntityRef name={sa.application_name} id={sa.application_id} to={`${console}/applications/${sa.application_id}`} secondary={sa.resource_name ? `→ ${sa.resource_name}` : undefined} />,
          sa.permissions?.length ? <CollapsibleScopes key={sa.id} scopes={sa.permissions} /> : <span className="text-xs text-muted-foreground">—</span>,
          <Time value={sa.expires_at} />,
          <CredentialStatus state={state} />,
        ]
        if (canWrite) cells.push(state === 'active' ? <RowActions label={`Actions for ${sa.name}`} actions={[{ label: 'Revoke', icon: <Ban />, destructive: true, onSelect: () => setRevoke(sa) }]} /> : null)
        return cells
      })} />
    {add && <ServiceAccountForm base={base} path={path} onClose={() => setAdd(false)} onCreated={cred => { setSecret(cred); list.reload() }} />}
    {revoke && <ConfirmDialog title={`Revoke ${revoke.name}?`} description="Services using this secret stop working immediately. This cannot be undone." confirmLabel="Revoke" onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); toast.success('Service account revoked'); list.reload() }} />}
    {secret && <SecretDialog title="Service account created" description="Copy the secret now — it is shown only once." onClose={() => setSecret(null)} confirm="I have saved the secret">
      <CopyField label="Client ID" value={secret.id} />
      <CopyField label="Client secret" value={secret.secret} secret hint={<>Expires <Time value={secret.expires_at} />.</>} />
    </SecretDialog>}
  </div>
}

type CredentialState = 'active' | 'expired' | 'revoked'
function credentialState(c: { revoked_at: string | null; expires_at: string }): CredentialState {
  return c.revoked_at ? 'revoked' : Date.parse(c.expires_at) <= Date.now() ? 'expired' : 'active'
}
function CredentialStatus({ state }: { state: CredentialState }) {
  return state === 'active' ? <Status active /> : <Status active={false} label={state === 'revoked' ? 'Revoked' : 'Expired'} />
}

/** SecretDialog shows credentials that cannot be retrieved again. */
function SecretDialog({ title, description, confirm, onClose, children }: { title: string; description: string; confirm: string; onClose: () => void; children: ReactNode }) {
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{title}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
      <div className="space-y-4">{children}</div>
      <div className="flex justify-end border-t pt-4"><Button onClick={onClose}>{confirm}</Button></div>
    </DialogContent>
  </Dialog>
}

// --- Federation Connections ---
interface FederationConnection { id: string; organization_id: string | null; organization_name: string; name: string; provider: string; issuer: string; client_id: string; active: boolean; linked: number; jit_provisioning: boolean; enforcement: string; signup: boolean; link_email: boolean }

export function FederationPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/federation-connections`
  const list = usePaginatedList<FederationConnection>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState(false)
  const [disable, setDisable] = useState<FederationConnection | null>(null)
  const navigate = useNavigate()
  const detailPath = (id: string) => `${console}/federation/${id}`
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> Add connection</Button>

  return <div className="space-y-6">
    <PageHeader title="Social & SSO" description="Let users sign in with Google, Microsoft, GitHub or Apple, or with an organization's own identity provider (enterprise SSO)." actions={create} />
    <PaginationBar state={list} noun="connections" />
    <DataTable columns={['Connection', { header: 'Available to', hideBelow: 'md' }, { header: 'Linked users', hideBelow: 'sm', nowrap: true }, 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading} error={list.error} retry={list.reload} rowHref={i => detailPath(list.data[i].id)}
      empty={<EmptyState icon={<Globe />} title="No sign-in connections yet" description="Add Google, Microsoft, GitHub or Apple for social login, or an organization's OIDC provider for enterprise SSO." action={create} />}
      rows={list.data.map(c => {
        const cells: ReactNode[] = [
          <div className="flex items-center gap-3"><ProviderMark provider={c.provider} /><EntityRef name={c.name} to={detailPath(c.id)} secondary={c.provider === 'oidc' ? <span className="break-all">{c.issuer}</span> : providerLabel(c.provider)} /></div>,
          c.organization_id
            ? <EntityRef name={c.organization_name} id={c.organization_id} secondary={c.enforcement === 'enforced' ? <span className="font-medium text-primary">SSO required</span> : 'Enterprise SSO'} />
            : <EntityRef name="Everyone" secondary={[c.signup && 'New users can sign up', c.link_email && 'Links by email'].filter(Boolean).join(' · ') || 'Existing users only'} />,
          <span className="tabular-nums">{c.linked}</span>,
          <Status active={c.active} label={c.active ? 'Active' : 'Disabled'} />,
        ]
        if (canWrite) cells.push(<RowActions label={`Actions for ${c.name}`} actions={[
          { label: 'Open', icon: <ArrowRight />, onSelect: () => navigate(detailPath(c.id)) },
          ...(c.active ? [{ label: 'Disable', icon: <Ban />, destructive: true, onSelect: () => setDisable(c) }] : []),
        ]} />)
        return cells
      })} />
    {add && <CreateConnectionDialog base={base} onClose={() => setAdd(false)} onCreated={list.reload} />}
    {disable && <ConfirmDialog title={`Disable ${disable.name}?`} description="Users can no longer sign in with this connection. Linked accounts are kept." confirmLabel="Disable" onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); toast.success('Connection disabled'); list.reload() }} />}
  </div>
}

const marks: Record<string, [string, string]> = { google: ['G', 'bg-[#4285F4]/15 text-[#4285F4]'], microsoft: ['M', 'bg-[#00A4EF]/15 text-[#00A4EF]'], github: ['GH', 'bg-foreground/10 text-foreground'], apple: ['', 'bg-foreground/10 text-foreground'] }
/** ProviderMark is a small initial badge standing in for the provider logo. */
function ProviderMark({ provider }: { provider: string }) {
  const [text, tone] = marks[provider] ?? ['', 'bg-primary/10 text-primary']
  return <span aria-hidden className={`flex size-8 shrink-0 items-center justify-center rounded-md text-xs font-semibold ${tone}`}>{text || <KeyRound className="size-4" />}</span>
}

// --- OAuth Clients ---
export interface OAuthClient { id: string; application_id: string; application_name: string; resource_id: string; resource_name: string; redirect_uris: string[]; public: boolean; hosted_login: boolean; active: boolean }
export const signInModes = [
  { value: 'hosted', label: 'Hosted sign-in page', description: 'IAMKit shows the sign-in pages (branding, social login, MFA) and returns to your redirect URI.' },
  { value: 'custom', label: 'Your own sign-in UI', description: 'Your app renders the login form and completes the authorization with the ticket.' },
]
export const clientTypes = [
  { value: 'public', label: 'Public', description: 'Browser or mobile app. No secret; PKCE protects the flow.' },
  { value: 'confidential', label: 'Confidential', description: 'Server-side app that can keep a client secret.' },
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
  const [secret, setSecret] = useState<{ id: string; client_id: string; client_secret: string } | null>(null)
  const go = useNavigate()
  const detailPath = (id: string) => `${console}/oauth-clients/${id}`

  const createFields: Field[] = [
    { name: 'application_id', label: 'Application', type: 'select', selectPath: `${base}/applications`, selectMap: named, value: preset, hint: 'The product users sign in to.' },
    { name: 'resource_id', label: 'Resource', type: 'select', selectPath: `${base}/resources`, selectMap: named, hint: 'The API the issued access tokens are for. It must be linked to the application.' },
    { name: 'redirect_uris', label: 'Redirect URIs', type: 'tags', hint: 'Where users return after signing in. Type a full URL and press Enter.' },
    { name: 'type', label: 'Client type', type: 'radio', value: 'public', options: clientTypes },
    { name: 'sign_in', label: 'Sign-in experience', type: 'radio', value: 'hosted', options: signInModes },
  ]
  const toggleHosted = async (c: OAuthClient) => {
    try { await api.patch(`${path}/${c.id}`, { hosted_login: !c.hosted_login }); toast.success(c.hosted_login ? 'Now using your own sign-in UI' : 'Now using the hosted sign-in page'); list.reload() } catch (e) { toast.error(message(e)) }
  }
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> Create client</Button>

  return <div className="space-y-6">
    <PageHeader title="OAuth clients" description="How an application signs users in: its redirect URIs, client type and sign-in experience." actions={create} />
    <PaginationBar state={list} noun="clients" placeholder="Search by application or resource…" />
    <DataTable columns={['Application', { header: 'Sign-in', hideBelow: 'md' }, { header: 'Redirect URIs', hideBelow: 'lg' }, 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading} error={list.error} retry={list.reload} rowHref={i => detailPath(list.data[i].id)}
      empty={<EmptyState icon={<Link2 />} title="No OAuth clients yet" description="Create a client to let an application sign users in. You need an application and a resource linked to it first." action={create} />}
      rows={list.data.map(c => {
        const cells: ReactNode[] = [
          <EntityRef name={c.application_name || shortId(c.application_id)} to={detailPath(c.id)} secondary={<span className="inline-flex flex-wrap items-center gap-x-2">{c.resource_name && <span>→ {c.resource_name}</span>}<span>{c.public ? 'Public' : 'Confidential'}</span><CopyText value={c.id} short label="Copy client ID" /></span>} />,
          <Badge variant="outline">{c.hosted_login ? 'Hosted page' : 'Your UI'}</Badge>,
          <RedirectList uris={c.redirect_uris} />,
          <Status active={c.active} label={c.active ? 'Active' : 'Disabled'} />,
        ]
        if (canWrite) cells.push(<RowActions label={`Actions for ${c.application_name || c.id}`} actions={[
          { label: 'Open', icon: <ArrowRight />, onSelect: () => go(detailPath(c.id)) },
          ...(c.active ? [
            { label: c.hosted_login ? 'Switch to your own UI' : 'Switch to hosted page', icon: <LogIn />, onSelect: () => void toggleHosted(c) },
            { label: 'Disable client', icon: <Ban />, destructive: true, onSelect: () => setDisable(c) },
          ] : []),
        ]} />)
        return cells
      })} />
    {add && <FormDialog title="Create OAuth client" description="Connect an application to sign-in." fields={createFields} submitLabel="Create client" success="OAuth client created" onClose={() => { setAdd(false); if (preset) setParams({}, { replace: true }) }} submit={async values => {
      const data = { application_id: values.application_id, resource_id: values.resource_id, redirect_uris: splitList(values.redirect_uris), public: values.type === 'public', hosted_login: values.sign_in === 'hosted' }
      const result = await api.post<{ id: string; client_id: string; client_secret: string }>(path, data)
      setSecret(result)
      list.reload()
    }} />}
    {disable && <ConfirmDialog title="Disable this OAuth client?" description={`${disable.application_name || 'The application'} can no longer sign users in with this client. Existing sessions keep working until they expire.`} confirmLabel="Disable client" onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); toast.success('OAuth client disabled'); list.reload() }} />}
    {secret && <SecretDialog title="OAuth client created" description={secret.client_secret ? 'Copy the client secret now — it is shown only once.' : 'This is a public client, so it has no secret.'} confirm={secret.client_secret ? 'I have saved the secret' : 'Done'} onClose={() => { setSecret(null); go(detailPath(secret.id)) }}>
      <CopyField label="Client ID" value={secret.client_id} />
      {secret.client_secret && <CopyField label="Client secret" value={secret.client_secret} secret />}
    </SecretDialog>}
  </div>
}

/** RedirectList shows the first redirect URI and how many more exist. */
export function RedirectList({ uris }: { uris: string[] | null }) {
  if (!uris?.length) return <span className="text-muted-foreground">—</span>
  return <span className="block max-w-xs text-xs" title={uris.join('\n')}><span className="block truncate font-mono">{uris[0]}</span>{uris.length > 1 && <span className="text-muted-foreground">+{uris.length - 1} more</span>}</span>
}

// --- Provisioning (SCIM) Credentials ---
interface ProvCredential { id: string; name: string; organization_id: string; organization_name: string; connection_id: string; connection_name: string; expires_at: string; revoked_at: string | null; adopt_existing_members?: boolean; adopt_scope?: 'any' | 'verified_domains' }
const lifetimes = [
  { label: '1 hour', value: '1h' }, { label: '24 hours', value: '24h' }, { label: '7 days', value: '168h' }, { label: '30 days', value: '720h' },
  { label: '90 days', value: '2160h' }, { label: '1 year', value: '8760h' }, { label: 'No expiry', value: 'never' },
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
  const create = canWrite && <Button onClick={() => setAdd(true)}><Plus /> Connect a directory</Button>

  return <div className="space-y-6">
    <PageHeader title="SCIM provisioning" description="Let an organization's directory (Microsoft Entra ID, Okta, …) create, update and remove its users automatically." actions={create} />
    <div className="rounded-lg border bg-muted/30 p-3"><CopyField label="SCIM base URL" value={scimURL} hint="Paste this into your directory's provisioning settings together with a token issued below." /></div>
    <PaginationBar state={list} noun="tokens" />
    <DataTable columns={['Token', { header: 'Organization', hideBelow: 'sm' }, { header: 'Existing members', hideBelow: 'lg' }, { header: 'Expires', nowrap: true, hideBelow: 'md' }, 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<Server />} title="No directories connected" description="Issue a token for an organization, then paste it and the SCIM base URL into its directory." action={create} />}
      rows={list.data.map(c => {
        const state = credentialState(c)
        const cells: ReactNode[] = [
          <EntityRef name={c.name} secondary={<span className="inline-flex flex-wrap items-center gap-x-2"><span>Connection: {c.connection_name || shortId(c.connection_id)}</span><CopyText value={c.connection_id} short label="Copy connection ID" /></span>} />,
          <EntityRef name={c.organization_name} id={c.organization_id} to={`${console}/organizations/${c.organization_id}/members`} />,
          <span className="text-sm">{c.adopt_existing_members ? (c.adopt_scope === 'verified_domains' ? 'Adopted (verified domains)' : 'Adopted by email') : 'Not adopted'}</span>,
          <Time value={c.expires_at} />,
          <CredentialStatus state={state} />,
        ]
        if (canWrite) cells.push(<RowActions label={`Actions for ${c.name}`} actions={[
          { label: 'Issue another token', icon: <Plus />, onSelect: () => setAdd(c) },
          { label: 'Link a user manually', icon: <Link2 />, onSelect: () => setLink(c) },
          ...(state === 'active' ? [{ label: 'Revoke token', icon: <Ban />, destructive: true, onSelect: () => setRevoke(c) }] : []),
        ]} />)
        return cells
      })} />
    {add && <IssueTokenDialog base={base} path={path} existing={add === true ? null : add} onClose={() => setAdd(null)} onIssued={result => { setSecret(result); list.reload() }} />}
    {revoke && <ConfirmDialog title={`Revoke ${revoke.name}?`} description="The directory using this token can no longer provision users. Users already provisioned are kept." confirmLabel="Revoke token" onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); toast.success('Token revoked'); list.reload() }} />}
    {link && <FormDialog title="Link a user manually" description={`Tell ${link.connection_name || 'this connection'} that a directory user is an existing user here, so SCIM updates that user instead of creating a new one.`} submitLabel="Link user" success="User linked" fields={[
      { name: 'user_id', label: 'User', type: 'select', selectPath: `${base}/users`, selectMap: named },
      { name: 'external_id', label: 'Directory user ID', hint: "The user's externalId in the directory (Entra: object ID)." },
    ]} onClose={() => setLink(null)} submit={async values => { await api.post(`${base}/provisioned-identities`, { ...values, connection_id: link.connection_id }) }} />}
    {secret && <SecretDialog title="Token issued" description="Copy the token now — it is shown only once. Paste both values into the directory's provisioning settings." confirm="I have saved the token" onClose={() => setSecret(null)}>
      <CopyField label="SCIM base URL (Tenant URL)" value={scimURL} />
      <CopyField label="Bearer token (Secret token)" value={secret.secret} secret hint={<>Expires <Time value={secret.expires_at} />.</>} />
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
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? `Issue another token for ${existing.connection_name || 'this directory'}` : 'Connect a directory'}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{existing ? 'Use this to rotate the token. Revoke the old one once the directory uses the new token.' : "The token lets one organization's directory provision users with SCIM."}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const body: Record<string, unknown> = {
          name: String(form.get('name') ?? '').trim(), organization_id: organization, expires_in: String(form.get('expires_in') ?? '8760h'),
          adopt_existing_members: adopt, adopt_scope: adopt ? scope : 'any',
        }
        if (connection) body.connection_id = connection
        pending.current = true; setBusy(true); setError('')
        try { onIssued(await api.post(path, body)); toast.success('Token issued'); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>Name</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} placeholder="e.g. Acme Entra ID" defaultValue={existing ? `${existing.connection_name || existing.name} (rotated)` : ''} />
        </div>
        {!existing && <>
          <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor={`${id}-org`}>Organization</label>
            <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder="Search organizations…" onChange={v => { setOrganization(v); setConnection('') }} />
            <p className="text-xs text-muted-foreground">Users from the directory become members of this organization.</p>
          </div>
          {organization && connections.length > 0 && <div className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor={`${id}-conn`}>Directory</label>
            <select id={`${id}-conn`} className={selectClass} value={connection} onChange={e => {
              const picked = connections.find(c => c.connection_id === e.target.value)
              setConnection(e.target.value); setAdopt(picked?.adopt_existing_members ?? false); setScope(picked?.adopt_scope ?? 'verified_domains')
            }} disabled={busy}>
              <option value="">New directory connection</option>
              {connections.map(c => <option key={c.connection_id} value={c.connection_id}>{c.connection_name || shortId(c.connection_id)} (add a token)</option>)}
            </select>
          </div>}
        </>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>Token expires in</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="8760h" disabled={busy}>{lifetimes.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
        </div>
        <SwitchField label="Adopt existing members" hint="When the directory sends a user whose email already belongs to a member, link to that member instead of rejecting the user." checked={adopt} onCheckedChange={setAdopt} disabled={busy} />
        {adopt && <RadioCards name="adopt_scope" label="Which emails can be adopted" value={scope} onChange={setScope} disabled={busy} options={[
          { value: 'verified_domains', label: 'Verified domains only', description: "Only emails on the organization's verified domains. Safer." },
          { value: 'any', label: 'Any email', description: 'Any member with a matching email.' },
        ]} />}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy || !organization}>{busy ? 'Issuing…' : 'Issue token'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
