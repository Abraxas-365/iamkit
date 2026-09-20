import { useId, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Plus } from 'lucide-react'
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
import { ConfirmDialog, DataTable, FormDialog, ID, PageHeader, Status, ErrorState, splitList } from '@/components/library/patterns'
import type { Field } from '@/components/library/patterns'

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
          <select id={`${id}-ttl`} name="expires_in" className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" defaultValue="24h">
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
  const { environment } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/service-accounts`
  const list = usePaginatedList<ServiceAccount>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState(false)
  const [revoke, setRevoke] = useState<ServiceAccount | null>(null)
  const [secret, setSecret] = useState<Credential | null>(null)

  return <div className="space-y-6">
    <PageHeader title="Service accounts" description="Machine-to-machine credentials scoped to an application and resource." actions={canWrite && <Button onClick={() => setAdd(true)}><Plus className="size-4" /> Create</Button>} />
    <PaginationBar state={list} noun="service accounts" />
    <DataTable columns={['Name / ID', 'Application', 'Resource', 'Permissions', 'Expires', 'Status', ...(canWrite ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(sa => {
      const active = !sa.revoked_at && Date.parse(sa.expires_at) > Date.now()
      const cells: React.ReactNode[] = [
        <div className="space-y-1"><p className="font-medium">{sa.name}</p><ID value={sa.id} /></div>,
        <span className="text-sm">{sa.application_name || <ID value={sa.application_id} />}</span>,
        <span className="text-sm">{sa.resource_name || <ID value={sa.resource_id} />}</span>,
        sa.permissions?.length ? <CollapsibleScopes key={sa.id} scopes={sa.permissions} /> : <span className="text-xs text-muted-foreground">—</span>,
        new Date(sa.expires_at).toLocaleString(),
        <Status active={active} />,
      ]
      if (canWrite) cells.push(active ? <Button variant="destructive" size="sm" onClick={() => setRevoke(sa)}>Revoke</Button> : null)
      return cells
    })} />
    {add && <ServiceAccountForm base={base} path={path} onClose={() => setAdd(false)} onCreated={cred => { setSecret(cred); list.reload() }} />}
    {revoke && <ConfirmDialog title="Revoke service account?" description={`${revoke.name} will immediately lose access.`} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); list.reload() }} />}
    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">Service account created</DialogTitle>
        <DialogDescription className="text-muted-foreground">This secret is shown once. Store it securely.</DialogDescription>
        <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.secret}</code>
        <p className="text-xs text-muted-foreground">Expires {new Date(secret.expires_at).toLocaleString()}</p>
        <Button onClick={() => setSecret(null)}>I have saved the secret</Button>
      </DialogContent>
    </Dialog>}
  </div>
}

// --- Federation Connections ---
interface FederationConnection { id: string; name: string; issuer: string; client_id: string; active: boolean; linked: number }

export function FederationPage() {
  const { project, environment } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/federation-connections`
  const list = usePaginatedList<FederationConnection>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState(false)
  const [disable, setDisable] = useState<FederationConnection | null>(null)

  const detailPath = (id: string) => `/projects/${project}/environments/${environment}/federation/${id}`

  return <div className="space-y-6">
    <PageHeader title="Federation connections" description="External OIDC identity providers. Users authenticate through these connections and are linked to local identities." actions={canWrite && <Button onClick={() => setAdd(true)}><Plus className="size-4" /> Create</Button>} />
    <PaginationBar state={list} noun="connections" />
    <DataTable columns={['Name / ID', 'Issuer', 'Client ID', 'Linked', 'Status', ...(canWrite ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(c => {
      const cells: React.ReactNode[] = [
        <div className="space-y-1"><Link to={detailPath(c.id)} className="block font-medium text-primary hover:underline">{c.name}</Link><ID value={c.id} /></div>,
        <span className="text-xs break-all">{c.issuer}</span>,
        <span className="text-xs">{c.client_id}</span>,
        <span className="text-sm">{c.linked}</span>,
        <Status active={c.active} />,
      ]
      if (canWrite) cells.push(c.active ? <Button variant="destructive" size="sm" onClick={e => { e.stopPropagation(); setDisable(c) }}>Disable</Button> : null)
      return cells
    })} />
    {add && <FormDialog title="Create federation connection" description="Connect an external OIDC identity provider." fields={[
      { name: 'name', label: 'Name' },
      { name: 'issuer', label: 'Issuer URL', hint: 'Must be HTTPS, e.g. https://accounts.google.com' },
      { name: 'client_id', label: 'Client ID' },
      { name: 'secret_env', label: 'Secret env variable', hint: 'e.g. IAMKIT_PROVIDER_GOOGLE_SECRET' },
    ]} onClose={() => setAdd(false)} submit={async values => { await api.post(path, values); list.reload() }} />}
    {disable && <ConfirmDialog title="Disable connection?" description={`${disable.name} will no longer accept new logins.`} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); list.reload() }} />}
  </div>
}

// --- OAuth Clients ---
interface OAuthClient { id: string; application_id: string; application_name: string; resource_id: string; resource_name: string; redirect_uris: string[]; public: boolean; active: boolean }

export function OAuthClientsPage() {
  const { environment } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/oauth-clients`
  const list = usePaginatedList<OAuthClient>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState(false)
  const [disable, setDisable] = useState<OAuthClient | null>(null)
  const [secret, setSecret] = useState<{ id: string; client_id: string; client_secret: string } | null>(null)

  const createFields: Field[] = [
    { name: 'application_id', label: 'Application', type: 'select', selectPath: `${base}/applications`, selectMap: named },
    { name: 'resource_id', label: 'Resource', type: 'select', selectPath: `${base}/resources`, selectMap: named },
    { name: 'redirect_uris', label: 'Redirect URIs', type: 'list', hint: 'Comma-separated absolute URLs.' },
    { name: 'public', label: 'Public client (no secret)', type: 'checkbox' },
  ]

  return <div className="space-y-6">
    <PageHeader title="OAuth clients" description="OIDC/OAuth 2.0 client registrations bound to an application and resource." actions={canWrite && <Button onClick={() => setAdd(true)}><Plus className="size-4" /> Create</Button>} />
    <PaginationBar state={list} noun="clients" />
    <DataTable columns={['Client ID', 'Application', 'Resource', 'Redirect URIs', 'Type', 'Status', ...(canWrite ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(c => {
      const cells: React.ReactNode[] = [
        <ID value={c.id} />,
        <span className="text-sm">{c.application_name || <ID value={c.application_id} />}</span>,
        <span className="text-sm">{c.resource_name || <ID value={c.resource_id} />}</span>,
        <span className="text-xs break-all">{c.redirect_uris?.join(', ') || '—'}</span>,
        c.public ? 'Public' : 'Confidential',
        <Status active={c.active} />,
      ]
      if (canWrite) cells.push(c.active ? <Button variant="destructive" size="sm" onClick={() => setDisable(c)}>Disable</Button> : null)
      return cells
    })} />
    {add && <FormDialog title="Create OAuth client" description="Bind to an existing application and resource." fields={createFields} onClose={() => setAdd(false)} submit={async values => {
      const data = { ...values, redirect_uris: String(values.redirect_uris || '').split(',').map(s => s.trim()).filter(Boolean) }
      const result = await api.post<{ id: string; client_id: string; client_secret: string }>(path, data)
      setSecret(result)
      list.reload()
    }} />}
    {disable && <ConfirmDialog title="Disable OAuth client?" description={`Client ${disable.id} will immediately stop accepting requests.`} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`${path}/${disable.id}`); list.reload() }} />}
    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">OAuth client created</DialogTitle>
        <DialogDescription className="text-muted-foreground">{secret.client_secret ? 'The client secret is shown once.' : 'This is a public client — no secret was generated.'}</DialogDescription>
        <div className="space-y-2">
          <p className="text-sm">Client ID</p>
          <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.client_id}</code>
          {secret.client_secret && <>
            <p className="text-sm">Client secret (shown once)</p>
            <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.client_secret}</code>
          </>}
        </div>
        <Button onClick={() => setSecret(null)}>I have saved the credentials</Button>
      </DialogContent>
    </Dialog>}
  </div>
}

// --- Provisioning (SCIM) Credentials ---
interface ProvCredential { id: string; name: string; organization_id: string; connection_id: string; expires_at: string; revoked_at: string | null }

export function ProvisioningPage() {
  const { environment } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/provisioning-credentials`
  const list = usePaginatedList<ProvCredential>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [add, setAdd] = useState(false)
  const [revoke, setRevoke] = useState<ProvCredential | null>(null)
  const [secret, setSecret] = useState<{ id: string; secret: string; expires_at: string; connection_id: string } | null>(null)
  const [linkId, setLinkId] = useState(false)

  const createFields: Field[] = [
    { name: 'name', label: 'Name' },
    { name: 'organization_id', label: 'Organization', type: 'select', selectPath: `${base}/organizations`, selectMap: named },
    { name: 'connection_id', label: 'Connection ID', optional: true, hint: 'Leave empty to create a new connection.' },
    { name: 'expires_in', label: 'Expires in', type: 'dropdown', value: '24h', options: [
      { label: '1 hour', value: '1h' },
      { label: '24 hours', value: '24h' },
      { label: '7 days', value: '168h' },
      { label: '30 days', value: '720h' },
      { label: '90 days', value: '2160h' },
      { label: '1 year', value: '8760h' },
      { label: 'No expiry', value: 'never' },
    ] },
  ]
  const linkFields: Field[] = [
    { name: 'connection_id', label: 'Connection ID' },
    { name: 'user_id', label: 'User', type: 'select', selectPath: `${base}/users`, selectMap: named },
    { name: 'external_id', label: 'External ID' },
  ]

  return <div className="space-y-6">
    <PageHeader title="SCIM provisioning" description="SCIM 2.0 credentials for automated user provisioning from your IdP." actions={canWrite && <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setLinkId(true)}>Link identity</Button><Button onClick={() => setAdd(true)}><Plus className="size-4" /> Issue credential</Button></div>} />
    <PaginationBar state={list} noun="credentials" />
    <DataTable columns={['Name / ID', 'Organization', 'Connection', 'Expires', 'Status', ...(canWrite ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(c => {
      const active = !c.revoked_at && Date.parse(c.expires_at) > Date.now()
      const cells: React.ReactNode[] = [
        <div className="space-y-1"><p className="font-medium">{c.name}</p><ID value={c.id} /></div>,
        <ID value={c.organization_id} />,
        <ID value={c.connection_id} />,
        new Date(c.expires_at).toLocaleString(),
        <Status active={active} />,
      ]
      if (canWrite) cells.push(active ? <Button variant="destructive" size="sm" onClick={() => setRevoke(c)}>Revoke</Button> : null)
      return cells
    })} />
    {add && <FormDialog title="Issue SCIM credential" description="Create a bearer token for your IdP's SCIM integration." fields={createFields} onClose={() => setAdd(false)} submit={async values => {
      const result = await api.post<{ id: string; secret: string; expires_at: string; connection_id: string }>(path, values)
      setSecret(result)
      list.reload()
    }} />}
    {revoke && <ConfirmDialog title="Revoke SCIM credential?" description={`${revoke.name} will immediately stop provisioning.`} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); list.reload() }} />}
    {linkId && <FormDialog title="Link provisioned identity" description="Manually link an external identity to a local user within a provisioning connection." fields={linkFields} onClose={() => setLinkId(false)} submit={async values => { await api.post(`${base}/provisioned-identities`, values) }} />}
    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">SCIM credential issued</DialogTitle>
        <DialogDescription className="text-muted-foreground">This bearer token is shown once. Configure it in your IdP's SCIM settings.</DialogDescription>
        <div className="space-y-2">
          <p className="text-sm">Connection ID</p>
          <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.connection_id}</code>
          <p className="text-sm">Bearer token (shown once)</p>
          <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.secret}</code>
          <p className="text-xs text-muted-foreground">Expires {new Date(secret.expires_at).toLocaleString()}</p>
        </div>
        <Button onClick={() => setSecret(null)}>I have saved the token</Button>
      </DialogContent>
    </Dialog>}
  </div>
}
