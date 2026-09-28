import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { ConfirmDialog, DataTable, FormDialog, ID, PageHeader, Status, type Field } from '@/components/library/patterns'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { providerLabel } from './federation-connection-form'

export interface ConnectionDetail {
  id: string; organization_id: string | null; name: string; issuer: string; client_id: string
  provider?: string; options?: { tenant?: string; tenants?: string[]; domains?: string[]; team_id?: string; key_id?: string }
  secret_env: string; secret_source: 'env' | 'sealed'; active: boolean; linked: number
  jit_provisioning: boolean; jit_group_id: string | null; enforcement: 'optional' | 'enforced'
  signup?: boolean; link_email?: boolean; signup_organization_id?: string | null; signup_group_id?: string | null
  callback_url?: string; created_at: string
}
interface ExternalIdentity {
  connection_id: string; subject: string
  user_id: string; user_name: string; user_email: string
  origin: 'linked' | 'jit' | 'email' | 'signup'; created_at: string
}

const origins: Record<string, string> = { jit: 'Just-in-time', email: 'Verified email', signup: 'Sign-up', linked: 'Linked' }
const tenants: Record<string, string> = { common: 'Work, school and personal accounts', organizations: 'Work and school accounts', consumers: 'Personal accounts' }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id), inactive: item.active === false })

export default function FederationDetailPage() {
  const { project, environment, connectionId } = useParams()
  const base = `/environments/${environment}`
  const backPath = `/projects/${project}/environments/${environment}/federation`

  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [conn, setConn] = useState<ConnectionDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const identities = usePaginatedList<ExternalIdentity>(`${base}/federation-connections/${connectionId}/identities`)

  const [linking, setLinking] = useState(false)
  const [unlinking, setUnlinking] = useState<ExternalIdentity | null>(null)
  const [editing, setEditing] = useState(false)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    if (!environment || !connectionId) return
    setLoading(true)
    api.get<ConnectionDetail>(`${base}/federation-connections/${connectionId}`)
      .then(data => { setConn(data); setLoading(false); setError('') })
      .catch(e => { setError(message(e)); setLoading(false) })
  }, [environment, connectionId, base, version])

  if (loading) return <div className="space-y-6">
    <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to sign-in providers
    </Link>
    <p className="text-sm text-muted-foreground">Loading connection…</p>
  </div>

  if (error || !conn) return <div className="space-y-6">
    <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to sign-in providers
    </Link>
    <p className="text-sm text-destructive">{error || 'Connection not found'}</p>
  </div>

  return <div className="space-y-8">
    <div className="space-y-3">
      <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to sign-in providers
      </Link>
      <PageHeader title={conn.name} description={conn.id} actions={<div className="flex items-center gap-2">
        <Status active={conn.active} />
        {canWrite && conn.active && <Button variant="outline" onClick={() => setEditing(true)}><Pencil className="size-4" /> Edit</Button>}
      </div>} />
    </div>

    {/* Connection info */}
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <InfoCard label="Provider" value={providerLabel(conn.provider ?? 'oidc')} />
      <InfoCard label="Scope" value={conn.organization_id ? `Organization ${conn.organization_id}` : 'Environment-wide'} mono={!!conn.organization_id} />
      <InfoCard label="Issuer" value={conn.issuer} mono />
      <InfoCard label={conn.provider === 'apple' ? 'Services ID' : 'Client ID'} value={conn.client_id} mono />
      {conn.provider === 'microsoft' && conn.options?.tenant && <InfoCard label="Accounts" value={(tenants[conn.options.tenant] ?? `Tenant ${conn.options.tenant}`) + (conn.options.tenants?.length ? ` · only ${conn.options.tenants.length} allowed tenant${conn.options.tenants.length > 1 ? 's' : ''}` : '')} />}
      {conn.provider === 'apple' && <InfoCard label="Apple team / key" value={`${conn.options?.team_id ?? ''} / ${conn.options?.key_id ?? ''}`} mono />}
      {conn.provider === 'google' && <InfoCard label="Accounts" value={conn.options?.domains?.length ? `Google Workspace: ${conn.options.domains.join(', ')}` : 'Any Google account'} />}
      {!conn.organization_id && <>
        <InfoCard label="Sign-up" value={conn.signup ? (conn.signup_group_id ? `On, joins organization ${conn.signup_organization_id} and group ${conn.signup_group_id}` : `On, joins organization ${conn.signup_organization_id}`) : 'Off: only existing or linked users'} />
        <InfoCard label="Email linking" value={conn.link_email ? 'On: verified email signs in to the matching account' : 'Off'} />
      </>}
      {conn.callback_url && <InfoCard label="Redirect URI" value={conn.callback_url} mono />}
      <InfoCard label="Client secret" value={conn.secret_source === 'sealed' ? 'Stored encrypted' : `Env variable ${conn.secret_env}`} mono={conn.secret_source !== 'sealed'} />
      {conn.organization_id && <>
        <InfoCard label="Just-in-time provisioning" value={conn.jit_provisioning ? (conn.jit_group_id ? `On, joins group ${conn.jit_group_id}` : 'On, no default group') : 'Off'} />
        <InfoCard label="Enforcement" value={conn.enforcement === 'enforced' ? 'Enforced: password login blocked for verified domains' : 'Optional'} />
      </>}
    </div>

    {/* Linked identities */}
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-mono text-lg font-semibold">Linked identities</h2>
          <p className="text-sm text-muted-foreground">Users authenticated through this provider.</p>
        </div>
        {canWrite && <Button variant="outline" onClick={() => setLinking(true)}><Plus className="size-4" /> Link identity</Button>}
      </div>

      <PaginationBar state={identities} noun="identities" />

      <DataTable
        columns={['User', 'Subject', 'Origin', ...(canWrite ? ['Actions'] : [])]}
        loading={identities.loading}
        error={identities.error}
        retry={identities.reload}
        rows={identities.data.map(id => {
          const cells: React.ReactNode[] = [
            <div className="space-y-1">
              <p className="font-medium">{id.user_name}</p>
              <p className="text-xs text-muted-foreground">{id.user_email}</p>
              <ID value={id.user_id} />
            </div>,
            <span className="break-all font-mono text-xs">{id.subject}</span>,
            <span className="text-xs text-muted-foreground" title={id.created_at ? new Date(id.created_at).toLocaleString() : undefined}>{origins[id.origin] ?? 'Linked'}</span>,
          ]
          if (canWrite) cells.push(
            <Button variant="ghost" size="icon" aria-label={`Unlink ${id.user_name || id.user_id}`} onClick={() => setUnlinking(id)}>
              <Trash2 className="size-4" />
            </Button>,
          )
          return cells
        })}
      />
    </div>

    {/* Link identity dialog */}
    {linking && <LinkIdentityDialog
      base={base}
      connectionId={connectionId!}
      onClose={() => setLinking(false)}
      onLinked={() => { identities.reload(); setLinking(false); setConn(c => c ? { ...c, linked: c.linked + 1 } : c) }}
    />}

    {editing && <FormDialog
      title="Edit connection"
      description={conn.organization_id ? 'Leave the secret empty to keep the current one. Enforcement requires a verified domain.' : 'Leave the secret empty to keep the current one. Sign-up needs an organization for new users.'}
      fields={editFields(conn, base)}
      onClose={() => setEditing(false)}
      submit={async values => {
        await api.patch(`${base}/federation-connections/${connectionId}`, connectionPatch(conn, values))
        setVersion(v => v + 1)
      }}
    />}

    {/* Unlink confirm */}
    {unlinking && (
      <ConfirmDialog
        title={`Unlink ${unlinking.user_name || 'this user'}?`}
        description={`${unlinking.user_name || unlinking.user_id} can no longer sign in through this connection. Their user account and other sign-in methods are kept.`}
        confirmLabel="Unlink"
        onClose={() => setUnlinking(null)}
        confirm={async () => {
          await api.delete(`${base}/external-identities/${connectionId}/${unlinking.user_id}`)
          toast.success('Identity unlinked')
          identities.reload()
          setConn(c => c ? { ...c, linked: Math.max(0, c.linked - 1) } : c)
        }}
      />
    )}
  </div>
}

export function editFields(conn: ConnectionDetail, base: string): Field[] {
  const apple = conn.provider === 'apple'
  const fields: Field[] = [
    { name: 'name', label: 'Name', value: conn.name },
    { name: 'client_secret', label: apple ? 'New private key (.p8)' : conn.secret_source === 'sealed' ? 'New client secret' : 'Client secret (replaces env variable)', type: 'password', optional: true, hint: apple ? 'Paste the whole key, including the BEGIN and END lines. Stored encrypted.' : 'Stored encrypted.' },
  ]
  if (apple) fields.push({ name: 'key_id', label: 'Key ID', value: conn.options?.key_id ?? '', hint: 'Change it together with the new private key.' })
  if (conn.provider === 'microsoft' && (conn.options?.tenant === 'common' || conn.options?.tenant === 'organizations')) {
    fields.push({ name: 'tenants', label: 'Allowed tenants', type: 'tags', optional: true, tags: conn.options?.tenants ?? [], hint: 'Only these tenant IDs may sign in; empty accepts any tenant.' })
  }
  if (conn.provider === 'google') {
    fields.push({ name: 'domains', label: 'Workspace domains', type: 'tags', optional: true, tags: conn.options?.domains ?? [], hint: conn.organization_id ? "Only Google accounts of these Workspace domains can sign in. Keep the organization's domains here." : 'Only Google Workspace accounts of these domains can sign in; empty accepts any Google account.' })
  }
  if (!conn.organization_id) return [...fields,
    { name: 'link_email', label: 'Link existing accounts by verified email', type: 'checkbox', value: !!conn.link_email },
    { name: 'signup', label: 'Create accounts for new users', type: 'checkbox', value: !!conn.signup },
    { name: 'signup_organization_id', label: 'Sign-up organization', type: 'select', optional: true, value: conn.signup_organization_id ?? '', selectPath: `${base}/organizations`, selectMap: named, hint: 'Required for sign-up.' },
    ...(conn.signup_organization_id ? [{ name: 'signup_group_id', label: 'Sign-up default group', type: 'select' as const, optional: true, value: conn.signup_group_id ?? '', selectPath: `${base}/organizations/${conn.signup_organization_id}/groups`, selectMap: named, hint: 'Save a new organization first to pick one of its groups.' }] : []),
  ]
  return [...fields,
    { name: 'jit_provisioning', label: 'Just-in-time provisioning', type: 'checkbox', value: conn.jit_provisioning },
    { name: 'jit_group_id', label: 'Default group', type: 'select', optional: true, value: conn.jit_group_id ?? '', selectPath: `${base}/organizations/${conn.organization_id}/groups`, selectMap: named, hint: 'Users provisioned on first login join this operator-managed group.' },
    { name: 'enforcement', label: 'Enforcement', type: 'dropdown', value: conn.enforcement, options: [{ label: 'Optional', value: 'optional' }, { label: 'Enforced', value: 'enforced' }] },
  ]
}

// connectionPatch sends only what the form may change; an empty default
// group clears it.
export function connectionPatch(conn: ConnectionDetail, values: Record<string, string | boolean>) {
  const patch: Record<string, unknown> = {}
  if (values.name !== conn.name) patch.name = values.name
  if (values.client_secret) patch.client_secret = values.client_secret
  if (conn.provider === 'apple' && typeof values.key_id === 'string' && values.key_id !== (conn.options?.key_id ?? '')) patch.options = { ...conn.options, key_id: values.key_id }
  if (typeof values.tenants === 'string') {
    const next = values.tenants.split(',').map(t => t.trim()).filter(Boolean)
    if (next.join(',') !== (conn.options?.tenants ?? []).join(',')) patch.options = { ...conn.options, tenants: next }
  }
  if (typeof values.domains === 'string') {
    const next = values.domains.split(',').map(d => d.trim()).filter(Boolean)
    if (next.join(',') !== (conn.options?.domains ?? []).join(',')) patch.options = { ...conn.options, domains: next }
  }
  if (!conn.organization_id) {
    if (values.link_email !== undefined && values.link_email !== !!conn.link_email) patch.link_email = values.link_email
    if (values.signup !== undefined && values.signup !== !!conn.signup) patch.signup = values.signup
    const org = values.signup ? values.signup_organization_id : ''
    if (values.signup && org !== (conn.signup_organization_id ?? '')) { patch.signup_organization_id = org; patch.signup_group_id = '' }
    else if (values.signup && values.signup_group_id !== undefined && values.signup_group_id !== (conn.signup_group_id ?? '')) patch.signup_group_id = values.signup_group_id
  }
  if (conn.organization_id) {
    if (values.jit_provisioning !== conn.jit_provisioning) patch.jit_provisioning = values.jit_provisioning
    if (values.jit_group_id !== (conn.jit_group_id ?? '')) patch.jit_group_id = values.jit_group_id
    if (values.enforcement !== conn.enforcement) patch.enforcement = values.enforcement
  }
  return patch
}

function InfoCard({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="rounded-lg border bg-card p-4">
    <p className="text-xs font-medium text-muted-foreground">{label}</p>
    <p className={`mt-1 text-sm ${mono ? 'break-all font-mono' : ''}`}>{value}</p>
  </div>
}

function LinkIdentityDialog({ base, connectionId, onClose, onLinked }: { base: string; connectionId: string; onClose: () => void; onLinked: () => void }) {
  const [userId, setUserId] = useState('')
  const [subject, setSubject] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">Link external identity</DialogTitle>
      <DialogDescription className="text-muted-foreground">Link a user to this provider by their external subject identifier.</DialogDescription>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault()
        if (!userId || !subject.trim() || busy) return
        setBusy(true); setError('')
        try {
          await api.post(`${base}/external-identities`, { connection_id: connectionId, user_id: userId, subject: subject.trim() })
          toast.success('Identity linked')
          onLinked()
        } catch (err) { setError(message(err)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">User</label>
          <SearchSelect
            name="user_id"
            path={`${base}/users`}
            mapItem={named}
            required
            disabled={busy}
            placeholder="Search users…"
            onChange={setUserId}
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">External subject</label>
          <Input
            value={subject}
            onChange={e => setSubject(e.target.value)}
            required
            disabled={busy}
            placeholder="e.g. 110248495921238986420"
          />
          <p className="text-xs text-muted-foreground">The unique identifier from the identity provider (OIDC sub claim).</p>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy || !userId || !subject.trim()}>{busy ? 'Linking…' : 'Link'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
