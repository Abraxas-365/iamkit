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

interface ConnectionDetail {
  id: string; organization_id: string | null; name: string; issuer: string; client_id: string
  secret_env: string; secret_source: 'env' | 'sealed'; active: boolean; linked: number
  jit_provisioning: boolean; jit_group_id: string | null; enforcement: 'optional' | 'enforced'
  created_at: string
}
interface ExternalIdentity {
  connection_id: string; subject: string
  user_id: string; user_name: string; user_email: string
  origin: 'linked' | 'jit'; created_at: string
}

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
      <ArrowLeft className="size-3.5" />Back to federation
    </Link>
    <p className="text-sm text-muted-foreground">Loading connection…</p>
  </div>

  if (error || !conn) return <div className="space-y-6">
    <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to federation
    </Link>
    <p className="text-sm text-destructive">{error || 'Connection not found'}</p>
  </div>

  return <div className="space-y-8">
    <div className="space-y-3">
      <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to federation
      </Link>
      <PageHeader title={conn.name} description={conn.id} actions={<div className="flex items-center gap-2">
        <Status active={conn.active} />
        {canWrite && conn.active && <Button variant="outline" onClick={() => setEditing(true)}><Pencil className="size-4" /> Edit</Button>}
      </div>} />
    </div>

    {/* Connection info */}
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <InfoCard label="Scope" value={conn.organization_id ? `Organization ${conn.organization_id}` : 'Environment-wide'} mono={!!conn.organization_id} />
      <InfoCard label="Issuer" value={conn.issuer} mono />
      <InfoCard label="Client ID" value={conn.client_id} mono />
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
            <span className="text-xs text-muted-foreground" title={id.created_at ? new Date(id.created_at).toLocaleString() : undefined}>{id.origin === 'jit' ? 'Just-in-time' : 'Linked'}</span>,
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
      description="Leave the secret empty to keep the current one. Enforcement requires a verified domain."
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
        title="Unlink identity?"
        description={`Remove the external identity link for ${unlinking.user_name || unlinking.user_id}. They will no longer be able to sign in through this provider.`}
        onClose={() => setUnlinking(null)}
        confirm={async () => {
          await api.delete(`${base}/external-identities/${connectionId}/${unlinking.user_id}`)
          identities.reload()
          setConn(c => c ? { ...c, linked: Math.max(0, c.linked - 1) } : c)
        }}
      />
    )}
  </div>
}

export function editFields(conn: ConnectionDetail, base: string): Field[] {
  const fields: Field[] = [
    { name: 'name', label: 'Name', value: conn.name },
    { name: 'client_secret', label: conn.secret_source === 'sealed' ? 'New client secret' : 'Client secret (replaces env variable)', type: 'password', optional: true, hint: 'Stored encrypted.' },
  ]
  if (!conn.organization_id) return fields
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
