import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { SearchSelect } from '@/components/ui/search-select'
import { ConfirmDialog, DataTable, ID, PageHeader, Status } from '@/components/library/patterns'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'

interface Application { id: string; name: string; redirect_uris: string[]; active: boolean }
interface Resource { id: string; name: string; prefix: string; audience: string; permissions: string[] }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

export default function ApplicationDetailPage() {
  const { project, environment, appId } = useParams()
  const base = `/environments/${environment}`
  const appsPath = `/projects/${project}/environments/${environment}/applications`

  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [app, setApp] = useState<Application | null>(null)
  const [appLoading, setAppLoading] = useState(true)
  const [appError, setAppError] = useState('')

  const linkedResources = useList<Resource>(`${base}/applications/${appId}/resources`)

  const [linking, setLinking] = useState(false)
  const [unlinking, setUnlinking] = useState<Resource | null>(null)

  useEffect(() => {
    if (!environment || !appId) return
    setAppLoading(true)
    api.get<Application>(`${base}/applications/${appId}`)
      .then(data => { setApp(data); setAppLoading(false); setAppError('') })
      .catch(e => { setAppError(message(e)); setAppLoading(false) })
  }, [environment, appId, base])

  if (appLoading) return <div className="space-y-6">
    <Link to={appsPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to applications
    </Link>
    <p className="text-sm text-muted-foreground">Loading application…</p>
  </div>

  if (appError || !app) return <div className="space-y-6">
    <Link to={appsPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to applications
    </Link>
    <p className="text-sm text-destructive">{appError || 'Application not found'}</p>
  </div>

  return <div className="space-y-8">
    <div className="space-y-3">
      <Link to={appsPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to applications
      </Link>
      <PageHeader title={app.name} description={app.id} actions={<Status active={app.active} />} />
    </div>

    {/* Application info */}
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <InfoCard label="Redirect URIs" value={app.redirect_uris?.length ? app.redirect_uris.join('\n') : '—'} mono />
      <InfoCard label="Status" value={app.active ? 'Active' : 'Inactive'} />
    </div>

    {/* Linked resources */}
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-mono text-lg font-semibold">Linked resources</h2>
          <p className="text-sm text-muted-foreground">API resources this application can request tokens for.</p>
        </div>
        {canWrite && <Button variant="outline" onClick={() => setLinking(true)}><Plus className="size-4" /> Link resource</Button>}
      </div>

      <DataTable
        columns={['Name / ID', 'Prefix', 'Audience', 'Scopes', ...(canWrite ? ['Actions'] : [])]}
        loading={linkedResources.loading}
        error={linkedResources.error}
        retry={linkedResources.reload}
        rows={linkedResources.data.map(r => {
          const scopes = r.permissions?.length
            ? <div className="flex flex-wrap gap-1">{r.permissions.map(p => <span key={p} className="inline-block rounded-md bg-secondary px-1.5 py-0.5 font-mono text-xs">{p}</span>)}</div>
            : <span className="text-xs text-muted-foreground">No scopes</span>
          const cells: React.ReactNode[] = [
            <div className="space-y-1"><p className="font-medium">{r.name}</p><ID value={r.id} /></div>,
            <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">{r.prefix}</code>,
            <span className="text-sm">{r.audience}</span>,
            scopes,
          ]
          if (canWrite) cells.push(
            <Button variant="ghost" size="icon" aria-label={`Unlink ${r.name}`} onClick={() => setUnlinking(r)}>
              <Trash2 className="size-4" />
            </Button>,
          )
          return cells
        })}
      />
      <p className="text-xs text-muted-foreground">{linkedResources.data.length} of {linkedResources.total} linked resources</p>
    </div>

    {/* Link resource dialog */}
    {linking && <LinkResourceDialog
      base={base}
      appId={appId!}
      onClose={() => setLinking(false)}
      onLinked={() => { linkedResources.reload(); setLinking(false) }}
    />}

    {/* Unlink confirm */}
    {unlinking && (
      <ConfirmDialog
        title="Unlink resource?"
        description={`"${app.name}" will no longer be able to request tokens for "${unlinking.name}". Existing tokens are not revoked.`}
        onClose={() => setUnlinking(null)}
        confirm={async () => {
          await api.delete(`${base}/application-resources/${appId}/${unlinking.id}`)
          linkedResources.reload()
        }}
      />
    )}
  </div>
}

function InfoCard({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="rounded-lg border bg-card p-4">
    <p className="text-xs font-medium text-muted-foreground">{label}</p>
    <p className={`mt-1 text-sm ${mono ? 'whitespace-pre-wrap font-mono' : ''}`}>{value}</p>
  </div>
}

function LinkResourceDialog({ base, appId, onClose, onLinked }: { base: string; appId: string; onClose: () => void; onLinked: () => void }) {
  const [resourceId, setResourceId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">Link resource</DialogTitle>
      <DialogDescription className="text-muted-foreground">Select an API resource this application should be able to access.</DialogDescription>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault()
        if (!resourceId || busy) return
        setBusy(true); setError('')
        try {
          await api.post(`${base}/application-resources`, { application_id: appId, resource_id: resourceId })
          toast.success('Resource linked')
          onLinked()
        } catch (err) { setError(message(err)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">Resource</label>
          <SearchSelect
            name="resource_id"
            path={`${base}/resources`}
            mapItem={named}
            required
            disabled={busy}
            placeholder="Search resources…"
            onChange={setResourceId}
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy || !resourceId}>{busy ? 'Linking…' : 'Link'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
