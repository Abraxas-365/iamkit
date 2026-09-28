import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Ban, KeyRound, Link2, Pencil, Plus, RotateCcw, Unlink } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { CollapsibleScopes } from '@/components/ui/collapsible-scopes'
import { RowActions } from '@/components/ui/menu'
import { Skeleton } from '@/components/ui/skeleton'
import { BackLink, ConfirmDialog, CopyText, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, FormDialog, Properties, Status, splitList } from '@/components/library/patterns'
import type { OAuthClient } from './integrations'

interface Application { id: string; name: string; redirect_uris: string[] | null; active: boolean }
interface Resource { id: string; name: string; prefix: string; audience: string; permissions: string[] }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

/** ApplicationDetailPage shows one application: its redirect URIs, the APIs
 * it may call, and the OAuth clients your code uses to sign users in to it. */
export default function ApplicationDetailPage() {
  const { project, environment, appId } = useParams()
  const base = `/environments/${environment}`
  const console = `/projects/${project}/environments/${environment}`
  const path = `${base}/applications/${appId}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [app, setApp] = useState<Application | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [toggling, setToggling] = useState(false)
  const [linking, setLinking] = useState(false)
  const [unlinking, setUnlinking] = useState<Resource | null>(null)
  const resources = usePaginatedList<Resource>(`${path}/resources`, { limit: 100 })
  const clientParams = useMemo(() => ({ application_id: appId ?? '' }), [appId])
  const clients = usePaginatedList<OAuthClient>(`${base}/oauth-clients`, { extraParams: clientParams, limit: 100 })

  const load = useCallback(() => { setError(''); api.get<Application>(path).then(setApp).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])

  const back = <BackLink to={`${console}/applications`}>All applications</BackLink>
  if (error) return <div className="space-y-4">{back}<ErrorState error={error} retry={load} /></div>
  if (!app) return <div role="status" className="space-y-4">{back}<Skeleton className="h-9 w-64" /><Skeleton className="h-40" /><span className="sr-only">Loading application…</span></div>

  const link = canWrite && <Button variant="outline" size="sm" onClick={() => setLinking(true)}><Link2 /> Link resource</Button>
  const newClient = canWrite && <Link to={`${console}/oauth-clients?create=${app.id}`} className={buttonVariants({ variant: 'outline', size: 'sm' })}><Plus className="size-4" /> Create OAuth client</Link>

  return <div className="space-y-6">
    <div className="space-y-3">
      {back}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h1 className="font-mono text-2xl font-bold tracking-tight">{app.name}</h1>
        <Status active={app.active} />
      </div>
      <CopyText value={app.id} short label="Copy application ID" />
    </div>

    <DetailSection title="Details" actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      <Properties items={[
        ['Name', app.name],
        ['Redirect URIs', app.redirect_uris?.length ? <ul className="space-y-1">{app.redirect_uris.map(u => <li key={u} className="break-all font-mono text-xs">{u}</li>)}</ul> : <span className="text-muted-foreground">None</span>],
      ]} />
    </DetailSection>

    <DetailSection title="Resources" description="APIs this application can request tokens for, and the scopes they define." actions={resources.data.length > 0 && link}>
      <DataTable
        columns={['Resource', { header: 'Audience', hideBelow: 'lg' }, { header: 'Scopes', hideBelow: 'md' }, ...(canWrite ? ['Actions'] : [])]}
        loading={resources.loading} error={resources.error} retry={resources.reload}
        empty={<EmptyState icon={<KeyRound />} title="No resources linked" description="Link the APIs this application calls so it can request tokens for them." action={link} />}
        rows={resources.data.map(r => [
          <span className="block"><span className="font-medium">{r.name}</span> <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[11px]">{r.prefix}</code></span>,
          <span className="break-all text-sm">{r.audience}</span>,
          r.permissions?.length ? <CollapsibleScopes key={r.id} scopes={r.permissions} /> : <span className="text-xs text-muted-foreground">No scopes</span>,
          ...(canWrite ? [<RowActions label={`Actions for ${r.name}`} actions={[{ label: 'Unlink resource', icon: <Unlink />, destructive: true, onSelect: () => setUnlinking(r) }]} />] : []),
        ])} />
    </DetailSection>

    <DetailSection title="OAuth clients" description="Credentials your code uses to sign users in to this application." actions={clients.data.length > 0 && newClient}>
      <DataTable
        columns={['Client', { header: 'Type', hideBelow: 'sm' }, 'Status']}
        loading={clients.loading} error={clients.error} retry={clients.reload}
        rowHref={i => `${console}/oauth-clients/${clients.data[i].id}`}
        empty={<EmptyState icon={<KeyRound />} title="No OAuth clients" description={resources.data.length ? 'Create a client to start signing users in to this application.' : 'Link a resource first, then create a client for it.'} action={resources.data.length ? newClient : undefined} />}
        rows={clients.data.map(c => [
          <EntityRef name={c.resource_name} id={c.id} to={`${console}/oauth-clients/${c.id}`} secondary={c.hosted_login ? 'Hosted sign-in page' : 'Your own sign-in UI'} />,
          <Badge variant="secondary">{c.public ? 'Public (PKCE)' : 'Confidential'}</Badge>,
          <Status active={c.active} label={c.active ? 'Active' : 'Disabled'} />,
        ])} />
    </DetailSection>

    {canWrite && <DetailSection danger title={app.active ? 'Deactivate application' : 'Reactivate application'} description={app.active ? 'Users can no longer sign in to it and its clients stop issuing tokens. Nothing is deleted.' : 'Users can sign in to it again through its active clients.'}>
      <Button variant={app.active ? 'destructive' : 'outline'} onClick={() => setToggling(true)}>{app.active ? <><Ban /> Deactivate</> : <><RotateCcw /> Reactivate</>}</Button>
    </DetailSection>}

    {editing && <FormDialog title={`Edit ${app.name}`} description="Redirect URIs must match exactly what your application sends." fields={[
      { name: 'name', label: 'Name', value: app.name },
      { name: 'redirect_uris', label: 'Redirect URIs', value: (app.redirect_uris ?? []).join(', '), hint: 'Comma-separated. HTTPS, or http://localhost for development.' },
    ]} onClose={() => setEditing(false)} submit={async values => { await api.patch(path, { name: values.name, redirect_uris: splitList(values.redirect_uris) }); load() }} />}
    {toggling && (app.active
      ? <ConfirmDialog title={`Deactivate ${app.name}?`} description="Users can no longer sign in to it, and its OAuth clients stop issuing tokens. You can reactivate it later." confirmLabel="Deactivate" onClose={() => setToggling(false)} confirm={async () => { await api.delete(path); toast.success('Application deactivated'); load() }} />
      : <ConfirmDialog title={`Reactivate ${app.name}?`} description="Users can sign in to it again through its active OAuth clients." confirmLabel="Reactivate" onClose={() => setToggling(false)} confirm={async () => { await api.patch(path, { active: true }); toast.success('Application reactivated'); load() }} />)}
    {linking && <FormDialog title={`Link a resource to ${app.name}`} description="The application can then request tokens for this API." submitLabel="Link resource" success="Resource linked" fields={[
      { name: 'resource_id', label: 'Resource', type: 'select', selectPath: `${base}/resources`, selectMap: named },
    ]} onClose={() => setLinking(false)} submit={async values => { await api.post(`${base}/application-resources`, { application_id: app.id, resource_id: values.resource_id }); resources.reload() }} />}
    {unlinking && <ConfirmDialog title={`Unlink ${unlinking.name}?`} description={`${app.name} can no longer request new tokens for ${unlinking.name}. Tokens already issued stay valid until they expire.`} confirmLabel="Unlink" onClose={() => setUnlinking(null)} confirm={async () => { await api.delete(`${base}/application-resources/${app.id}/${unlinking.id}`); toast.success('Resource unlinked'); resources.reload() }} />}
  </div>
}
