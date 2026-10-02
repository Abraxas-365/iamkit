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
import { HistorySection } from './history'
import { t } from '@/lib/i18n'

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

  const back = <BackLink to={`${console}/applications`}>{t('All applications')}</BackLink>
  if (error) return <div className="space-y-4">{back}<ErrorState error={error} retry={load} /></div>
  if (!app) return <div role="status" className="space-y-4">{back}<Skeleton className="h-9 w-64" /><Skeleton className="h-40" /><span className="sr-only">{t('Loading application…')}</span></div>

  const link = canWrite && <Button variant="outline" size="sm" onClick={() => setLinking(true)}><Link2 /> {t('Link resource')}</Button>
  const newClient = canWrite && <Link to={`${console}/oauth-clients?create=${app.id}`} className={buttonVariants({ variant: 'outline', size: 'sm' })}><Plus className="size-4" /> {t('Create OAuth client')}</Link>

  return <div className="space-y-6">
    <div className="space-y-3">
      {back}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h1 className="font-mono text-2xl font-bold tracking-tight">{app.name}</h1>
        <Status active={app.active} />
      </div>
      <CopyText value={app.id} short label={t('Copy application ID')} />
    </div>

    <DetailSection title={t('Details')} actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>}>
      <Properties items={[
        [t('Name'), app.name],
        [t('Redirect URIs'), app.redirect_uris?.length ? <ul className="space-y-1">{app.redirect_uris.map(u => <li key={u} className="break-all font-mono text-xs">{u}</li>)}</ul> : <span className="text-muted-foreground">{t('None')}</span>],
      ]} />
    </DetailSection>

    <DetailSection title={t('Resources')} description={t('APIs this application can request tokens for, and the scopes they define.')} actions={resources.data.length > 0 && link}>
      <DataTable
        columns={[t('Resource'), { header: t('Audience'), hideBelow: 'lg' }, { header: t('Scopes'), hideBelow: 'md' }, ...(canWrite ? [t('Actions')] : [])]}
        loading={resources.loading} error={resources.error} retry={resources.reload}
        empty={<EmptyState icon={<KeyRound />} title={t('No resources linked')} description={t('Link the APIs this application calls so it can request tokens for them.')} action={link} />}
        rows={resources.data.map(r => [
          <span className="block"><span className="font-medium">{r.name}</span> <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[11px]">{r.prefix}</code></span>,
          <span className="break-all text-sm">{r.audience}</span>,
          r.permissions?.length ? <CollapsibleScopes key={r.id} scopes={r.permissions} /> : <span className="text-xs text-muted-foreground">{t('No scopes')}</span>,
          ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: r.name })} actions={[{ label: t('Unlink resource'), icon: <Unlink />, destructive: true, onSelect: () => setUnlinking(r) }]} />] : []),
        ])} />
    </DetailSection>

    <DetailSection title={t('OAuth clients')} description={t('Credentials your code uses to sign users in to this application.')} actions={clients.data.length > 0 && newClient}>
      <DataTable
        columns={[t('Client'), { header: t('Type'), hideBelow: 'sm' }, t('Status')]}
        loading={clients.loading} error={clients.error} retry={clients.reload}
        rowHref={i => `${console}/oauth-clients/${clients.data[i].id}`}
        empty={<EmptyState icon={<KeyRound />} title={t('No OAuth clients')} description={resources.data.length ? t('Create a client to start signing users in to this application.') : t('Link a resource first, then create a client for it.')} action={resources.data.length ? newClient : undefined} />}
        rows={clients.data.map(c => [
          <EntityRef name={c.resource_name} id={c.id} to={`${console}/oauth-clients/${c.id}`} secondary={c.hosted_login ? t('Hosted sign-in page') : t('Your own sign-in UI')} />,
          <Badge variant="secondary">{c.public ? t('Public (PKCE)') : t('Confidential')}</Badge>,
          <Status active={c.active} label={c.active ? t('Active') : t('Disabled')} />,
        ])} />
    </DetailSection>

    <HistorySection path={path} refresh={app} />

    {canWrite && <DetailSection danger title={app.active ? t('Deactivate application') : t('Reactivate application')} description={app.active ? t('Users can no longer sign in to it and its clients stop issuing tokens. Nothing is deleted.') : t('Users can sign in to it again through its active clients.')}>
      <Button variant={app.active ? 'destructive' : 'outline'} onClick={() => setToggling(true)}>{app.active ? <><Ban /> {t('Deactivate')}</> : <><RotateCcw /> {t('Reactivate')}</>}</Button>
    </DetailSection>}

    {editing && <FormDialog title={t('Edit {{name}}', { name: app.name })} description={t('Redirect URIs must match exactly what your application sends.')} fields={[
      { name: 'name', label: t('Name'), value: app.name },
      { name: 'redirect_uris', label: t('Redirect URIs'), value: (app.redirect_uris ?? []).join(', '), hint: t('Comma-separated. HTTPS, or http://localhost for development.') },
    ]} onClose={() => setEditing(false)} submit={async values => { await api.patch(path, { name: values.name, redirect_uris: splitList(values.redirect_uris) }); load() }} />}
    {toggling && (app.active
      ? <ConfirmDialog title={t('Deactivate {{name}}?', { name: app.name })} description={t('Users can no longer sign in to it, and its OAuth clients stop issuing tokens. You can reactivate it later.')} confirmLabel={t('Deactivate')} onClose={() => setToggling(false)} confirm={async () => { await api.delete(path); toast.success(t('Application deactivated')); load() }} />
      : <ConfirmDialog title={t('Reactivate {{name}}?', { name: app.name })} description={t('Users can sign in to it again through its active OAuth clients.')} confirmLabel={t('Reactivate')} onClose={() => setToggling(false)} confirm={async () => { await api.patch(path, { active: true }); toast.success(t('Application reactivated')); load() }} />)}
    {linking && <FormDialog title={t('Link a resource to {{name}}', { name: app.name })} description={t('The application can then request tokens for this API.')} submitLabel={t('Link resource')} success={t('Resource linked')} fields={[
      { name: 'resource_id', label: t('Resource'), type: 'select', selectPath: `${base}/resources`, selectMap: named },
    ]} onClose={() => setLinking(false)} submit={async values => { await api.post(`${base}/application-resources`, { application_id: app.id, resource_id: values.resource_id }); resources.reload() }} />}
    {unlinking && <ConfirmDialog title={t('Unlink {{name}}?', { name: unlinking.name })} description={t('{{name}} can no longer request new tokens for {{name2}}. Tokens already issued stay valid until they expire.', { name: app.name, name2: unlinking.name })} confirmLabel={t('Unlink')} onClose={() => setUnlinking(null)} confirm={async () => { await api.delete(`${base}/application-resources/${app.id}/${unlinking.id}`); toast.success(t('Resource unlinked')); resources.reload() }} />}
  </div>
}
