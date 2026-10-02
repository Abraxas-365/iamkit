import { Link, useOutletContext, useParams } from 'react-router-dom'
import { useState } from 'react'
import { ArrowRight, FolderKanban, Layers, Plus } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import type { Named } from '@/components/layout/app-layout'
import { LogoMark } from '@/components/brand/logo'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { DataTable, EmptyState, EntityRef, FormDialog, ID, PageHeader } from '@/components/library/patterns'
import { t } from '@/lib/i18n'
export function OverviewPage() {
  const { principal } = useAuth()
  return <div className="space-y-6"><PageHeader title={t('Workspace overview')} description={t('One place to manage identities and control access to your applications.')} />
    <Card className="space-y-4 p-6"><div className="flex items-center gap-3"><LogoMark className="size-8" /><h2 className="font-mono text-lg font-semibold">{t('Welcome to IAMKit')}</h2></div><p className="max-w-2xl text-muted-foreground">{t('Start with a project, create an isolated environment, then configure users, applications, and permission catalogs. Operators manage the workspace; end users belong to environments.')}</p><Link className="inline-flex items-center gap-2 text-primary hover:underline" to="/projects">{t('Open projects')} <ArrowRight className="size-4" /></Link></Card>
    <div className="grid gap-4 md:grid-cols-2"><Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">{t('Workspace ID')}</h2><ID value={principal!.workspace_id} /></Card><Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">{t('Your access')}</h2><p className="capitalize">{principal!.role}</p><p className="mt-2 text-xs text-muted-foreground">{t('Authenticated with a secure operator session. Sessions expire after one hour.')}</p></Card></div>
    <Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">{t('Access model')}</h2><p className="text-muted-foreground">{t('Define scopes on resources, group permissions into roles, and assign access within an organization. Application-resource links determine which resources an application can use.')}</p></Card>
  </div>
}
export function ProjectsPage() {
  const { project } = useParams()
  const { refreshStructure } = useOutletContext<{ refreshStructure: () => void }>()
  const path = project ? `/projects/${project}/environments` : '/projects'
  const list = useList<Named>(path + '?limit=200')
  const { principal } = useAuth()
  const [creating, setCreating] = useState(false)
  const href = (id: string) => project ? `/projects/${project}/environments/${id}` : `/projects/${id}`
  return <div className="space-y-6"><PageHeader title={project ? t('Environments') : t('Projects')} description={project ? t('Isolated identity and access configuration for each stage of your product.') : t('Organize your products and their environments.')} actions={principal?.role !== 'viewer' && <Button onClick={() => setCreating(true)}><Plus />{project ? t('Create environment') : t('Create project')}</Button>} />
    <DataTable columns={[t('Name'), { header: '', align: 'right' }]} loading={list.loading} error={list.error} retry={list.reload}
      rowHref={i => href(list.data[i].id)}
      empty={<EmptyState icon={project ? <Layers /> : <FolderKanban />} title={project ? t('No environments yet') : t('No projects yet')} description={project ? t('Create an environment such as development or production to start adding users and applications.') : t('Create a project for each product you secure with IAMKit.')} action={principal?.role !== 'viewer' && <Button variant="outline" onClick={() => setCreating(true)}><Plus />{project ? t('Create environment') : t('Create project')}</Button>} />}
      rows={list.data.map(item => [<EntityRef name={item.name} id={item.id} to={href(item.id)} />, <ArrowRight className="ml-auto size-4 text-muted-foreground" aria-hidden />])} />
    {creating && <FormDialog title={project ? t('Create environment') : t('Create project')} description={project ? t('Choose a name for this environment.') : t('Choose a name for this project.')} fields={[{ name: 'name', label: t('Name') }]} onClose={() => setCreating(false)} submit={async data => { await api.post(path, data); list.reload(); refreshStructure(); }} />}
  </div>
}
