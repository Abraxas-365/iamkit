import { Link, useOutletContext, useParams } from 'react-router-dom'
import { useState } from 'react'
import { ArrowRight, FolderKanban, Layers, Plus } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import type { Named } from '@/components/layout/app-layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { DataTable, EmptyState, EntityRef, FormDialog, ID, PageHeader } from '@/components/library/patterns'
export function OverviewPage() {
  const { principal } = useAuth()
  return <div className="space-y-6"><PageHeader title="Workspace overview" description="One place to manage identities and control access to your applications." />
    <Card className="space-y-4 p-6"><div className="flex items-center gap-3"><ShieldMark /><h2 className="font-mono text-lg font-semibold">Welcome to IAMKit</h2></div><p className="max-w-2xl text-muted-foreground">Start with a project, create an isolated environment, then configure users, applications, and permission catalogs. Operators manage the workspace; end users belong to environments.</p><Link className="inline-flex items-center gap-2 text-primary hover:underline" to="/projects">Open projects <ArrowRight className="size-4" /></Link></Card>
    <div className="grid gap-4 md:grid-cols-2"><Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">Workspace ID</h2><ID value={principal!.workspace_id} /></Card><Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">Your access</h2><p className="capitalize">{principal!.role}</p><p className="mt-2 text-xs text-muted-foreground">Authenticated with a secure operator session. Sessions expire after one hour.</p></Card></div>
    <Card className="gap-0 space-y-2 p-4"><h2 className="mb-2 font-mono font-medium">Access model</h2><p className="text-muted-foreground">Define scopes on resources, group permissions into roles, and assign access within an organization. Application-resource links determine which resources an application can use.</p></Card>
  </div>
}
function ShieldMark() { return <FolderKanban className="size-6 text-primary" /> }
export function ProjectsPage() {
  const { project } = useParams()
  const { refreshStructure } = useOutletContext<{ refreshStructure: () => void }>()
  const path = project ? `/projects/${project}/environments` : '/projects'
  const list = useList<Named>(path + '?limit=200')
  const { principal } = useAuth()
  const [creating, setCreating] = useState(false)
  const singular = project ? 'environment' : 'project'
  const href = (id: string) => project ? `/projects/${project}/environments/${id}` : `/projects/${id}`
  return <div className="space-y-6"><PageHeader title={project ? 'Environments' : 'Projects'} description={project ? 'Isolated identity and access configuration for each stage of your product.' : 'Organize your products and their environments.'} actions={principal?.role !== 'viewer' && <Button onClick={() => setCreating(true)}><Plus />Create {singular}</Button>} />
    <DataTable columns={['Name', { header: '', align: 'right' }]} loading={list.loading} error={list.error} retry={list.reload}
      rowHref={i => href(list.data[i].id)}
      empty={<EmptyState icon={project ? <Layers /> : <FolderKanban />} title={`No ${singular}s yet`} description={project ? 'Create an environment such as development or production to start adding users and applications.' : 'Create a project for each product you secure with IAMKit.'} action={principal?.role !== 'viewer' && <Button variant="outline" onClick={() => setCreating(true)}><Plus />Create {singular}</Button>} />}
      rows={list.data.map(item => [<EntityRef name={item.name} id={item.id} to={href(item.id)} />, <ArrowRight className="ml-auto size-4 text-muted-foreground" aria-hidden />])} />
    {creating && <FormDialog title={`Create ${singular}`} description={`Choose a name for this ${singular}.`} fields={[{ name: 'name', label: 'Name' }]} onClose={() => setCreating(false)} submit={async data => { await api.post(path, data); list.reload(); refreshStructure(); }} />}
  </div>
}
