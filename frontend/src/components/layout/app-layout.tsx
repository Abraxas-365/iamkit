import { Link, matchPath, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import { useTheme } from 'next-themes'
import { Activity, Bell, Blocks, Bot, Building2, FolderKanban, Globe, KeyRound, LayoutDashboard, Link2, LogOut, Moon, Server, Settings, Shield, ShieldCheck, Sun, Tags, UserCog, Users } from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarSeparator, SidebarTrigger, useSidebar } from '@/components/ui/sidebar'
import { ErrorState } from '@/components/library/patterns'
export interface Named { id: string; name: string }
const environmentNav = [
  ['users', 'Users', Users], ['organizations', 'Organizations', Building2], ['applications', 'Applications', Blocks],
  ['resources', 'Resources & scopes', Shield], ['roles', 'Roles', Tags], ['grants', 'Grants', ShieldCheck],
  ['service-accounts', 'Service accounts', Bot], ['federation', 'Federation', Globe], ['oauth-clients', 'OAuth clients', Link2], ['provisioning', 'SCIM provisioning', Server],
  ['notifications', 'Notifications', Bell],
  ['sessions', 'Sessions', KeyRound], ['audit-events', 'Audit events', Activity],
] as const
export default function AppLayout() {
  const auth = useAuth()
  if (auth.loading) return <p role="status" className="p-8">Loading session…</p>
  if (auth.error) return <div className="p-8"><ErrorState error={auth.error} retry={() => void auth.reload()} /></div>
  if (!auth.principal) return <Navigate to="/login" replace />
  return <SidebarProvider><Shell /></SidebarProvider>
}
function Shell() {
  const { principal, logout } = useAuth()
  const { setOpenMobile } = useSidebar()
  const location = useLocation()
  const project = matchPath('/projects/:project/*', location.pathname)?.params.project
  const environment = matchPath('/projects/:project/environments/:environment/*', location.pathname)?.params.environment
  const navigate = useNavigate()
  const projects = useList<Named>('/projects')
  const environments = useList<Named>(project ? `/projects/${project}/environments` : null)
  const { resolvedTheme, setTheme } = useTheme()
  const [signingOut, setSigningOut] = useState(false)
  const envBase = project && environment ? `/projects/${project}/environments/${environment}` : ''
  const currentPage = environmentNav.find(([path]) => location.pathname.endsWith(`/${path}`))?.[1] ?? 'Workspace'
  function link(to: string, label: string, Icon: typeof Shield) {
    const active = location.pathname === to
    return <SidebarMenuItem key={to}><SidebarMenuButton isActive={active} render={<Link to={to} aria-current={active ? 'page' : undefined} />} onClick={() => setOpenMobile(false)}><Icon /><span>{label}</span></SidebarMenuButton></SidebarMenuItem>
  }
  return <>
    <a className="sr-only focus:not-sr-only focus:fixed focus:z-50 focus:bg-background focus:p-3" href="#content">Skip to content</a>
    <Sidebar>
      <SidebarHeader>
        <Link to="/" onClick={() => setOpenMobile(false)} className="flex h-12 items-center gap-2 rounded-md p-2 focus-visible:outline-ring">
          <div className="flex h-7 w-7 items-center justify-center rounded-sm bg-primary font-mono text-xs font-bold text-primary-foreground">IK</div>
          <div className="flex flex-col"><span className="font-mono text-sm font-semibold text-foreground">IAMKit</span><span className="text-[10px] text-muted-foreground">Identity & access management</span></div>
        </Link>
      </SidebarHeader>
      <SidebarSeparator />
      <SidebarContent>
        <nav aria-label="Main navigation">
          <SidebarGroup><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">Workspace</SidebarGroupLabel><SidebarGroupContent><SidebarMenu>{link('/', 'Overview', LayoutDashboard)}{link('/projects', 'Projects', FolderKanban)}</SidebarMenu></SidebarGroupContent></SidebarGroup>
          <SidebarGroup><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">Environment</SidebarGroupLabel><SidebarGroupContent>{envBase ? <SidebarMenu>{environmentNav.map(([path, label, icon]) => link(`${envBase}/${path}`, label, icon))}</SidebarMenu> : <p className="px-2 text-xs leading-relaxed text-muted-foreground">Select a project and environment to manage identities and access.</p>}</SidebarGroupContent></SidebarGroup>
          <SidebarGroup><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">Administration</SidebarGroupLabel><SidebarGroupContent><SidebarMenu>{link('/operators', 'Operators', UserCog)}{link('/keys', 'API keys', KeyRound)}{link('/settings', 'Settings', Settings)}</SidebarMenu></SidebarGroupContent></SidebarGroup>
        </nav>
      </SidebarContent>
      <SidebarSeparator />
      <SidebarFooter>
        <div className="flex min-w-0 items-center gap-2 p-2">
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px] text-muted-foreground">{principal?.role.charAt(0).toUpperCase()}</div>
          <div className="min-w-0"><p className="text-xs capitalize text-foreground">{principal?.role} access</p><p className="truncate font-mono text-[10px] text-muted-foreground" title={principal?.operator_id}>{principal?.operator_id}</p></div>
        </div>
        <Button variant="ghost" className="justify-start" disabled={signingOut} onClick={async () => { setSigningOut(true); try { await logout() } catch (e) { toast.error(message(e)) } finally { setSigningOut(false) } }}><LogOut />{signingOut ? 'Signing out…' : 'Sign out'}</Button>
      </SidebarFooter>
    </Sidebar>
    <SidebarInset className="min-w-0">
      <header className="flex min-h-12 flex-wrap items-center gap-2 border-b px-4 py-2">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mr-2 !h-4 self-center" />
        <span className="hidden font-mono text-xs text-muted-foreground lg:inline">iamkit</span>
        <select aria-label="Project" className="h-7 min-w-0 max-w-40 rounded-md border border-input bg-background px-2 text-xs" value={project ?? ''} disabled={projects.loading || !!projects.error} onChange={e => navigate(e.target.value ? `/projects/${e.target.value}` : '/projects')}><option value="">Select project</option>{projects.data.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
        {project && <><span className="text-xs text-muted-foreground">/</span><select aria-label="Environment" className="h-7 min-w-0 max-w-40 rounded-md border border-input bg-background px-2 text-xs" value={environment ?? ''} disabled={environments.loading || !!environments.error} onChange={e => navigate(e.target.value ? `/projects/${project}/environments/${e.target.value}/users` : `/projects/${project}`)}><option value="">Select environment</option>{environments.data.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}</select></>}
        <Button className="ml-auto" size="icon-sm" variant="ghost" aria-label="Toggle color theme" onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}>{resolvedTheme === 'dark' ? <Sun /> : <Moon />}</Button>
      </header>
      <div id="content" className="min-w-0 flex-1 space-y-6 overflow-auto p-4 md:p-6">
        {(projects.error || environments.error) && <ErrorState error={projects.error || environments.error} retry={() => { projects.reload(); environments.reload() }} />}
        <p className="font-mono text-xs text-muted-foreground">Console <span className="px-2">/</span> {currentPage}</p>
        {principal?.role === 'viewer' && <p className="rounded-lg border bg-muted/50 p-3 text-sm text-muted-foreground">Read-only access. An owner or admin can modify environment configuration.</p>}
        {project && (projects.loading || environments.loading) ? <p role="status">Loading environment context…</p> :
          project && (projects.error || environments.error) ? null :
          project && (!projects.data.some(p => p.id === project) || (environment && !environments.data.some(e => e.id === environment))) ?
            <ErrorState error="This project or environment was not found. Select a valid context above." /> :
            <Outlet key={`${project ?? ''}/${environment ?? ''}/${principal?.workspace_id}`} context={{ refreshStructure: () => { projects.reload(); environments.reload() } }} />}
      </div>
    </SidebarInset>
  </>
}
