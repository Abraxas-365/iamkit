import { Link, matchPath, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useMemo, useState } from 'react'
import { useTheme } from 'next-themes'
import { Activity, AppWindow, Bell, Blocks, Bot, Building2, ChevronRight, FileKey, FolderKanban, Home, Globe, KeyRound, LayoutDashboard, Link2, ListChecks, Lock, LogIn, LogOut, Moon, Radio, Server, Settings, Shield, ShieldCheck, Sun, Tags, UserCog, Users } from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarSeparator, SidebarTrigger, useSidebar } from '@/components/ui/sidebar'
import { ErrorState } from '@/components/library/patterns'
import { CommandPalette, type PaletteItem } from './command-palette'
import { LogoMark } from '@/components/brand/logo'
export interface Named { id: string; name: string }
type NavItem = readonly [path: string, label: string, icon: typeof Shield]
const environmentNav: readonly (readonly [group: string, items: readonly NavItem[]])[] = [
  ['Users & access', [['users', 'Users', Users], ['organizations', 'Organizations', Building2], ['roles', 'Roles', Tags], ['grants', 'Grants', ShieldCheck]]],
  ['Applications', [['applications', 'Applications', Blocks], ['resources', 'Resources & scopes', Shield], ['oauth-clients', 'OAuth clients', Link2], ['saml-apps', 'SAML applications', AppWindow], ['service-accounts', 'Service accounts', Bot], ['signing-keys', 'Signing keys', FileKey]]],
  ['Sign-in', [['hosted-login', 'Hosted login', LogIn], ['sign-in-policy', 'Sign-in methods', ListChecks], ['password-policy', 'Password policy', Lock], ['federation', 'Sign-in providers', Globe], ['provisioning', 'SCIM provisioning', Server], ['notifications', 'Notifications', Bell]]],
  ['Monitoring', [['sessions', 'Sessions', KeyRound], ['audit-events', 'Audit events', Activity], ['logout-deliveries', 'Logout deliveries', Radio]]],
]
const allNav = environmentNav.flatMap(([, items]) => items)
const subpages: Record<string, [string, string]> = { 'role-assignments': ['roles', 'Assignments'] }
const workspacePages: [string, string][] = [['/projects', 'Projects'], ['/operators', 'Operators'], ['/keys', 'API keys'], ['/settings', 'Settings']]
function workspacePage(path: string) { return workspacePages.find(([p]) => path === p || path.startsWith(`${p}/`))?.[1] ?? 'Overview' }
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
  const projects = useList<Named>('/projects?limit=200')
  const environments = useList<Named>(project ? `/projects/${project}/environments?limit=200` : null)
  const { resolvedTheme, setTheme } = useTheme()
  const [signingOut, setSigningOut] = useState(false)
  const envBase = project && environment ? `/projects/${project}/environments/${environment}` : ''
  const section = envBase ? allNav.find(([path]) => location.pathname === `${envBase}/${path}` || location.pathname.startsWith(`${envBase}/${path}/`)) : undefined
  const envName = environments.data.find(e => e.id === environment)?.name
  const palettePages = useMemo<PaletteItem[]>(() => [
    ...(envBase ? [{ to: envBase, label: 'Environment home', group: 'Pages' }, ...environmentNav.flatMap(([group, items]) => items.map(([path, label]) => ({ to: `${envBase}/${path}`, label, group: 'Pages', hint: group }))), { to: `${envBase}/role-assignments`, label: 'Role assignments', group: 'Pages', hint: 'Users & access' }] : []),
    { to: '/', label: 'Workspace overview', group: 'Pages', hint: 'Workspace' },
    ...workspacePages.map(([to, label]) => ({ to, label, group: 'Pages', hint: 'Workspace' })),
    ...projects.data.map(p => ({ to: `/projects/${p.id}`, label: p.name, group: 'Projects' })),
    ...(project ? environments.data.map(e => ({ to: `/projects/${project}/environments/${e.id}`, label: e.name, group: 'Environments' })) : []),
  ], [envBase, project, projects.data, environments.data])
  // Pages reached from a section rather than the sidebar: path → [parent path, label].
  const subpage = envBase ? Object.entries(subpages).find(([path]) => location.pathname === `${envBase}/${path}`)?.[1] : undefined
  const parent = subpage && allNav.find(([path]) => path === subpage[0])
  const crumbs: [string, string | null][] = subpage && parent
    ? [[envName ?? 'Environment', envBase], [parent[1], `${envBase}/${parent[0]}`], [subpage[1], null]]
    : envBase
    ? [[envName ?? 'Environment', section || location.pathname !== envBase ? envBase : null], ...(section ? [[section[1], location.pathname === `${envBase}/${section[0]}` ? null : `${envBase}/${section[0]}`] as [string, string | null]] : []), ...(section && location.pathname !== `${envBase}/${section[0]}` ? [['Details', null] as [string, string | null]] : [])]
    : [[workspacePage(location.pathname), null]]
  function link(to: string, label: string, Icon: typeof Shield) {
    const active = location.pathname.replace(/(.)\/$/, '$1') === to || (!!envBase && to !== envBase && to.startsWith(envBase) && location.pathname.startsWith(`${to}/`))
    return <SidebarMenuItem key={to}><SidebarMenuButton isActive={active} render={<Link to={to} aria-current={active ? 'page' : undefined} />} onClick={() => setOpenMobile(false)}><Icon /><span>{label}</span></SidebarMenuButton></SidebarMenuItem>
  }
  return <>
    <a className="sr-only focus:not-sr-only focus:fixed focus:z-50 focus:bg-background focus:p-3" href="#content">Skip to content</a>
    <Sidebar>
      <SidebarHeader>
        <Link to="/" onClick={() => setOpenMobile(false)} className="flex h-12 items-center gap-2 rounded-md p-2 focus-visible:outline-ring">
          <LogoMark className="size-7" />
          <div className="flex flex-col"><span className="font-mono text-sm font-semibold text-foreground">IAMKit</span><span className="text-[10px] text-muted-foreground">Identity & access management</span></div>
        </Link>
      </SidebarHeader>
      <SidebarSeparator />
      <SidebarContent>
        <nav aria-label="Main navigation">
          <SidebarGroup><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">Workspace</SidebarGroupLabel><SidebarGroupContent><SidebarMenu>{link('/', 'Overview', LayoutDashboard)}{link('/projects', 'Projects', FolderKanban)}</SidebarMenu></SidebarGroupContent></SidebarGroup>
          {envBase ? <>
            <SidebarGroup><SidebarGroupContent><SidebarMenu>{link(envBase, 'Environment home', Home)}</SidebarMenu></SidebarGroupContent></SidebarGroup>
            {environmentNav.map(([group, items]) => <SidebarGroup key={group}><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">{group}</SidebarGroupLabel><SidebarGroupContent><SidebarMenu>{items.map(([path, label, icon]) => link(`${envBase}/${path}`, label, icon))}</SidebarMenu></SidebarGroupContent></SidebarGroup>)}
          </> : <SidebarGroup><SidebarGroupLabel className="font-mono text-[10px] uppercase tracking-wider">Environment</SidebarGroupLabel><SidebarGroupContent><p className="px-2 text-xs leading-relaxed text-muted-foreground">Select a project and environment to manage identities and access.</p></SidebarGroupContent></SidebarGroup>}
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
        {project && <><span className="text-xs text-muted-foreground">/</span><select aria-label="Environment" className="h-7 min-w-0 max-w-40 rounded-md border border-input bg-background px-2 text-xs" value={environment ?? ''} disabled={environments.loading || !!environments.error} onChange={e => navigate(e.target.value ? `/projects/${project}/environments/${e.target.value}` : `/projects/${project}`)}><option value="">Select environment</option>{environments.data.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}</select></>}
        <div className="ml-auto" />
        <CommandPalette pages={palettePages} envBase={envBase} environment={envBase ? environment : undefined} />
        <Button size="icon-sm" variant="ghost" aria-label="Toggle color theme" onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}>{resolvedTheme === 'dark' ? <Sun /> : <Moon />}</Button>
      </header>
      <div id="content" className="min-w-0 flex-1 space-y-6 overflow-auto p-4 md:p-6">
        {(projects.error || environments.error) && <ErrorState error={projects.error || environments.error} retry={() => { projects.reload(); environments.reload() }} />}
        <nav aria-label="Breadcrumb"><ol className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          {crumbs.map(([label, to], i) => <li key={i} className="flex items-center gap-1.5">{i > 0 && <ChevronRight className="size-3" aria-hidden />}{to ? <Link to={to} className="hover:text-foreground hover:underline">{label}</Link> : <span aria-current={i === crumbs.length - 1 ? 'page' : undefined} className={i === crumbs.length - 1 ? 'text-foreground' : undefined}>{label}</span>}</li>)}
        </ol></nav>
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
