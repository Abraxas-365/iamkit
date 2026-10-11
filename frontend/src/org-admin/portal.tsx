import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Activity, Building2, ScrollText, Waypoints, CheckCircle2, Globe, KeyRound, KeySquare, Link2, Lock, LogOut, Mail, Palette, Server, Share2, Tags, UserCog, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ErrorState } from '@/components/library/patterns'
import { LogoMark } from '@/components/brand/logo'
import { Toaster } from '@/components/ui/sonner'
import { cn, message } from '@/lib/utils'
import { Client, clearSetup, complete, decode, discover, exchangeSetup, readSetup, readTokens, signIn, signOut, userInfo, type Portal, type Setup } from './session'
import { AdminContext, ORG_PERMISSIONS, OWNER, useAdmin, type Admin } from './context'
import { APIKeysPage, API_KEYS_READ } from './api-keys'
import { AuditLogsPage, LogStreamsPage, AUDIT_READ, STREAMS_WRITE } from './audit'
import { ActivityPage, BrandingPage, ConnectionsPage, DirectoryPage, DomainsPage, InvitationsPage, MembersPage, OverviewPage, PasswordPage, ResourcesPage, RolesPage, SetupLinksPage, UsersPage } from './pages'
import { t } from '@/lib/i18n'

/** A page shows with any of its permissions. */
type NavItem = [path: string, label: string, icon: typeof Users, permission: string | string[]]
const allowed = (can: (p: string) => boolean, permission: string | string[]) => [permission].flat().some(can)
const nav: NavItem[] = [
  ['', t('Overview'), Building2, 'iam:org:read'],
  ['members', t('Members'), Users, 'iam:org:members:read'],
  ['users', t('Users'), UserCog, 'iam:org:members:read'],
  ['invitations', t('Invitations'), Mail, 'iam:org:members:read'],
  ['roles', t('Roles'), Tags, 'iam:org:roles:read'],
  ['domains', t('Domains'), Globe, 'iam:org:read'],
  ['sso', t('Single sign-on'), KeyRound, 'iam:org:read'],
  ['directory', t('Directory (SCIM)'), Server, 'iam:org:read'],
  ['resources', t('Resources'), Share2, 'iam:org:resources:read'],
  ['branding', t('Branding'), Palette, 'iam:org:read'],
  ['password-policy', t('Password policy'), Lock, 'iam:org:read'],
  ['api-keys', t('API keys'), KeySquare, API_KEYS_READ],
  ['setup-links', t('Setup links'), Link2, OWNER],
  ['activity', t('Activity'), Activity, 'iam:org:audit:read'],
  ['audit-logs', t('Audit logs'), ScrollText, AUDIT_READ],
  ['log-streams', t('Log streams'), Waypoints, [AUDIT_READ, STREAMS_WRITE]],
]

/** OrgAdminPortal is the hosted organization admin portal: served by
 * IAMKit at /org-admin/:environment, signed in through the hosted login
 * with the environment's portal client. It never shares the operator
 * console's session. */
export default function OrgAdminPortal() {
  return <>
    <Routes>
      <Route path=":environment/callback" element={<Callback />} />
      <Route path=":environment/setup" element={<SetupLink />} />
      <Route path=":environment/*" element={<Environment />} />
      <Route path="*" element={<Centered><ErrorState error={t('Open the portal link your administrator gave you: it names the environment.')} /></Centered>} />
    </Routes>
    <Toaster />
  </>
}

function Centered({ children }: { children: ReactNode }) {
  return <main className="flex min-h-svh items-center justify-center bg-background p-6"><div className="w-full max-w-md space-y-4">{children}</div></main>
}

function usePortal(environment: string) {
  const [state, setState] = useState<{ portal?: Portal; error?: string }>({})
  useEffect(() => {
    const ctrl = new AbortController()
    discover(environment, ctrl.signal).then(portal => setState({ portal })).catch(e => { if (!ctrl.signal.aborted) setState({ error: message(e) }) })
    return () => ctrl.abort()
  }, [environment])
  return state
}

function Callback() {
  const { environment = '' } = useParams()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const [error, setError] = useState('')
  useEffect(() => {
    let live = true
    complete(environment, params)
      .then(back => { if (live) navigate(back && back.startsWith(`/org-admin/${environment}`) ? back : `/org-admin/${environment}`, { replace: true }) })
      .catch(e => { if (live) setError(message(e)) })
    return () => { live = false }
    // The code is single use: run once per callback URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  if (error) return <Centered><ErrorState error={error} /><Button className="w-full" onClick={() => navigate(`/org-admin/${environment}`, { replace: true })}>{t('Back to sign-in')}</Button></Centered>
  return <Centered><p role="status" className="text-center text-sm text-muted-foreground">{t('Signing you in…')}</p></Centered>
}

function Environment() {
  const { environment = '' } = useParams()
  const { portal, error } = usePortal(environment)
  const [version, setVersion] = useState(0)
  const tokens = useMemo(() => readTokens(environment), [environment, version])
  if (error) return <Centered><ErrorState error={error} /></Centered>
  if (!portal) return <Centered><p role="status" className="text-center text-sm text-muted-foreground">{t('Loading…')}</p></Centered>
  if (!tokens) return <SignIn environment={environment} portal={portal} />
  return <Signed environment={environment} portal={portal} access={tokens.access_token} idToken={tokens.id_token} expired={() => setVersion(v => v + 1)} />
}

function SignIn({ environment, portal }: { environment: string; portal: Portal }) {
  const [params] = useSearchParams()
  const location = useLocation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const organization = params.get('organization_id') ?? undefined
  const back = location.pathname === `/org-admin/${environment}` ? '' : location.pathname
  return <Centered>
    <div className="space-y-6 rounded-xl border bg-card p-8 text-center shadow-sm">
      <LogoMark className="mx-auto size-10" />
      <div className="space-y-1.5">
        <h1 className="text-lg font-semibold">{t('Organization administration')}</h1>
        <p className="text-sm text-muted-foreground">{t('Manage your organization\'s members, roles, invitations and single sign-on.')}</p>
      </div>
      {error && <ErrorState error={error} />}
      <Button className="w-full" disabled={busy} onClick={async () => {
        setBusy(true); setError('')
        try { await signIn(environment, portal, { organization, back }) } catch (e) { setError(message(e)); setBusy(false) }
      }}>{busy ? t('Redirecting…') : t('Sign in')}</Button>
    </div>
  </Centered>
}

function Signed({ environment, portal, access, idToken, expired }: { environment: string; portal: Portal; access: string; idToken?: string; expired: () => void }) {
  const claims = useMemo(() => ({ ...decode(idToken), ...decode(access) }), [access, idToken])
  const organization = claims.organization_id ?? ''
  const client = useMemo(() => new Client(environment, portal, organization, expired), [environment, portal, organization, expired])
  const permissions = useMemo(() => new Set(claims.permissions ?? []), [claims])
  const can = useCallback((p: string) => p === OWNER ? ORG_PERMISSIONS.every(x => permissions.has(x)) : permissions.has(p), [permissions])
  const admin = useMemo<Admin>(() => ({ environment, portal, client, claims, can }), [environment, portal, client, claims, can])
  if (!organization || ![...permissions].some(p => p.startsWith('iam:org:'))) return <Centered>
    <ErrorState error={t('Your account does not administer this organization. Ask one of its owners for an administrator role, or sign in with another account.')} />
    <Button variant="outline" className="w-full" onClick={() => signOut(environment, portal)}><LogOut /> {t('Sign out')}</Button>
  </Centered>
  return <AdminContext.Provider value={admin}><Shell /></AdminContext.Provider>
}

function Shell() {
  const { environment, portal, client, claims, can } = useAdmin()
  const [name, setName] = useState('')
  useEffect(() => {
    if (!can('iam:org:read')) return
    const ctrl = new AbortController()
    client.get<{ name: string }>('', ctrl.signal).then(o => setName(o.name)).catch(() => {})
    return () => ctrl.abort()
  }, [client, can])
  const [who, setWho] = useState(claims.email || claims.name || '')
  useEffect(() => {
    const ctrl = new AbortController()
    userInfo(environment, ctrl.signal).then(u => { if (u?.email || u?.name) setWho(u.email || u.name || '') })
    return () => ctrl.abort()
  }, [environment])
  const base = `/org-admin/${environment}`
  const items = nav.filter(([, , , permission]) => allowed(can, permission))
  const home = items[0] ? `${base}/${items[0][0]}` : base
  return <div className="flex min-h-svh flex-col bg-background md:flex-row">
    <aside className="border-b bg-sidebar md:w-60 md:shrink-0 md:border-r md:border-b-0">
      <div className="flex items-center gap-2 px-4 py-4">
        <LogoMark className="size-6" />
        <div className="min-w-0"><p className="truncate text-sm font-semibold">{name || t('Your organization')}</p><p className="text-xs text-muted-foreground">{t('Administration')}</p></div>
      </div>
      <nav aria-label={t('Organization administration')} className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:overflow-visible">
        {items.map(([path, label, Icon]) => <NavLink key={path} to={path ? `${base}/${path}` : base} end={!path}
          className={({ isActive }) => cn('flex shrink-0 items-center gap-2 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground', isActive && 'bg-muted font-medium text-foreground')}>
          <Icon className="size-4" />{label}
        </NavLink>)}
      </nav>
    </aside>
    <div className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-center justify-end gap-3 border-b px-6 py-3">
        <span className="truncate text-sm text-muted-foreground">{who}</span>
        <Button variant="outline" size="sm" onClick={() => signOut(environment, portal)}><LogOut /> {t('Sign out')}</Button>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 space-y-6 p-6">
        <Routes>
          <Route index element={can('iam:org:read') ? <OverviewPage /> : <Navigate to={home} replace />} />
          <Route path="members" element={<Guard permission="iam:org:members:read"><MembersPage /></Guard>} />
          <Route path="users" element={<Guard permission="iam:org:members:read"><UsersPage /></Guard>} />
          <Route path="invitations" element={<Guard permission="iam:org:members:read"><InvitationsPage /></Guard>} />
          <Route path="roles" element={<Guard permission="iam:org:roles:read"><RolesPage /></Guard>} />
          <Route path="domains" element={<Guard permission="iam:org:read"><DomainsPage /></Guard>} />
          <Route path="sso" element={<Guard permission="iam:org:read"><ConnectionsPage /></Guard>} />
          <Route path="directory" element={<Guard permission="iam:org:read"><DirectoryPage /></Guard>} />
          <Route path="resources" element={<Guard permission="iam:org:resources:read"><ResourcesPage /></Guard>} />
          <Route path="branding" element={<Guard permission="iam:org:read"><BrandingPage /></Guard>} />
          <Route path="password-policy" element={<Guard permission="iam:org:read"><PasswordPage /></Guard>} />
          <Route path="setup-links" element={<Guard permission={OWNER}><SetupLinksPage /></Guard>} />
          <Route path="activity" element={<Guard permission="iam:org:audit:read"><ActivityPage /></Guard>} />
          <Route path="api-keys" element={<Guard permission={API_KEYS_READ}><APIKeysPage /></Guard>} />
          <Route path="audit-logs" element={<Guard permission={AUDIT_READ}><AuditLogsPage /></Guard>} />
          <Route path="log-streams" element={<Guard permission={[AUDIT_READ, STREAMS_WRITE]}><LogStreamsPage /></Guard>} />
          <Route path="*" element={<Navigate to={home} replace />} />
        </Routes>
      </main>
    </div>
  </div>
}

function Guard({ permission, children }: { permission: string | string[]; children: ReactNode }) {
  const { can, environment } = useAdmin()
  if (!allowed(can, permission)) return <div className="space-y-3"><ErrorState error={t('You do not have access to this page.')} /><Link className="text-sm underline" to={`/org-admin/${environment}`}>{t('Back')}</Link></div>
  return <>{children}</>
}

// Setup links ----------------------------------------------------------

const inflight = new Map<string, Promise<Setup>>()

// What each intent lets the bearer do (mirrors orgadmin.IntentPermissions;
// the server checks again).
const intentPermissions: Record<string, string[]> = {
  sso: ['iam:org:read', 'iam:org:sso:write'],
  directory: ['iam:org:read', 'iam:org:sso:write'],
  domains: ['iam:org:read', 'iam:org:domains:write'],
  log_streams: ['iam:org:read', 'iam:org:log-streams:write'],
}

interface Step { intent: string; title: string; description: string; icon: typeof Users; page: () => ReactNode }
// Domains first: SSO routes employees by verified domain.
const steps: Step[] = [
  { intent: 'domains', title: t('Domains'), description: t('Add your company\'s email domains and verify them with a DNS record.'), icon: Globe, page: () => <DomainsPage /> },
  { intent: 'sso', title: t('Single sign-on'), description: t('Connect your identity provider so employees sign in with their work account.'), icon: KeyRound, page: () => <ConnectionsPage /> },
  { intent: 'directory', title: t('Directory (SCIM)'), description: t('Create a SCIM credential so your directory provisions users and groups.'), icon: Server, page: () => <DirectoryPage /> },
  { intent: 'log_streams', title: t('Log streams'), description: t('Send your organization\'s audit log events to your SIEM or storage.'), icon: Waypoints, page: () => <LogStreamsPage /> },
]

/** SetupLink is the setup-link portal: the link's secret travels in the URL
 * fragment, is removed from the address bar at once, and is exchanged for a
 * bearer limited to the link's intents. */
function SetupLink() {
  const { environment = '' } = useParams()
  const [state, setState] = useState<{ setup?: Setup; error?: string }>({})
  useEffect(() => {
    let live = true
    const secret = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : ''
    if (secret) {
      // Never leave the secret in the address bar or the history entry.
      window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
      inflight.set(environment, exchangeSetup(environment, secret).finally(() => inflight.delete(environment)))
    }
    const pending = inflight.get(environment)
    const current = readSetup(environment)
    const opened = pending ?? (current ? Promise.resolve(current) : null)
    if (!opened) { setState({ error: t('Open the setup link you were given: it has the address of the setup page.') }); return }
    opened.then(setup => { if (live) setState({ setup }) }).catch(e => { inflight.delete(environment); clearSetup(environment); if (live) setState({ error: message(e) }) })
    return () => { live = false }
  }, [environment])
  if (state.error) return <Centered>
    <div className="space-y-4 rounded-xl border bg-card p-8 text-center shadow-sm">
      <LogoMark className="mx-auto size-10" />
      <h1 className="text-lg font-semibold">{t('This setup link cannot be used')}</h1>
      <ErrorState error={state.error} />
      <p className="text-sm text-muted-foreground">{t('Ask the person who sent it to create a new setup link.')}</p>
    </div>
  </Centered>
  if (!state.setup) return <Centered><p role="status" className="text-center text-sm text-muted-foreground">{t('Opening your setup link…')}</p></Centered>
  return <SetupPortal environment={environment} setup={state.setup} expired={() => { inflight.delete(environment); clearSetup(environment); setState({ error: t('This setup link is invalid, has expired or was revoked.') }) }} close={() => { inflight.delete(environment); clearSetup(environment); setState({ error: t('The setup session is closed.') }) }} />
}

function SetupPortal({ environment, setup, expired, close }: { environment: string; setup: Setup; expired: () => void; close: () => void }) {
  const portal = useMemo<Portal>(() => ({ client_id: '', environment_id: environment, url: `/org-admin/${environment}` }), [environment])
  const client = useMemo(() => new Client(environment, portal, setup.organization_id, expired, true), [environment, portal, setup.organization_id, expired])
  const permissions = useMemo(() => new Set(setup.intents.flatMap(i => intentPermissions[i] ?? [])), [setup.intents])
  const can = useCallback((p: string) => p !== OWNER && permissions.has(p), [permissions])
  const claims = useMemo(() => ({ organization_id: setup.organization_id, permissions: [...permissions] }), [setup.organization_id, permissions])
  const admin = useMemo<Admin>(() => ({ environment, portal, client, claims, can, setup: { intents: setup.intents, organization_name: setup.organization_name } }), [environment, portal, client, claims, can, setup])
  const available = steps.filter(s => setup.intents.includes(s.intent))
  const [index, setIndex] = useState(0)
  const [finished, setFinished] = useState(false)
  const step = available[index]
  if (finished || !step) return <Centered>
    <div className="space-y-4 rounded-xl border bg-card p-8 text-center shadow-sm">
      <CheckCircle2 className="mx-auto size-10 text-success" />
      <h1 className="text-lg font-semibold">{t('All done')}</h1>
      <p className="text-sm text-muted-foreground">{t('{{name}} is set up. You can close this page; ask for a new setup link if you need to change something later.', { name: setup.organization_name || t('Your organization') })}</p>
      <div className="flex justify-center gap-2">
        <Button variant="outline" onClick={() => { setFinished(false); setIndex(0) }}>{t('Review')}</Button>
        <Button onClick={close}>{t('Close setup')}</Button>
      </div>
    </div>
  </Centered>
  const last = index === available.length - 1
  return <AdminContext.Provider value={admin}>
    <div className="min-h-svh bg-background">
      <header className="border-b px-6 py-4">
        <div className="mx-auto flex max-w-4xl items-center gap-3">
          <LogoMark className="size-6" />
          <div className="min-w-0"><p className="truncate text-sm font-semibold">{setup.organization_name || t('Your organization')}</p><p className="text-xs text-muted-foreground">{t('Setup')}</p></div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-4xl space-y-6 p-6">
        <ol aria-label={t('Setup steps')} className="flex flex-wrap gap-2">
          {available.map((s, i) => <li key={s.intent}>
            <button type="button" aria-current={i === index ? 'step' : undefined} onClick={() => setIndex(i)}
              className={cn('flex items-center gap-2 rounded-full border px-3 py-1 text-sm', i === index ? 'border-primary bg-primary/5 font-medium' : 'text-muted-foreground hover:bg-muted')}>
              <span className="flex size-5 items-center justify-center rounded-full bg-muted text-xs">{i + 1}</span>{s.title}
            </button>
          </li>)}
        </ol>
        <p className="text-sm text-muted-foreground">{step.description}</p>
        <div className="space-y-6" key={step.intent}>{step.page()}</div>
        <div className="flex justify-between border-t pt-4">
          <Button variant="outline" disabled={index === 0} onClick={() => setIndex(index - 1)}>{t('Back')}</Button>
          <Button onClick={() => last ? setFinished(true) : setIndex(index + 1)}>{last ? t('Done') : t('Next')}</Button>
        </div>
      </main>
    </div>
  </AdminContext.Provider>
}
