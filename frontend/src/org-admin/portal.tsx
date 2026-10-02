import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Activity, Building2, Globe, KeyRound, Lock, LogOut, Mail, Palette, Share2, Tags, UserCog, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ErrorState } from '@/components/library/patterns'
import { LogoMark } from '@/components/brand/logo'
import { Toaster } from '@/components/ui/sonner'
import { cn, message } from '@/lib/utils'
import { Client, complete, decode, discover, readTokens, signIn, signOut, type Portal } from './session'
import { AdminContext, useAdmin, type Admin } from './context'
import { ActivityPage, BrandingPage, ConnectionsPage, DomainsPage, InvitationsPage, MembersPage, OverviewPage, PasswordPage, ResourcesPage, RolesPage, UsersPage } from './pages'
import { t } from '@/lib/i18n'

type NavItem = [path: string, label: string, icon: typeof Users, permission: string]
const nav: NavItem[] = [
  ['', t('Overview'), Building2, 'iam:org:read'],
  ['members', t('Members'), Users, 'iam:org:members:read'],
  ['users', t('Users'), UserCog, 'iam:org:members:read'],
  ['invitations', t('Invitations'), Mail, 'iam:org:members:read'],
  ['roles', t('Roles'), Tags, 'iam:org:roles:read'],
  ['domains', t('Domains'), Globe, 'iam:org:read'],
  ['sso', t('Single sign-on'), KeyRound, 'iam:org:read'],
  ['resources', t('Resources'), Share2, 'iam:org:resources:read'],
  ['branding', t('Branding'), Palette, 'iam:org:read'],
  ['password-policy', t('Password policy'), Lock, 'iam:org:read'],
  ['activity', t('Activity'), Activity, 'iam:org:audit:read'],
]

/** OrgAdminPortal is the hosted organization admin portal: served by
 * IAMKit at /org-admin/:environment, signed in through the hosted login
 * with the environment's portal client. It never shares the operator
 * console's session. */
export default function OrgAdminPortal() {
  return <>
    <Routes>
      <Route path=":environment/callback" element={<Callback />} />
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
  const can = useCallback((p: string) => permissions.has(p), [permissions])
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
  const base = `/org-admin/${environment}`
  const items = nav.filter(([, , , permission]) => can(permission))
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
        <span className="truncate text-sm text-muted-foreground">{claims.email || claims.name || ''}</span>
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
          <Route path="resources" element={<Guard permission="iam:org:resources:read"><ResourcesPage /></Guard>} />
          <Route path="branding" element={<Guard permission="iam:org:read"><BrandingPage /></Guard>} />
          <Route path="password-policy" element={<Guard permission="iam:org:read"><PasswordPage /></Guard>} />
          <Route path="activity" element={<Guard permission="iam:org:audit:read"><ActivityPage /></Guard>} />
          <Route path="*" element={<Navigate to={home} replace />} />
        </Routes>
      </main>
    </div>
  </div>
}

function Guard({ permission, children }: { permission: string; children: ReactNode }) {
  const { can, environment } = useAdmin()
  if (!can(permission)) return <div className="space-y-3"><ErrorState error={t('You do not have access to this page.')} /><Link className="text-sm underline" to={`/org-admin/${environment}`}>{t('Back')}</Link></div>
  return <>{children}</>
}
