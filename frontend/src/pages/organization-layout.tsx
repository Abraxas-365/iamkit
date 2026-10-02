import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { Skeleton } from '@/components/ui/skeleton'
import { BackLink, CopyText, ErrorState, Status } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

export interface Organization {
  id: string; name: string; active: boolean
  metadata?: Record<string, unknown> | null
  mfa_required: boolean; mfa_for_federated: boolean
  allow_password: boolean; allow_email_code: boolean; allow_social: boolean; allow_passkey: boolean
  allowed_factors?: string[]
}

interface OrgContext { org: Organization; reload: () => void }
const Context = createContext<OrgContext | null>(null)

/** useOrganization returns the organization loaded by OrganizationLayout. */
export function useOrganization() {
  const ctx = useContext(Context)
  if (!ctx) throw new Error(t('useOrganization must be used inside OrganizationLayout'))
  return ctx
}

const tabs: [string, string][] = [['', t('Overview')], ['members', t('Members')], ['groups', t('Groups')], ['domains', t('Domains')], ['invitations', t('Invitations')], ['connections', 'SSO'], ['resources', t('Resources')], ['branding', t('Branding')]]

/** OrganizationLayout is the shared header and tab bar of every
 * organization page; each tab renders in the outlet. */
export default function OrganizationLayout() {
  const { project, environment, orgId } = useParams()
  const console = `/projects/${project}/environments/${environment}`
  const root = `${console}/organizations/${orgId}`
  const [org, setOrg] = useState<Organization | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(() => {
    setError('')
    api.get<Organization>(`/environments/${environment}/organizations/${orgId}`).then(setOrg).catch(e => setError(message(e)))
  }, [environment, orgId])
  useEffect(load, [load])

  return <div className="space-y-6">
    <div className="space-y-3">
      <BackLink to={`${console}/organizations`}>{t('All organizations')}</BackLink>
      {error ? <ErrorState error={error} retry={load} /> : !org ? <Skeleton className="h-9 w-64" /> : <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h1 className="font-mono text-2xl font-bold tracking-tight">{org.name}</h1>
        <Status active={org.active} />
        <CopyText value={org.id} label={t('Copy organization ID')} />
      </div>}
    </div>
    <nav aria-label={t('Organization sections')} className="-mx-1 overflow-x-auto border-b [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
      <ul className="flex min-w-max gap-1 px-1">
        {tabs.map(([path, label]) => <li key={label}>
          <NavLink end={path === ''} to={path ? `${root}/${path}` : root} className={({ isActive }) => cn('-mb-px inline-flex h-9 items-center border-b-2 px-3 text-sm transition-colors', isActive ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>{label}</NavLink>
        </li>)}
      </ul>
    </nav>
    {org && <Context.Provider value={{ org, reload: load }}><Outlet /></Context.Provider>}
  </div>
}
