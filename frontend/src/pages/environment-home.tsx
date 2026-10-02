import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Activity, ArrowRight, Blocks, Building2, Check, KeyRound, Link2, LogIn, Shield, Users } from 'lucide-react'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, EmptyState, PageHeader, Time } from '@/components/library/patterns'
import { describeAction } from './activity'
import { t } from '@/lib/i18n'

interface Event { id: string; action: string; actor_id: string; target_id: string; created_at: string }
type Counts = Record<'users' | 'organizations' | 'applications' | 'resources' | 'clients' | 'sessions', number | null>
const sources: [keyof Counts, string][] = [['users', 'users'], ['organizations', 'organizations'], ['applications', 'applications'], ['resources', 'resources'], ['clients', 'oauth-clients'], ['sessions', 'sessions']]

/** EnvironmentHome is the landing page of an environment: what exists,
 * what is left to set up, and what happened recently. */
export default function EnvironmentHomePage() {
  const { project, environment } = useParams()
  const base = `/projects/${project}/environments/${environment}`
  const [counts, setCounts] = useState<Counts | null>(null)
  const [events, setEvents] = useState<Event[] | null>(null)
  useEffect(() => {
    const controller = new AbortController()
    const api_ = `/environments/${environment}`
    Promise.all(sources.map(([, path]) => api.list(`${api_}/${path}?limit=1`, controller.signal).then(r => r.total).catch(() => null)))
      .then(values => { if (!controller.signal.aborted) setCounts(Object.fromEntries(sources.map(([k], i) => [k, values[i]])) as Counts) })
    api.list<Event>(`${api_}/audit-events?limit=6`, controller.signal).then(r => { if (!controller.signal.aborted) setEvents(r.data) }).catch(() => { if (!controller.signal.aborted) setEvents([]) })
    return () => controller.abort()
  }, [environment])

  const stats: [string, keyof Counts, typeof Users, string][] = [
    [t('Users'), 'users', Users, 'users'], [t('Organizations'), 'organizations', Building2, 'organizations'],
    [t('Applications'), 'applications', Blocks, 'applications'], [t('Sessions'), 'sessions', KeyRound, 'sessions'],
  ]
  const steps: [string, string, boolean | null, string][] = counts ? [
    [t('Register an application'), t('The product your users sign in to.'), counts.applications === null ? null : counts.applications > 0, 'applications'],
    [t('Define a resource and its scopes'), t('An API audience and the permissions it understands.'), counts.resources === null ? null : counts.resources > 0, 'resources'],
    [t('Create an OAuth client'), t('Redirect URIs and how users sign in to the application.'), counts.clients === null ? null : counts.clients > 0, 'oauth-clients'],
    [t('Style the hosted sign-in page (optional)'), t('Logo, colors and the sign-in methods users see.'), null, 'hosted-login'],
    [t('Add your first organization'), t('Tenants group users and hold their access.'), counts.organizations === null ? null : counts.organizations > 0, 'organizations'],
  ] : []
  const done = steps.filter(s => s[2]).length

  return <div className="space-y-6">
    <PageHeader title={t('Environment home')} description={t('What this environment contains, what is left to set up, and recent changes.')} />
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stats.map(([label, key, Icon, path]) => <Link key={key} to={`${base}/${path}`} className="group rounded-lg border bg-card p-4 transition-colors hover:border-primary/50">
        <div className="flex items-center justify-between text-muted-foreground"><span className="text-xs">{label}</span><Icon className="size-4" /></div>
        {counts ? <p className="mt-2 text-2xl font-semibold tabular-nums">{counts[key] ?? '—'}</p> : <Skeleton className="mt-2 h-8 w-12" />}
      </Link>)}
    </div>
    <div className="grid gap-6 lg:grid-cols-2">
      <DetailSection title={t('Set up sign-in')} description={counts ? t('{{done}} of {{count}} required steps done', { done, count: steps.filter(s => s[2] !== null).length }) : t('Checking…')}>
        {!counts ? <div className="space-y-3">{[1, 2, 3].map(i => <Skeleton key={i} className="h-10" />)}</div> :
          <ol className="space-y-1">{steps.map(([title, text, complete, path], i) => <li key={title}>
            <Link to={`${base}/${path}`} className="flex items-start gap-3 rounded-md p-2 hover:bg-muted/50">
              <span className={cn('mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[10px]', complete ? 'border-success bg-success/15 text-success' : 'text-muted-foreground')}>{complete ? <Check className="size-3" /> : complete === null ? <LogIn className="size-3" /> : i + 1}</span>
              <span className="min-w-0 flex-1"><span className={cn('block text-sm font-medium', complete && 'text-muted-foreground line-through decoration-muted-foreground/40')}>{title}</span><span className="block text-xs text-muted-foreground">{text}</span></span>
              <ArrowRight className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            </Link>
          </li>)}</ol>}
      </DetailSection>
      <DetailSection title={t('Recent changes')} actions={<Link to={`${base}/audit-events`} className="text-xs text-primary hover:underline">{t('All activity')}</Link>}>
        {events === null ? <div className="space-y-3">{[1, 2, 3].map(i => <Skeleton key={i} className="h-8" />)}</div> :
          events.length === 0 ? <EmptyState icon={<Activity />} title={t('No changes yet')} description={t('Changes made in this environment appear here.')} /> :
            <ul className="divide-y">{events.map(e => <li key={e.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <span className="min-w-0 truncate">{describeAction(e.action, e.target_id)}</span>
              <span className="shrink-0 text-xs text-muted-foreground"><Time value={e.created_at} /></span>
            </li>)}</ul>}
      </DetailSection>
    </div>
    <div className="grid gap-3 sm:grid-cols-3">
      {([[t('OAuth clients'), 'oauth-clients', Link2, t('Connect applications to sign-in.')], [t('Sign-in providers'), 'federation', Shield, t('Social login (Google, GitHub…) and organization SSO.')], [t('Hosted login'), 'hosted-login', LogIn, t('The sign-in pages your users see.')]] as const).map(([title, path, Icon, text]) =>
        <Link key={path} to={`${base}/${path}`} className="flex items-start gap-3 rounded-lg border p-4 hover:border-primary/50">
          <Icon className="mt-0.5 size-4 text-muted-foreground" /><span><span className="block text-sm font-medium">{title}</span><span className="block text-xs text-muted-foreground">{text}</span></span>
        </Link>)}
    </div>
  </div>
}
