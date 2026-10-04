import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Languages, LogIn, Palette, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { normalize, resolved } from '@/lib/branding'
import type { Branding } from '@/lib/branding'
import { buttonVariants } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmDialog, DataTable, EntityRef, ErrorState, PageHeader, shortId } from '@/components/library/patterns'
import { RowActions } from '@/components/ui/menu'
import { clientName, PreviewFrame } from '@/components/library/preview-frame'
import { everyMethod, SignInDialog, summary, type SignIn } from './sign-in-options'
import { OrgAdminPortalCard } from './org-admin-portal'
import { formatDateTime, rich, t } from '@/lib/i18n'

interface Client { id: string; application_name: string; resource_name: string; hosted_login: boolean; active: boolean }

const description = t('Branding for the sign-in and invitation pages IAMKit hosts for OAuth clients with hosted login enabled.')
const modes = { light: t('Light'), dark: t('Dark'), adaptive: t('Adaptive') }

function Swatches({ style }: { style: Branding }) {
  const p = resolved(style, style.theme.mode === 'dark' ? 'dark' : 'light')
  return <span className="inline-flex items-center gap-1" aria-hidden>
    {[p.primary, p.background, p.card, p.text].map((c, i) => <span key={i} className="size-3.5 rounded-full border" style={{ background: c }} />)}
  </span>
}

export default function HostedLoginPage() {
  const { project, environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const page = `/projects/${project}/environments/${environment}/hosted-login`
  const go = useNavigate()
  const [fallback, setFallback] = useState<Branding | null>(null)
  const [styles, setStyles] = useState<Branding[]>([])
  const [clients, setClients] = useState<Client[]>([])
  const [thumbnail, setThumbnail] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [reset, setReset] = useState<Branding | null>(null)
  const [signIns, setSignIns] = useState<SignIn[]>([])
  const [connections, setConnections] = useState<{ id: string; name: string; provider: string; organization_id: string | null; active: boolean }[]>([])
  const [methods, setMethods] = useState<Client | null>(null)
  const [resetMethods, setResetMethods] = useState<Client | null>(null)

  const load = () => {
    setError(''); setLoading(true)
    Promise.all([
      api.get<Branding>(`${base}/login-settings`),
      api.get<{ items: Branding[] }>(`${base}/login-settings/clients?limit=100`),
      api.get<{ items: Client[] }>(`${base}/oauth-clients?limit=100`),
      api.get<{ items: SignIn[] }>(`${base}/login-settings/sign-in?limit=100`),
      api.get<{ items: typeof connections }>(`${base}/federation-connections?limit=100`),
    ]).then(([d, s, c, m, f]) => { setFallback(normalize(d)); setStyles(s.items.map(normalize)); setClients(c.items); setSignIns(m.items); setConnections(f.items) })
      .catch(e => setError(message(e))).finally(() => setLoading(false))
    api.get<{ html: string }>(`${base}/login-settings/preview?page=identify`).then(r => setThumbnail(r.html)).catch(() => setThumbnail(''))
  }
  useEffect(load, [base])

  const header = <PageHeader title={t('Hosted login')} description={description} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (loading || !fallback) return <div className="space-y-6">{header}<p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p></div>

  const styled = new Map(styles.map(s => [s.client_id, s]))
  const offered = new Map(signIns.map(s => [s.client_id, s]))
  const hosted = clients.filter(c => c.hosted_login && c.active)
  // Clients with a style stay listed even if hosted login was turned off.
  const rows = [...hosted, ...clients.filter(c => (styled.has(c.id) || offered.has(c.id)) && !hosted.includes(c))]

  return <div className="space-y-6">
    {header}
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card className="overflow-hidden">
        <div className="grid sm:grid-cols-[1fr_220px]">
          <div className="space-y-4 p-6">
            <div>
              <h2 className="font-mono font-medium">{t('Default style')}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{t('Invitation pages and every client without its own style.')}</p>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">{t('Display name')}</dt><dd>{fallback.display_name || <span className="text-muted-foreground">—</span>}</dd>
              <dt className="text-muted-foreground">{t('Mode')}</dt><dd>{modes[fallback.theme.mode]}</dd>
              <dt className="text-muted-foreground">{t('Colors')}</dt><dd><Swatches style={fallback} /></dd>
              <dt className="text-muted-foreground">{t('Last saved')}</dt><dd>{fallback.updated_at ? formatDateTime(fallback.updated_at) : t('Never (IAMKit defaults)')}</dd>
            </dl>
            <div className="flex flex-wrap gap-2">
              <Link to={`${page}/default`} className={buttonVariants({ variant: canWrite ? 'default' : 'outline' })}><Palette className="size-4" /> {canWrite ? t('Edit default style') : t('View default style')}</Link>
              <Link to={`${page}/texts`} className={buttonVariants({ variant: 'outline' })}><Languages className="size-4" /> {t('Sign-in texts')}</Link>
            </div>
          </div>
          <div className="relative hidden h-full min-h-56 overflow-hidden border-l bg-muted/40 sm:block" aria-hidden>
            {thumbnail && <div className="pointer-events-none absolute top-0 left-0 h-[250%] w-[250%] origin-top-left scale-[0.4]"><PreviewFrame html={thumbnail} className="h-full" title={t('Default style thumbnail')} /></div>}
          </div>
        </div>
      </Card>
      <Card className="border-dashed">
        <CardHeader><CardDescription>{t('How it works')}</CardDescription><CardTitle className="text-sm font-normal">{t('Enable “Hosted pages” on an OAuth client')}</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>{rich('{{code}} then sends the browser to {{code2}} instead of returning the authorization ticket.', { code: <code className="text-xs">{'/oauth/authorize'}</code>, code2: <code className="text-xs">{'/hosted/login'}</code> })}</p>
          <p>{t('Users sign in with a password, an email code, social login or their organization\'s single sign-on, pick an organization when they belong to several, and return to your redirect URI with an authorization code.')}</p>
          <p>{rich('Invitation links open {{code}} unless Notifications sets an invitation page of your own.', { code: <code className="text-xs">{'/hosted/invite'}</code> })}</p>
        </CardContent>
      </Card>
    </div>

    <OrgAdminPortalCard environment={environment ?? ''} canWrite={canWrite} />

    <section className="space-y-3">
      <div>
        <h2 className="font-mono font-medium">{t('Clients')}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t('Give an OAuth client its own look and choose which sign-in methods it offers. Clients without their own use the default style and every method.')}</p>
      </div>
      <DataTable columns={[t('Client'), t('Style'), { header: t('Sign-in methods'), hideBelow: 'md' }, t('Actions')]} loading={false} error="" retry={load}
        rowHref={i => `${page}/clients/${rows[i].id}`}
        rows={rows.map(c => {
          const own = styled.get(c.id)
          const name = clientName(c) || shortId(c.id)
          return [
            <EntityRef name={name} id={c.id} to={`${page}/clients/${c.id}`} secondary={!c.hosted_login ? t('Hosted pages off') : undefined} />,
            <span className="inline-flex items-center gap-2 text-sm"><Swatches style={own ?? fallback} />{own ? <Badge className="bg-primary/10 text-primary">{t('Custom')}</Badge> : <span className="text-muted-foreground">{t('Default')}</span>}<span className="text-xs text-muted-foreground">{modes[(own ?? fallback).theme.mode]}</span></span>,
            <span className={`text-sm ${offered.has(c.id) ? '' : 'text-muted-foreground'}`}>{summary(offered.get(c.id) ?? everyMethod(c.id), connections)}</span>,
            <RowActions label={t('Actions for {{name}}', { name })} actions={[
              { label: own ? (canWrite ? t('Edit style') : t('View style')) : t('Customize style'), icon: <Palette />, disabled: !own && !canWrite, onSelect: () => go(`${page}/clients/${c.id}`) },
              { label: canWrite ? t('Choose sign-in methods') : t('View sign-in methods'), icon: <LogIn />, onSelect: () => setMethods(c) },
              ...(canWrite && own ? [{ label: t('Reset to default style'), icon: <RotateCcw />, onSelect: () => setReset(own) }] : []),
              ...(canWrite && offered.has(c.id) ? [{ label: t('Offer every method'), icon: <RotateCcw />, onSelect: () => setResetMethods(c) }] : []),
            ]} />,
          ]
        })} />
      {rows.length === 0 && <p className="text-xs text-muted-foreground">{t('Turn on hosted pages for an OAuth client to give it a style.')}</p>}
    </section>
    {methods && <SignInDialog base={base} client={methods.id} name={clientName(methods) || methods.id} readOnly={!canWrite} onClose={() => setMethods(null)} onSaved={load} />}
    {resetMethods && <ConfirmDialog title={t('Offer every sign-in method?')} description={t('The client\'s sign-in options are deleted and its sign-in page offers every method again.')} confirmLabel={t('Reset')} onClose={() => setResetMethods(null)}
      confirm={async () => { await api.delete(`${base}/login-settings/clients/${resetMethods.id}/sign-in`); toast.success(t('Sign-in methods reset')); load() }} />}
    {reset && <ConfirmDialog title={t('Reset to the default style?')} description={t('The client\'s own style is deleted and its sign-in pages use the environment default again.')} confirmLabel={t('Reset')} onClose={() => setReset(null)}
      confirm={async () => { await api.delete(`${base}/login-settings/clients/${reset.client_id}`); toast.success(t('Client style reset')); load() }} />}
  </div>
}
