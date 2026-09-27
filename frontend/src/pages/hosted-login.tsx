import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Palette, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { normalize, resolved } from '@/lib/branding'
import type { Branding } from '@/lib/branding'
import { Button, buttonVariants } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmDialog, DataTable, ErrorState, ID, PageHeader } from '@/components/library/patterns'
import { clientName, PreviewFrame } from '@/components/library/preview-frame'
import { everyMethod, SignInDialog, summary, type SignIn } from './sign-in-options'

interface Client { id: string; application_name: string; resource_name: string; hosted_login: boolean; active: boolean }

const description = 'Branding for the sign-in and invitation pages IAMKit hosts for OAuth clients with hosted login enabled.'
const modes = { light: 'Light', dark: 'Dark', adaptive: 'Adaptive' }

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

  const header = <PageHeader title="Hosted login" description={description} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (loading || !fallback) return <div className="space-y-6">{header}<p role="status" className="text-sm text-muted-foreground">Loading…</p></div>

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
              <h2 className="font-mono font-medium">Default style</h2>
              <p className="mt-1 text-sm text-muted-foreground">Invitation pages and every client without its own style.</p>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">Display name</dt><dd>{fallback.display_name || <span className="text-muted-foreground">—</span>}</dd>
              <dt className="text-muted-foreground">Mode</dt><dd>{modes[fallback.theme.mode]}</dd>
              <dt className="text-muted-foreground">Colors</dt><dd><Swatches style={fallback} /></dd>
              <dt className="text-muted-foreground">Last saved</dt><dd>{fallback.updated_at ? new Date(fallback.updated_at).toLocaleString() : 'Never (IAMKit defaults)'}</dd>
            </dl>
            <Link to={`${page}/default`} className={buttonVariants({ variant: canWrite ? 'default' : 'outline' })}><Palette className="size-4" /> {canWrite ? 'Edit default style' : 'View default style'}</Link>
          </div>
          <div className="relative hidden h-full min-h-56 overflow-hidden border-l bg-muted/40 sm:block" aria-hidden>
            {thumbnail && <div className="pointer-events-none absolute top-0 left-0 h-[250%] w-[250%] origin-top-left scale-[0.4]"><PreviewFrame html={thumbnail} className="h-full" title="Default style thumbnail" /></div>}
          </div>
        </div>
      </Card>
      <Card className="border-dashed">
        <CardHeader><CardDescription>How it works</CardDescription><CardTitle className="text-sm font-normal">Enable “Hosted pages” on an OAuth client</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p><code className="text-xs">/oauth/authorize</code> then sends the browser to <code className="text-xs">/hosted/login</code> instead of returning the authorization ticket.</p>
          <p>Users sign in with a password, an email code, social login or their organization's single sign-on, pick an organization when they belong to several, and return to your redirect URI with an authorization code.</p>
          <p>Invitation links can point to <code className="text-xs">/hosted/invite</code>: set it as the invitation page in Notifications.</p>
        </CardContent>
      </Card>
    </div>

    <section className="space-y-3">
      <div>
        <h2 className="font-mono font-medium">Clients</h2>
        <p className="mt-1 text-sm text-muted-foreground">Give an OAuth client its own look and choose which sign-in methods it offers. Clients without their own use the default style and every method.</p>
      </div>
      <DataTable columns={['Client', 'Client ID', 'Style', 'Colors', 'Sign-in methods', 'Actions']} loading={false} error="" retry={load} rows={rows.map(c => {
        const own = styled.get(c.id)
        return [
          <span className="text-sm">{clientName(c) || '—'}{!c.hosted_login && <Badge variant="secondary" className="ml-2">Hosted login off</Badge>}</span>,
          <ID value={c.id} />,
          <span className="text-sm">{own ? <Badge className="bg-primary/10 text-primary">Custom</Badge> : <span className="text-muted-foreground">Default</span>} <span className="ml-1 text-xs text-muted-foreground">{modes[(own ?? fallback).theme.mode]}</span></span>,
          <Swatches style={own ?? fallback} />,
          <div className="flex items-center gap-2">
            <span className={`text-sm ${offered.has(c.id) ? '' : 'text-muted-foreground'}`}>{summary(offered.get(c.id) ?? everyMethod(c.id), connections)}</span>
            <Button variant="outline" size="sm" aria-label={`Sign-in methods of ${clientName(c) || c.id}`} onClick={() => setMethods(c)}>{canWrite ? 'Choose' : 'View'}</Button>
            {offered.has(c.id) && canWrite && <Button variant="ghost" size="sm" aria-label={`Offer every method on ${clientName(c) || c.id}`} onClick={() => setResetMethods(c)}>Reset</Button>}
          </div>,
          <div className="flex gap-2">
            {own
              ? <Link to={`${page}/clients/${c.id}`} className={buttonVariants({ variant: 'outline', size: 'sm' })}>{canWrite ? 'Edit' : 'View'}</Link>
              : canWrite && <Link to={`${page}/clients/${c.id}`} className={buttonVariants({ variant: 'outline', size: 'sm' })}><Plus className="size-3.5" /> Customize</Link>}
            {own && canWrite && <Button variant="ghost" size="sm" onClick={() => setReset(own)}>Reset</Button>}
          </div>,
        ]
      })} />
      {rows.length === 0 && <p className="text-xs text-muted-foreground">Turn on hosted pages for an OAuth client to give it a style.</p>}
    </section>
    {methods && <SignInDialog base={base} client={methods.id} name={clientName(methods) || methods.id} readOnly={!canWrite} onClose={() => setMethods(null)} onSaved={load} />}
    {resetMethods && <ConfirmDialog title="Offer every sign-in method?" description="The client's sign-in options are deleted and its sign-in page offers every method again." confirmLabel="Reset" onClose={() => setResetMethods(null)}
      confirm={async () => { await api.delete(`${base}/login-settings/clients/${resetMethods.id}/sign-in`); toast.success('Sign-in methods reset'); load() }} />}
    {reset && <ConfirmDialog title="Reset to the default style?" description="The client's own style is deleted and its sign-in pages use the environment default again." confirmLabel="Reset" onClose={() => setReset(null)}
      confirm={async () => { await api.delete(`${base}/login-settings/clients/${reset.client_id}`); toast.success('Client style reset'); load() }} />}
  </div>
}
