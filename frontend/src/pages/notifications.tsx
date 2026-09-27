import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Mail, Globe, Shield, Clock, Pencil, Trash2, Plus, MailPlus, Send, Check, Copy, CircleCheck, CircleX, CircleDashed, Activity } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardAction } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ConfirmDialog, ErrorState, PageHeader } from '@/components/library/patterns'

interface DeliveryConfig {
  environment_id: string
  webhook_url: string
  has_token: boolean
  invitation_url: string
  created_at: string
  updated_at: string
}

type Source = 'environment' | 'global' | 'none'

export interface Attempt {
  source: Source
  purpose: string
  delivered: boolean
  status?: number
  reason?: string
  latency_ms: number
  at: string
}

interface DeliveryStatus {
  source: Source
  global_configured: boolean
  hosted_invitation_url: string
  last_attempt: Attempt | null
  last_failure: Attempt | null
}

const DESCRIPTION = 'Configure the webhook that delivers login codes, password resets, email verification and invitations.'

// The webhook contract (docs/reference/webhooks.md).
const PURPOSES = [
  { purpose: 'login', label: 'Login code', fields: ['email', 'purpose', 'code'], validity: '5 minutes, single use', example: { email: 'ada@example.com', purpose: 'login', code: '48213907' } },
  { purpose: 'password_reset', label: 'Password reset', fields: ['email', 'purpose', 'code'], validity: '5 minutes, single use', example: { email: 'ada@example.com', purpose: 'password_reset', code: '48213907' } },
  { purpose: 'email_verification', label: 'Email verification', fields: ['email', 'purpose', 'code'], validity: '5 minutes, single use', example: { email: 'ada@example.com', purpose: 'email_verification', code: '48213907' } },
  {
    purpose: 'invitation', label: 'Invitation', fields: ['email', 'purpose', 'token', 'link', 'organization', 'inviter', 'expires_at'], validity: '7 days, single use',
    example: { email: 'ada@example.com', purpose: 'invitation', token: 'ik_inv_…', link: 'https://app.example.com/join?token=ik_inv_…', organization: 'Acme', inviter: 'owner@example.com', expires_at: '2026-10-04T12:00:00Z' },
  },
  { purpose: 'test', label: 'Test (console)', fields: ['email', 'purpose'], validity: 'No code', example: { email: 'ops@example.com', purpose: 'test' } },
]

const SOURCE_TEXT: Record<Source, { badge: string; className: string; detail: string }> = {
  environment: { badge: 'This environment', className: 'bg-success/10 text-success', detail: 'Mail goes to this environment’s webhook.' },
  global: { badge: 'Global fallback', className: 'bg-primary/10 text-primary', detail: 'No webhook here: mail goes to the server-wide EMAIL_WEBHOOK_URL.' },
  none: { badge: 'Not configured', className: 'bg-destructive/10 text-destructive', detail: 'No webhook here and no EMAIL_WEBHOOK_URL: codes and invitations are not delivered.' },
}

export function outcome(a: Attempt) {
  if (a.delivered) return `Delivered${a.status ? ` (${a.status})` : ''} in ${a.latency_ms} ms`
  return `${a.reason || 'Delivery failed'}${a.status ? ` (HTTP ${a.status})` : ''}`
}

export default function NotificationsPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/delivery`
  const [config, setConfig] = useState<DeliveryConfig | null>(null)
  const [status, setStatus] = useState<DeliveryStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [testing, setTesting] = useState(false)

  const load = () => {
    setError('')
    Promise.all([
      api.get<DeliveryConfig>(path).catch(e => { if (e?.status === 404) return null; throw e }),
      api.get<DeliveryStatus>(`${path}/status`),
    ])
      .then(([cfg, st]) => { setConfig(cfg); setStatus(st) })
      .catch(e => setError(message(e)))
      .finally(() => setLoading(false))
  }
  useEffect(() => { setLoading(true); load() }, [path])

  if (loading) return <div className="space-y-6">
    <PageHeader title="Notifications" description={DESCRIPTION} />
    <div className="grid gap-4 lg:grid-cols-2">
      {[1, 2].map(i => <Card key={i} className="animate-pulse"><CardContent className="pt-6"><div className="h-32 rounded-lg bg-muted" /></CardContent></Card>)}
    </div>
  </div>

  if (error || !status) return <div className="space-y-6">
    <PageHeader title="Notifications" description={DESCRIPTION} />
    <ErrorState error={error || 'Delivery status unavailable'} retry={load} />
  </div>

  const source = SOURCE_TEXT[status.source]
  return <div className="space-y-6">
    <PageHeader title="Notifications" description={DESCRIPTION} actions={canWrite && status.source !== 'none' && (
      <Button variant="outline" onClick={() => setTesting(true)}><Send className="size-4" /> Send test email</Button>
    )} />

    <div className="grid gap-4 lg:grid-cols-2">
      {/* ── Delivery ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Mail className="size-4" /> Delivery</CardTitle>
          <CardDescription>{source.detail}</CardDescription>
          <CardAction><Badge variant="secondary" className={source.className}>{source.badge}</Badge></CardAction>
        </CardHeader>
        <CardContent className="space-y-4">
          {config ? <>
            <Field icon={Globe} label="Endpoint"><span className="break-all font-mono text-sm">{config.webhook_url}</span></Field>
            <Field icon={Shield} label="Authentication">
              {config.has_token ? <Badge variant="secondary" className="bg-success/10 text-success">Bearer token configured</Badge> : <Badge variant="destructive">No token</Badge>}
            </Field>
            <Field icon={Clock} label="Last updated"><span className="text-sm">{new Date(config.updated_at).toLocaleString()}</span></Field>
          </> : <p className="text-sm text-muted-foreground">
            {status.global_configured
              ? <>Using the global <code className="rounded bg-muted px-1 py-0.5 text-xs">EMAIL_WEBHOOK_URL</code>. Configure a webhook to give this environment its own endpoint.</>
              : <>Set a webhook here, or <code className="rounded bg-muted px-1 py-0.5 text-xs">EMAIL_WEBHOOK_URL</code> on the server, so users can receive codes and invitations.</>}
          </p>}
          {canWrite && <div className="flex flex-wrap gap-2 pt-1">
            {config ? <>
              <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil className="size-3.5" /> Update</Button>
              <Button variant="outline" size="sm" className="text-destructive hover:bg-destructive/10" onClick={() => setRemoving(true)}><Trash2 className="size-3.5" /> Remove</Button>
            </> : <Button size="sm" onClick={() => setEditing(true)}><Plus className="size-3.5" /> Configure webhook</Button>}
          </div>}
        </CardContent>
      </Card>

      {/* ── Activity ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Activity className="size-4" /> Recent activity</CardTitle>
          <CardDescription>Outcome of the latest delivery from this environment.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status.last_attempt ? <>
            <AttemptRow title="Last attempt" attempt={status.last_attempt} />
            {status.last_failure && !(status.last_attempt.delivered === false && status.last_failure.at === status.last_attempt.at) &&
              <AttemptRow title="Last failure" attempt={status.last_failure} />}
          </> : <div className="flex items-center gap-2 text-sm text-muted-foreground"><CircleDashed className="size-4" /> No deliveries yet.</div>}
        </CardContent>
      </Card>

      {/* ── Invitations ── */}
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><MailPlus className="size-4" /> Invitations</CardTitle>
          <CardDescription>The page that accepts invitations. IAMKit adds <code className="text-xs">?token=…</code> and sends the result as <code className="text-xs">link</code>.</CardDescription>
        </CardHeader>
        <CardContent>
          {config?.invitation_url
            ? <span className="break-all font-mono text-sm">{config.invitation_url}{config.invitation_url === status.hosted_invitation_url && <Badge variant="secondary" className="ml-2 font-sans">Hosted page</Badge>}</span>
            : <p className="text-sm text-muted-foreground">{config ? 'Not set: invitation emails carry only the token.' : status.global_configured ? 'Invitation links need this environment’s own webhook; the global fallback sends only the token.' : 'Configure a webhook to set an invitation page.'}</p>}
        </CardContent>
      </Card>
    </div>

    <PurposesCard />

    {editing && <DeliveryForm path={path} existing={config} hostedURL={status.hosted_invitation_url} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); load() }} />}
    {removing && <ConfirmDialog title="Remove delivery config?" description={status.global_configured ? 'This environment will fall back to the global EMAIL_WEBHOOK_URL.' : 'No global EMAIL_WEBHOOK_URL is set: this environment will stop delivering codes and invitations.'} onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success('Delivery config removed'); load() }} />}
    {testing && <TestDialog path={path} source={status.source} onClose={() => { setTesting(false); load() }} />}
  </div>
}

function Field({ icon: Icon, label, children }: { icon: typeof Globe; label: string; children: React.ReactNode }) {
  return <div className="space-y-1">
    <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Icon className="size-3.5" /> {label}</p>
    <div>{children}</div>
  </div>
}

function AttemptRow({ title, attempt }: { title: string; attempt: Attempt }) {
  const Icon = attempt.delivered ? CircleCheck : CircleX
  return <div className="space-y-1">
    <p className="text-xs text-muted-foreground">{title}</p>
    <div className="flex items-start gap-2">
      <Icon className={`mt-0.5 size-4 shrink-0 ${attempt.delivered ? 'text-success' : 'text-destructive'}`} />
      <div className="text-sm">
        <p className="font-medium">{outcome(attempt)}</p>
        <p className="text-xs text-muted-foreground">
          <code>{attempt.purpose}</code> via {attempt.source === 'environment' ? 'this environment' : attempt.source === 'global' ? 'global fallback' : 'no webhook'} · {new Date(attempt.at).toLocaleString()}
        </p>
      </div>
    </div>
  </div>
}

function PurposesCard() {
  const [open, setOpen] = useState<string | null>(null)
  return <Card>
    <CardHeader>
      <CardTitle className="text-base">Message types</CardTitle>
      <CardDescription>Every request is a JSON <code className="text-xs">POST</code> with <code className="text-xs">Authorization: Bearer &lt;token&gt;</code>. Reply with any 2xx within 10 seconds; redirects are refused and nothing is retried. Pick the email template by <code className="text-xs">purpose</code>.</CardDescription>
    </CardHeader>
    <CardContent>
      <Table>
        <TableHeader><TableRow><TableHead>Purpose</TableHead><TableHead>Fields</TableHead><TableHead>Valid for</TableHead><TableHead className="w-0" /></TableRow></TableHeader>
        <TableBody>
          {PURPOSES.map(p => <PurposeRow key={p.purpose} p={p} open={open === p.purpose} toggle={() => setOpen(open === p.purpose ? null : p.purpose)} />)}
        </TableBody>
      </Table>
    </CardContent>
  </Card>
}

function PurposeRow({ p, open, toggle }: { p: typeof PURPOSES[number]; open: boolean; toggle: () => void }) {
  const [copied, setCopied] = useState(false)
  const json = JSON.stringify(p.example, null, 2)
  return <>
    <TableRow>
      <TableCell><code className="text-xs">{p.purpose}</code><p className="text-xs text-muted-foreground">{p.label}</p></TableCell>
      <TableCell className="whitespace-normal"><div className="flex flex-wrap gap-1">{p.fields.map(f => <code key={f} className="rounded bg-muted px-1 py-0.5 text-[11px]">{f}</code>)}</div></TableCell>
      <TableCell className="text-xs">{p.validity}</TableCell>
      <TableCell><Button variant="ghost" size="sm" aria-expanded={open} onClick={toggle}>{open ? 'Hide' : 'Example'}</Button></TableCell>
    </TableRow>
    {open && <TableRow className="hover:bg-transparent">
      <TableCell colSpan={4}>
        <div className="relative">
          <pre aria-label={`${p.purpose} example payload`} className="overflow-x-auto rounded-md bg-muted p-3 text-xs">{json}</pre>
          <Button variant="ghost" size="icon" className="absolute top-1 right-1 size-7" aria-label={`Copy ${p.purpose} example`} onClick={async () => {
            try { await navigator.clipboard.writeText(json); setCopied(true); setTimeout(() => setCopied(false), 1500) }
            catch { toast.error('Copy failed') }
          }}>{copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}</Button>
        </div>
      </TableCell>
    </TableRow>}
  </>
}

function TestDialog({ path, source, onClose }: { path: string; source: Source; onClose: () => void }) {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Attempt | null>(null)

  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle className="pr-6 text-base font-semibold">Send test email</DialogTitle>
      <DialogDescription className="text-muted-foreground">
        Sends <code className="text-xs">{'{"email","purpose":"test"}'}</code> through {source === 'environment' ? 'this environment’s webhook' : 'the global EMAIL_WEBHOOK_URL'}. It carries no code; handle <code className="text-xs">test</code> in your service or expect it to be ignored.
      </DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault()
        if (busy) return
        setBusy(true); setError(''); setResult(null)
        try { setResult(await api.post<Attempt>(`${path}/test`, { email: email.trim() })) }
        catch (e) { setError(message(e)) }
        finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="test-email">Recipient</label>
          <Input id="test-email" type="email" required disabled={busy} value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        {result && <div role="status" className={`flex items-start gap-2 rounded-md border p-3 text-sm ${result.delivered ? 'border-success/30 bg-success/5' : 'border-destructive/30 bg-destructive/5'}`}>
          {result.delivered ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" /> : <CircleX className="mt-0.5 size-4 shrink-0 text-destructive" />}
          <div><p className="font-medium">{result.delivered ? 'Webhook accepted the message' : 'Delivery failed'}</p><p className="text-xs text-muted-foreground">{outcome(result)}</p></div>
        </div>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Close</Button>
          <Button type="submit" disabled={busy}><Send className="size-3.5" /> {busy ? 'Sending…' : result ? 'Send again' : 'Send'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

function DeliveryForm({ path, existing, hostedURL, onClose, onSaved }: { path: string; existing: DeliveryConfig | null; hostedURL: string; onClose: () => void; onSaved: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [invitationURL, setInvitationURL] = useState(existing?.invitation_url ?? '')
  const pending = useRef(false)

  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? 'Update' : 'Configure'} webhook</DialogTitle>
      <DialogDescription className="text-muted-foreground">IAMKit will POST codes and invitations to this endpoint with the token as a Bearer header.</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault()
        if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data = {
          webhook_url: String(form.get('webhook_url') ?? '').trim(),
          webhook_token: String(form.get('webhook_token') ?? '').trim(),
          invitation_url: invitationURL.trim(),
        }
        if (!data.webhook_url || !data.webhook_token) {
          setError('Both URL and token are required.')
          return
        }
        pending.current = true; setBusy(true); setError('')
        try {
          await api.put(path, data)
          toast.success('Delivery config saved')
          onSaved()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="webhook-url">Webhook URL</label>
          <Input id="webhook-url" name="webhook_url" type="url" required disabled={busy} defaultValue={existing?.webhook_url ?? ''} placeholder="https://mail.example.com/send" />
          <p className="text-xs text-muted-foreground">Must be HTTPS. HTTP is allowed only for localhost.</p>
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="webhook-token">Webhook token</label>
          <Input id="webhook-token" name="webhook_token" type="password" required disabled={busy} placeholder={existing ? '(enter new token)' : 'Bearer authentication secret'} autoComplete="off" />
          <p className="text-xs text-muted-foreground">Sent as <code className="text-[10px]">Authorization: Bearer &lt;token&gt;</code> with every delivery request.</p>
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invitation-url">Invitation page (optional)</label>
          <Input id="invitation-url" type="url" disabled={busy} value={invitationURL} onChange={e => setInvitationURL(e.target.value)} placeholder="https://app.example.com/join" />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-muted-foreground">Your page that accepts invitations, or IAMKit’s hosted page.</p>
            {hostedURL && invitationURL !== hostedURL && <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" disabled={busy} onClick={() => setInvitationURL(hostedURL)}>Use hosted invite page</Button>}
          </div>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
