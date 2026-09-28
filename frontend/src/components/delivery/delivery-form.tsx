import { cloneElement, isValidElement, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { message } from '@/lib/utils'
import { copySettings, deliveryBody, draftFrom, needsSecret, PROVIDERS, secretKept, SMTP_PRESETS } from '@/lib/delivery'
import type { DeliveryConfig, DeliveryDraft, Provider } from '@/lib/delivery'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, ErrorState, RadioCards, selectClass } from '@/components/library/patterns'

// Field labels a control and links its hint via aria-describedby.
function Field({ id, label, hint, children }: { id: string; label: string; hint?: ReactNode; children: ReactNode }) {
  const hintID = `${id}-hint`
  const control = hint && isValidElement<{ 'aria-describedby'?: string }>(children) ? cloneElement(children, { 'aria-describedby': hintID }) : children
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{label}</label>
    {control}
    {hint && <p id={hintID} className="text-xs text-muted-foreground">{hint}</p>}
  </div>
}

// DeliveryForm configures how this environment sends email: a webhook, an
// SMTP server or Resend. Secrets are never shown; blank keeps the stored one.
export function DeliveryForm({ path, existing, hostedURL, onClose, onSaved }: { path: string; existing: DeliveryConfig | null; hostedURL: string; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<DeliveryDraft>(() => draftFrom(existing))
  const [initial] = useState(() => JSON.stringify(draftFrom(existing)))
  const [discarding, setDiscarding] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [needsKey, setNeedsKey] = useState(false)
  const pending = useRef(false)
  const set = (patch: Partial<DeliveryDraft>) => setD(prev => ({ ...prev, ...patch }))
  const kept = secretKept(d, existing)
  const close = () => { if (pending.current) return; if (JSON.stringify(d) !== initial) setDiscarding(true); else onClose() }

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (pending.current) return
    if (d.provider === 'webhook' && (!d.webhook_url.trim() || !d.webhook_token.trim())) {
      setError('Both URL and token are required.')
      return
    }
    pending.current = true; setBusy(true); setError(''); setNeedsKey(false)
    try {
      await api.put(path, deliveryBody(d))
      toast.success('Delivery settings saved')
      onSaved()
    } catch (e) {
      setError(message(e))
      setNeedsKey(e instanceof ApiError && e.code === 'ENCRYPTION_KEY_REQUIRED')
    } finally { pending.current = false; setBusy(false) }
  }

  return <Dialog open onOpenChange={open => { if (!open) close() }}>
    <DialogContent className="sm:max-w-lg">
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? 'Update' : 'Configure'} email delivery</DialogTitle>
      <DialogDescription className="text-muted-foreground">How this environment sends login codes, password resets, email verification and invitations.</DialogDescription>
      <form className="space-y-4" onSubmit={submit}>
        <fieldset disabled={busy} className="min-w-0 space-y-4">
          <RadioCards name="provider" label="Provider" value={d.provider} onChange={v => { setError(''); set({ provider: v as Provider }) }}
            options={(Object.keys(PROVIDERS) as Provider[]).map(p => ({ value: p, label: PROVIDERS[p].label, description: PROVIDERS[p].description }))} />
          <CopyFrom path={path} onCopy={from => setD(prev => copySettings(prev, from))} />

          {d.provider === 'webhook' && <>
            <Field id="webhook-url" label="Webhook URL" hint="Must be HTTPS. HTTP is allowed only for localhost.">
              <Input id="webhook-url" name="webhook_url" type="url" required autoComplete="off" value={d.webhook_url} onChange={e => set({ webhook_url: e.target.value })} placeholder="https://mail.example.com/send" />
            </Field>
            <Field id="webhook-token" label="Webhook token" hint={<>Sent as <code className="text-[10px]">Authorization: Bearer &lt;token&gt;</code> with every delivery request.</>}>
              <Input id="webhook-token" name="webhook_token" type="password" required autoComplete="new-password" value={d.webhook_token} onChange={e => set({ webhook_token: e.target.value })} placeholder={existing ? '(enter new token)' : 'Bearer authentication secret'} />
            </Field>
          </>}

          {d.provider !== 'webhook' && <SenderFields d={d} set={set} />}
          {d.provider === 'smtp' && <SMTPFields d={d} set={set} kept={kept} moved={!kept && !!existing?.has_secret && existing.provider === 'smtp' && !!d.smtp_username.trim()} required={needsSecret(d, existing)} />}
          {d.provider === 'resend' && <Field id="api-key" label="API key" hint={kept ? 'Leave blank to keep the stored key.' : <>Create a sending key at resend.com. The sender domain must be verified there.</>}>
            <Input id="api-key" type="password" autoComplete="off" required={!kept} value={d.api_key} onChange={e => set({ api_key: e.target.value })} placeholder={kept ? '(unchanged)' : 're_…'} />
          </Field>}

          <InvitationField d={d} set={set} hostedURL={hostedURL} />
        </fieldset>
        {error && <ErrorState error={error} />}
        {needsKey && <p role="note" className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
          Passwords and API keys are stored encrypted. Set <code>IAMKIT_ENCRYPTION_KEY</code> on the server (see the configuration reference) and restart it, or use a webhook or SMTP without authentication.
        </p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={close}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </form>
      {discarding && <ConfirmDialog title="Discard changes?" confirmLabel="Discard" description="Your changes to the delivery settings have not been saved."
        onClose={() => setDiscarding(false)} confirm={async () => onClose()} />}
    </DialogContent>
  </Dialog>
}

// InvitationField is the page an invitation email links to, with what it
// is for and what an empty value does for the chosen provider.
function InvitationField({ d, set, hostedURL }: { d: DeliveryDraft; set: (p: Partial<DeliveryDraft>) => void; hostedURL: string }) {
  const webhook = d.provider === 'webhook'
  const empty = webhook
    ? 'Empty: your webhook gets the token but no link.'
    : 'Empty: the email links to IAMKit’s hosted invitation page.'
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor="invitation-url">Invitation page (optional)</label>
    <p id="invitation-url-about" className="text-xs text-muted-foreground">
      When you invite someone to an organization, IAMKit emails them a link to this page, where they accept: a new person creates an account, an existing one joins the organization.
    </p>
    <Input id="invitation-url" type="url" autoComplete="off" aria-describedby="invitation-url-about invitation-url-hint" value={d.invitation_url} onChange={e => set({ invitation_url: e.target.value })}
      placeholder={webhook ? 'https://app.example.com/join' : hostedURL || 'https://app.example.com/join'} />
    <div className="flex flex-wrap items-start justify-between gap-2">
      <p id="invitation-url-hint" className="text-xs text-muted-foreground">
        Your own page gets <code className="text-[10px]">?token=…</code> and posts it to <code className="text-[10px]">/identity/v1/invitations/accept</code>. {empty}
      </p>
      {hostedURL && d.invitation_url !== hostedURL && <Button type="button" variant="link" size="sm" className="h-auto shrink-0 p-0 text-xs" onClick={() => set({ invitation_url: hostedURL })}>Use hosted invite page</Button>}
    </div>
  </div>
}

function SenderFields({ d, set }: { d: DeliveryDraft; set: (p: Partial<DeliveryDraft>) => void }) {
  return <div className="grid gap-4 sm:grid-cols-2">
    <Field id="from-email" label="From address">
      <Input id="from-email" type="email" required value={d.from_email} onChange={e => set({ from_email: e.target.value })} placeholder="no-reply@acme.com" />
    </Field>
    <Field id="from-name" label="From name (optional)">
      <Input id="from-name" maxLength={100} value={d.from_name} onChange={e => set({ from_name: e.target.value })} placeholder="Acme" />
    </Field>
    <div className="sm:col-span-2">
      <Field id="reply-to" label="Reply-to (optional)">
        <Input id="reply-to" type="email" value={d.reply_to} onChange={e => set({ reply_to: e.target.value })} placeholder="support@acme.com" />
      </Field>
    </div>
  </div>
}

function SMTPFields({ d, set, kept, moved, required }: { d: DeliveryDraft; set: (p: Partial<DeliveryDraft>) => void; kept: boolean; moved: boolean; required: boolean }) {
  const [preset, setPreset] = useState('')
  const hint = SMTP_PRESETS.find(p => p.id === preset)?.hint
  return <>
    <Field id="smtp-preset" label="Service" hint={hint}>
      <select id="smtp-preset" className={selectClass} value={preset} onChange={e => {
        setPreset(e.target.value)
        const p = SMTP_PRESETS.find(x => x.id === e.target.value)
        if (p) set({ smtp_host: p.host, smtp_port: String(p.port), smtp_tls: p.tls, smtp_username: p.username ?? '' })
      }}>
        <option value="">Other server</option>
        {SMTP_PRESETS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
      </select>
    </Field>
    <div className="grid gap-4 sm:grid-cols-[1fr_6rem_8rem]">
      <Field id="smtp-host" label="Host">
        <Input id="smtp-host" required value={d.smtp_host} onChange={e => set({ smtp_host: e.target.value })} placeholder="smtp.example.com" />
      </Field>
      <Field id="smtp-port" label="Port">
        <Input id="smtp-port" type="number" min={1} max={65535} required value={d.smtp_port} onChange={e => set({ smtp_port: e.target.value, smtp_tls: e.target.value === '465' ? 'tls' : e.target.value === '587' ? 'starttls' : d.smtp_tls })} />
      </Field>
      <Field id="smtp-tls" label="Encryption">
        <select id="smtp-tls" className={selectClass} value={d.smtp_tls} onChange={e => set({ smtp_tls: e.target.value as DeliveryDraft['smtp_tls'] })}>
          <option value="starttls">STARTTLS</option><option value="tls">TLS</option>
        </select>
      </Field>
    </div>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field id="smtp-username" label="Username (optional)">
        <Input id="smtp-username" autoComplete="off" value={d.smtp_username} onChange={e => set({ smtp_username: e.target.value })} />
      </Field>
      <Field id="smtp-password" label="Password" hint={kept ? 'Leave blank to keep the stored password.' : moved ? 'Re-enter the password: a stored one is only used with the same server and username.' : d.smtp_username.trim() ? undefined : 'Only with a username.'}>
        <Input id="smtp-password" type="password" autoComplete="new-password" required={required} disabled={!d.smtp_username.trim()} value={d.smtp_password} onChange={e => set({ smtp_password: e.target.value })} placeholder={kept ? '(unchanged)' : ''} />
      </Field>
    </div>
  </>
}

interface Environment { id: string; name: string }

// CopyFrom fills the form with another environment's settings of the same
// project; secrets are not copied.
function CopyFrom({ path, onCopy }: { path: string; onCopy: (c: DeliveryConfig) => void }) {
  const { project, environment } = useParams()
  const [envs, setEnvs] = useState<Environment[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    if (!project) return
    api.list<Environment>(`/projects/${project}/environments?limit=100`).then(r => setEnvs(r.data.filter(e => e.id !== environment))).catch(() => {})
  }, [project, environment, path])
  if (envs.length === 0) return null
  return <div className="space-y-1">
    <select aria-label="Copy from environment" className={selectClass} value="" onChange={async e => {
      const id = e.target.value
      if (!id) return
      setError('')
      try {
        onCopy(await api.get<DeliveryConfig>(`/environments/${id}/delivery`))
        toast.success('Settings copied. Enter the secret, then save.')
      } catch (err) { setError(err instanceof ApiError && err.status === 404 ? 'That environment has no delivery settings.' : message(err)) }
    }}>
      <option value="">Copy from environment…</option>
      {envs.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
    </select>
    {error && <p className="text-xs text-destructive">{error}</p>}
  </div>
}
