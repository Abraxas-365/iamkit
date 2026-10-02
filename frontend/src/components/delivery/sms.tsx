import { useEffect, useRef, useState } from 'react'
import { MessageSquare, Pencil, Plus, Send, Trash2, CircleCheck, CircleX, CircleDashed } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import type { Attempt } from '@/lib/delivery'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardAction } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, ErrorState, RadioCards } from '@/components/library/patterns'
import { formatDateTime, t } from '@/lib/i18n'

/** GET /sms (authentication.SMSConfig). Secrets are never returned. */
export interface SMSConfig {
  provider: 'twilio' | 'webhook'
  account_sid?: string
  from_number?: string
  messaging_service_sid?: string
  webhook_url?: string
  has_secret: boolean
  updated_at: string
}

/** GET /sms/status (authentication.SMSStatus). */
export interface SMSStatus { configured: boolean; provider: string; last_attempt: Attempt | null; last_failure: Attempt | null }

type Draft = { provider: 'twilio' | 'webhook'; account_sid: string; auth_token: string; from_number: string; messaging_service_sid: string; webhook_url: string; webhook_token: string }

function draftFrom(c: SMSConfig | null): Draft {
  return { provider: c?.provider ?? 'twilio', account_sid: c?.account_sid ?? '', auth_token: '', from_number: c?.from_number ?? '', messaging_service_sid: c?.messaging_service_sid ?? '', webhook_url: c?.webhook_url ?? '', webhook_token: '' }
}

/** smsBody sends only the chosen provider's fields. */
export function smsBody(d: Draft) {
  return d.provider === 'twilio'
    ? { provider: 'twilio', account_sid: d.account_sid.trim(), auth_token: d.auth_token.trim(), from_number: d.from_number.trim(), messaging_service_sid: d.messaging_service_sid.trim() }
    : { provider: 'webhook', webhook_url: d.webhook_url.trim(), webhook_token: d.webhook_token.trim() }
}

function outcome(a: Attempt) {
  if (a.delivered) return `Delivered in ${a.latency_ms} ms`
  return `${a.reason || t('Delivery failed')}${a.status ? ` (HTTP ${a.status})` : ''}`
}

/** SMSCard shows and edits the environment's SMS provider, used for SMS
 * second-factor codes and phone confirmation. */
export function SMSCard({ environment, canWrite }: { environment: string; canWrite: boolean }) {
  const path = `/environments/${environment}/sms`
  const [config, setConfig] = useState<SMSConfig | null>(null)
  const [status, setStatus] = useState<SMSStatus | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [testing, setTesting] = useState(false)
  const load = () => {
    setError('')
    Promise.all([
      api.get<SMSConfig>(path).catch(e => { if (e?.status === 404) return null; throw e }),
      api.get<SMSStatus>(`${path}/status`),
    ]).then(([c, s]) => { setConfig(c); setStatus(s) }).catch(e => setError(message(e)))
  }
  useEffect(load, [path])

  return <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2 text-base"><MessageSquare className="size-4" /> SMS</CardTitle>
      <CardDescription>{t('Texts SMS second-factor codes and phone confirmations. Email delivery never receives them; without a provider the SMS factor cannot be used.')}</CardDescription>
      {config && <CardAction><Badge variant="outline">{config.provider === 'twilio' ? t('Twilio') : t('Webhook')}</Badge></CardAction>}
    </CardHeader>
    <CardContent className="space-y-4 text-sm">
      {error ? <ErrorState error={error} retry={load} /> : !status ? <div className="h-16 animate-pulse rounded-lg bg-muted" /> : <>
        {config ? <div className="space-y-1">
          {config.provider === 'twilio' ? <>
            <p>{t('Account')} <span className="font-mono text-xs">{config.account_sid}</span></p>
            <p>{config.messaging_service_sid ? <>{t('Messaging service')} <span className="font-mono text-xs">{config.messaging_service_sid}</span></> : <>{t('From')} <span className="font-mono">{config.from_number}</span></>}</p>
          </> : <p className="break-all font-mono text-xs">{config.webhook_url}</p>}
          {config.has_secret ? <Badge variant="secondary" className="bg-success/10 text-success">{config.provider === 'twilio' ? t('Auth token stored') : t('Signing token stored')}</Badge> : <Badge variant="destructive">{t('No secret')}</Badge>}
        </div> : <p className="text-muted-foreground">{t('Not configured.')}</p>}
        {status.last_attempt ? <div className="flex items-start gap-2">
          {status.last_attempt.delivered ? <CircleCheck className="mt-0.5 size-4 text-success" /> : <CircleX className="mt-0.5 size-4 text-destructive" />}
          <div><p className="font-medium">{outcome(status.last_attempt)}</p><p className="text-xs text-muted-foreground"><code>{status.last_attempt.purpose}</code> · {formatDateTime(status.last_attempt.at)}</p></div>
        </div> : <p className="flex items-center gap-2 text-muted-foreground"><CircleDashed className="size-4" /> {t('No text messages yet.')}</p>}
        {canWrite && <div className="flex flex-wrap gap-2">
          {config ? <>
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil className="size-3.5" /> {t('Update')}</Button>
            <Button variant="outline" size="sm" onClick={() => setTesting(true)}><Send className="size-3.5" /> {t('Send test SMS')}</Button>
            <Button variant="outline" size="sm" className="text-destructive hover:bg-destructive/10" onClick={() => setRemoving(true)}><Trash2 className="size-3.5" /> {t('Remove')}</Button>
          </> : <Button size="sm" onClick={() => setEditing(true)}><Plus className="size-3.5" /> {t('Configure SMS')}</Button>}
        </div>}
      </>}
    </CardContent>
    {editing && <SMSForm path={path} existing={config} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); load() }} />}
    {removing && <ConfirmDialog title={t('Remove the SMS provider?')} description={t('SMS codes stop being sent: users whose only factor is SMS will need a recovery code or a reset.')} confirmLabel={t('Remove provider')} onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success(t('SMS provider removed')); load() }} />}
    {testing && <SMSTestDialog path={path} onClose={() => { setTesting(false); load() }} />}
  </Card>
}

function SMSForm({ path, existing, onClose, onSaved }: { path: string; existing: SMSConfig | null; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<Draft>(() => draftFrom(existing))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  const set = (patch: Partial<Draft>) => setD(prev => ({ ...prev, ...patch }))
  const kept = !!existing?.has_secret && existing.provider === d.provider
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent className="sm:max-w-lg">
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? t('Update') : t('Configure')} SMS</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Where this environment sends text messages. Secrets are stored encrypted and never shown again.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        pending.current = true; setBusy(true); setError('')
        try { await api.put(path, smsBody(d)); toast.success(t('SMS settings saved')); onSaved() }
        catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <RadioCards name="provider" label={t('Provider')} value={d.provider} onChange={v => set({ provider: v as Draft['provider'] })} disabled={busy} options={[
          { value: 'twilio', label: t('Twilio'), description: t('Messages API with your account SID and auth token.') },
          { value: 'webhook', label: t('Webhook'), description: t('Your HTTPS endpoint receives {phone, purpose, code, body}, signed.') },
        ]} />
        {d.provider === 'twilio' ? <>
          <Labeled id="sms-sid" label={t('Account SID')}><Input id="sms-sid" required disabled={busy} value={d.account_sid} onChange={e => set({ account_sid: e.target.value })} placeholder={t('AC…')} /></Labeled>
          <Labeled id="sms-token" label={t('Auth token')} hint={kept ? t('Leave blank to keep the stored token.') : undefined}><Input id="sms-token" type="password" autoComplete="off" required={!kept} disabled={busy} value={d.auth_token} onChange={e => set({ auth_token: e.target.value })} /></Labeled>
          <Labeled id="sms-from" label={t('From number')} hint={t('E.164, e.g. +15551234567. Or use a messaging service instead.')}><Input id="sms-from" disabled={busy} value={d.from_number} onChange={e => set({ from_number: e.target.value })} placeholder="+15551234567" /></Labeled>
          <Labeled id="sms-service" label={t('Messaging service SID (optional)')}><Input id="sms-service" disabled={busy} value={d.messaging_service_sid} onChange={e => set({ messaging_service_sid: e.target.value })} placeholder={t('MG…')} /></Labeled>
        </> : <>
          <Labeled id="sms-url" label={t('Endpoint URL')} hint={t('HTTPS; plain HTTP only on localhost.')}><Input id="sms-url" type="url" required disabled={busy} value={d.webhook_url} onChange={e => set({ webhook_url: e.target.value })} placeholder="https://sms.example.com/iamkit" /></Labeled>
          <Labeled id="sms-wtoken" label={t('Token')} hint={kept ? (t('Leave blank to keep the stored token.') + ' ') : t('Sent as the bearer token and used to sign each request (Standard Webhooks).')}><Input id="sms-wtoken" type="password" autoComplete="off" required={!kept} disabled={busy} value={d.webhook_token} onChange={e => set({ webhook_token: e.target.value })} /></Labeled>
        </>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

function Labeled({ id, label, hint, children }: { id: string; label: string; hint?: string; children: React.ReactNode }) {
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{label}</label>
    {children}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
}

function SMSTestDialog({ path, onClose }: { path: string; onClose: () => void }) {
  const [phone, setPhone] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Attempt | null>(null)
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle className="pr-6 text-base font-semibold">{t('Send test SMS')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Texts a message without a code through this environment\'s provider.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (busy) return
        setBusy(true); setError(''); setResult(null)
        try { setResult(await api.post<Attempt>(`${path}/test`, { phone: phone.trim() })) }
        catch (e) { setError(message(e)) } finally { setBusy(false) }
      }}>
        <Labeled id="sms-test-phone" label={t('Phone number')}><Input id="sms-test-phone" type="tel" required disabled={busy} value={phone} onChange={e => setPhone(e.target.value)} placeholder="+15551234567" /></Labeled>
        {result && <div role="status" className={`rounded-md border p-3 text-sm ${result.delivered ? 'border-success/30 bg-success/5' : 'border-destructive/30 bg-destructive/5'}`}>
          <p className="font-medium">{result.delivered ? t('Provider accepted the message') : t('Delivery failed')}</p><p className="text-xs text-muted-foreground">{outcome(result)}</p>
        </div>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Close')}</Button>
          <Button type="submit" disabled={busy}><Send className="size-3.5" /> {busy ? t('Sending…') : result ? t('Send again') : t('Send')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
