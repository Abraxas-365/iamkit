import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Mail, Globe, Shield, Clock, Pencil, Trash2, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, ErrorState, PageHeader } from '@/components/library/patterns'

interface DeliveryConfig {
  environment_id: string
  webhook_url: string
  has_token: boolean
  created_at: string
  updated_at: string
}

export default function NotificationsPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/delivery`
  const [config, setConfig] = useState<DeliveryConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)

  const load = () => {
    setLoading(true)
    setError('')
    api.get<DeliveryConfig>(path)
      .then(cfg => { setConfig(cfg); setLoading(false) })
      .catch(e => {
        if (e?.status === 404) { setConfig(null); setLoading(false) }
        else { setError(message(e)); setLoading(false) }
      })
  }
  useEffect(load, [path])

  if (loading) return <div className="space-y-6">
    <PageHeader title="Notifications" description="Configure how challenge codes (OTP, password reset) are delivered." />
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {[1, 2, 3].map(i => <Card key={i} className="animate-pulse"><CardContent className="pt-6"><div className="h-20 rounded-lg bg-muted" /></CardContent></Card>)}
    </div>
  </div>

  if (error) return <div className="space-y-6">
    <PageHeader title="Notifications" description="Configure how challenge codes (OTP, password reset) are delivered." />
    <ErrorState error={error} retry={load} />
  </div>

  return <div className="space-y-8">
    <PageHeader title="Notifications" description="Configure how challenge codes (OTP, password reset) are delivered." />

    {config ? (
      /* ── Configured state ── */
      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <CardDescription className="flex items-center gap-1.5">
                <Globe className="size-3.5" /> Endpoint
              </CardDescription>
              <CardTitle className="break-all font-mono text-sm font-normal">{config.webhook_url}</CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader>
              <CardDescription className="flex items-center gap-1.5">
                <Shield className="size-3.5" /> Authentication
              </CardDescription>
              <CardTitle className="flex items-center gap-2">
                {config.has_token
                  ? <Badge variant="secondary" className="bg-success/10 text-success">Bearer token configured</Badge>
                  : <Badge variant="destructive">No token</Badge>}
              </CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader>
              <CardDescription className="flex items-center gap-1.5">
                <Clock className="size-3.5" /> Last updated
              </CardDescription>
              <CardTitle className="text-sm font-normal">{new Date(config.updated_at).toLocaleString()}</CardTitle>
            </CardHeader>
          </Card>
        </div>

        {canWrite && (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <Pencil className="size-3.5" /> Update configuration
            </Button>
            <Button variant="outline" size="sm" className="text-destructive hover:bg-destructive/10" onClick={() => setRemoving(true)}>
              <Trash2 className="size-3.5" /> Remove
            </Button>
          </div>
        )}
      </div>
    ) : (
      /* ── Empty state ── */
      <Card className="mx-auto max-w-lg">
        <CardContent className="flex flex-col items-center py-12 text-center">
          <div className="mb-4 flex size-12 items-center justify-center rounded-full bg-muted">
            <Mail className="size-6 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-medium">No webhook configured</h2>
          <p className="mt-1 max-w-sm text-sm text-muted-foreground">
            Challenge codes will use the global <code className="rounded bg-muted px-1 py-0.5 text-xs">EMAIL_WEBHOOK_URL</code> if set. Configure a per-environment webhook to use a dedicated endpoint.
          </p>
          {canWrite && (
            <Button className="mt-6" onClick={() => setEditing(true)}>
              <Plus className="size-4" /> Configure webhook
            </Button>
          )}
        </CardContent>
      </Card>
    )}

    <Card className="border-dashed">
      <CardHeader>
        <CardDescription>How it works</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-6 sm:grid-cols-3">
          <div className="space-y-1.5">
            <p className="text-sm font-medium">1. User requests a code</p>
            <p className="text-xs text-muted-foreground">Login OTP, password reset or email verification triggers a challenge.</p>
          </div>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">2. IAMKit POSTs to your webhook</p>
            <p className="text-xs text-muted-foreground">A JSON payload with <code className="text-[10px]">email</code>, <code className="text-[10px]">purpose</code> and <code className="text-[10px]">code</code>, authenticated with a Bearer token.</p>
          </div>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">3. Your service sends the email</p>
            <p className="text-xs text-muted-foreground">Codes are single-use, valid for 5 minutes. Your service picks the template by purpose.</p>
          </div>
        </div>
      </CardContent>
    </Card>

    {editing && <DeliveryForm path={path} existing={config} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); load() }} />}
    {removing && <ConfirmDialog title="Remove delivery config?" description="Challenge codes for this environment will fall back to the global EMAIL_WEBHOOK_URL." onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success('Delivery config removed'); load() }} />}
  </div>
}

function DeliveryForm({ path, existing, onClose, onSaved }: { path: string; existing: DeliveryConfig | null; onClose: () => void; onSaved: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)

  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle className="pr-6 text-base font-semibold">{existing ? 'Update' : 'Configure'} webhook</DialogTitle>
      <DialogDescription className="text-muted-foreground">IAMKit will POST challenge codes to this endpoint with the token as a Bearer header.</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault()
        if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data = {
          webhook_url: String(form.get('webhook_url') ?? '').trim(),
          webhook_token: String(form.get('webhook_token') ?? '').trim(),
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
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
