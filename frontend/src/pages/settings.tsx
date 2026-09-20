import { useRef, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, ErrorState, ID, PageHeader } from '@/components/library/patterns'
interface Key { id: string; operator_id: string; expires_at: string; revoked_at: string | null }
interface Credential { secret: string; expires_at: string }
const ttlOptions = [
  { label: '1 hour', value: '1h' },
  { label: '24 hours', value: '24h' },
  { label: '7 days', value: '168h' },
  { label: '30 days', value: '720h' },
  { label: '90 days', value: '2160h' },
  { label: '1 year', value: '8760h' },
  { label: 'No expiry', value: 'never' },
]
export function KeysPage() {
  const list = useList<Key>('/keys?limit=200')
  const { principal } = useAuth()
  const [secret, setSecret] = useState<Credential | null>(null)
  const [target, setTarget] = useState<Key | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [ttl, setTtl] = useState('24h')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <div className="space-y-6"><PageHeader title="Management API keys" description="For trusted server-side automation only." actions={<Button onClick={() => setShowCreate(true)}>Create key</Button>} />
    <DataTable columns={['Key ID', 'Operator', 'Expires', 'Status', 'Actions']} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(k => [<ID value={k.id} />, <ID value={k.operator_id} />, new Date(k.expires_at).toLocaleString(), k.revoked_at ? 'Revoked' : Date.parse(k.expires_at) <= Date.now() ? 'Expired' : 'Active', !k.revoked_at && (principal?.role === 'owner' || principal?.operator_id === k.operator_id) && <Button variant="destructive" size="sm" onClick={() => setTarget(k)}>Revoke</Button>])} />
    {showCreate && <Dialog open onOpenChange={open => { if (!open && !pending.current) setShowCreate(false) }}><DialogContent>
      <DialogTitle className="font-semibold">Create API key</DialogTitle>
      <DialogDescription className="text-muted-foreground">Choose how long this key should remain valid.</DialogDescription>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor="key-ttl">Expires in</label>
        <select id="key-ttl" className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={ttl} onChange={e => setTtl(e.target.value)}>{ttlOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select>
      </div>
      <div className="flex justify-end gap-2 border-t pt-4">
        <Button variant="outline" disabled={busy} onClick={() => setShowCreate(false)}>Cancel</Button>
        <Button disabled={busy} onClick={async () => { if (pending.current) return; pending.current = true; setBusy(true); try { setSecret(await api.post<Credential>('/keys', { expires_in: ttl })); setShowCreate(false); list.reload() } catch (e) { toast.error(message(e)) } finally { pending.current = false; setBusy(false) } }}>{busy ? 'Creating…' : 'Create key'}</Button>
      </div>
    </DialogContent></Dialog>}
    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}><DialogContent><DialogTitle className="font-semibold">Save your API key</DialogTitle><DialogDescription className="text-muted-foreground">This secret is shown once. Store it securely on your server, never in frontend code.</DialogDescription><code className="break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.secret}</code><p className="text-xs">Expires {new Date(secret.expires_at).toLocaleString()}</p><Button onClick={() => setSecret(null)}>I have saved the key</Button></DialogContent></Dialog>}
    {target && <ConfirmDialog title="Revoke API key?" description="Server integrations using this key will immediately lose access." onClose={() => setTarget(null)} confirm={async () => { await api.delete(`/keys/${target.id}`); list.reload() }} />}
  </div>
}
export function SettingsPage() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  return <div className="space-y-6"><PageHeader title="Account settings" description="Manage your operator console password." /><Card className="max-w-lg p-6"><form className="space-y-4" onSubmit={async event => {
    event.preventDefault(); if (pending.current) return
    const form = event.currentTarget
    const data = new FormData(form)
    const password = String(data.get('password'))
    if (password !== data.get('confirm')) { setError('Passwords do not match.'); return }
    const bytes = new TextEncoder().encode(password).length
    if (bytes < 12 || bytes > 72) { setError('Password must be 12–72 characters long.'); return }
    pending.current = true; setBusy(true); setError('')
    try { await api.post('/password', { password }); form.reset(); toast.success('Password updated') } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
  }}><h2 className="font-mono font-medium">Change password</h2><p className="text-sm text-muted-foreground">Use a unique password between 12 and 72 characters long.</p><div className="space-y-1.5"><label htmlFor="new-password">New password</label><Input id="new-password" name="password" type="password" autoComplete="new-password" required disabled={busy} /></div><div className="space-y-1.5"><label htmlFor="confirm-password">Confirm password</label><Input id="confirm-password" name="confirm" type="password" autoComplete="new-password" required disabled={busy} /></div>{error && <ErrorState error={error} />}<Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Update password'}</Button></form></Card></div>
}
