import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Ban, KeyRound, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, CopyField, CopyText, DataTable, EmptyState, ErrorState, PageHeader, Time } from '@/components/library/patterns'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
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
  const operators = useList<{ id: string; email: string }>('/operators?limit=200')
  const emails = useMemo(() => new Map(operators.data.map(o => [o.id, o.email])), [operators.data])
  const { principal } = useAuth()
  const [secret, setSecret] = useState<Credential | null>(null)
  const [target, setTarget] = useState<Key | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [ttl, setTtl] = useState('24h')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <div className="space-y-6"><PageHeader title="Management API keys" description="For trusted server-side automation only." actions={<Button onClick={() => setShowCreate(true)}><Plus /> Create key</Button>} />
    <DataTable columns={['Key', 'Operator', { header: 'Expires', nowrap: true }, 'Status', 'Actions']} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title="No API keys" description="Create a key to call the management API from your servers or CI." />}
      rows={list.data.map(k => {
        const [label, tone] = k.revoked_at ? ['Revoked', 'bg-destructive/10 text-destructive'] : Date.parse(k.expires_at) <= Date.now() ? ['Expired', 'bg-muted text-muted-foreground'] : ['Active', 'bg-success/10 text-success']
        const email = emails.get(k.operator_id)
        return [
          <CopyText value={k.id} short label="Copy key ID" />,
          k.operator_id === principal?.operator_id ? <span>You{email && <span className="block text-xs text-muted-foreground">{email}</span>}</span> : email ?? <CopyText value={k.operator_id} short label="Copy operator ID" />,
          <Time value={k.expires_at} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          !k.revoked_at && (principal?.role === 'owner' || principal?.operator_id === k.operator_id) && <RowActions label={`Actions for key ${k.id.slice(0, 8)}`} actions={[{ label: 'Revoke key', icon: <Ban />, destructive: true, onSelect: () => setTarget(k) }]} />,
        ]
      })} />
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
    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}><DialogContent><DialogTitle className="font-semibold">Save your API key</DialogTitle><DialogDescription className="text-muted-foreground">This secret is shown once. Store it securely on your server, never in frontend code.</DialogDescription><CopyField label="API key" value={secret.secret} /><p className="text-xs">Expires {new Date(secret.expires_at).toLocaleString()}</p><Button onClick={() => setSecret(null)}>I have saved the key</Button></DialogContent></Dialog>}
    {target && <ConfirmDialog title="Revoke this API key?" description="Servers and scripts using it lose access immediately. This cannot be undone." confirmLabel="Revoke key" onClose={() => setTarget(null)} confirm={async () => { await api.delete(`/keys/${target.id}`); toast.success('API key revoked'); list.reload() }} />}
  </div>
}
/** GET /password: the caller's own password state (management.PasswordStatus). */
interface PasswordStatus { set: boolean; usable: boolean; fresh: boolean; mode: 'enabled' | 'break_glass' | 'disabled' }
export function SettingsPage() {
  const { options, logout } = useAuth()
  const [status, setStatus] = useState<PasswordStatus | null>(null)
  const [loadError, setLoadError] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  const load = useCallback(async () => {
    setLoadError('')
    try { setStatus(await api.get<PasswordStatus>('/password')) } catch (e) { setLoadError(message(e)) }
  }, [])
  useEffect(() => { if (options?.password) void load() }, [options?.password, load])
  const header = <PageHeader title="Account settings" description="Manage your operator console password." />
  if (options && !options.password) return <div className="space-y-6">{header}<Card className="max-w-lg space-y-2 p-6"><h2 className="font-mono font-medium">Password sign-in is disabled</h2><p className="text-sm text-muted-foreground">This deployment signs operators in with single sign-on{options.providers.length > 0 && <> ({options.providers.map(p => p.name).join(', ')})</>}. Your password is managed by your identity provider.</p></Card></div>
  if (loadError) return <div className="space-y-6">{header}<ErrorState error={loadError} retry={load} /></div>
  if (!status) return <div className="space-y-6">{header}<p role="status" className="text-sm text-muted-foreground">Loading…</p></div>
  if (!status.usable) return <div className="space-y-6">{header}<Card className="max-w-lg space-y-2 p-6"><h2 className="font-mono font-medium">You sign in with single sign-on</h2><p className="text-sm text-muted-foreground">Passwords are emergency access in this deployment. A workspace owner can grant it to you from the Operators page.</p></Card></div>
  // Proof for the change: the current password, or a recent sign-in when
  // none is set (or after single sign-on, to replace a forgotten one).
  const needsCurrent = status.set && !status.fresh
  if (!status.set && !status.fresh) return <div className="space-y-6">{header}<Card className="max-w-lg space-y-3 p-6"><h2 className="font-mono font-medium">Set a password</h2><p className="text-sm text-muted-foreground">To set a password, sign in again first. For your security this is only possible within a few minutes of signing in.</p><Button onClick={() => void logout()}>Sign in again</Button></Card></div>
  return <div className="space-y-6">{header}<Card className="max-w-lg p-6"><form className="space-y-4" onSubmit={async event => {
    event.preventDefault(); if (pending.current) return
    const form = event.currentTarget
    const data = new FormData(form)
    const password = String(data.get('password'))
    if (password !== data.get('confirm')) { setError('Passwords do not match.'); return }
    const bytes = new TextEncoder().encode(password).length
    if (bytes < 12 || bytes > 72) { setError('Password must be 12–72 characters long.'); return }
    const current = needsCurrent ? String(data.get('current_password')) : ''
    pending.current = true; setBusy(true); setError('')
    try {
      await api.post('/password', current ? { current_password: current, password } : { password })
      form.reset(); toast.success(status.set ? 'Password updated. Your other sessions were signed out.' : 'Password set')
      void load()
    } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
  }}><h2 className="font-mono font-medium">{status.set ? 'Change password' : 'Set a password'}</h2><p className="text-sm text-muted-foreground">Use a unique password between 12 and 72 characters long.{status.set && ' Your other console sessions will be signed out.'}</p>
    {needsCurrent && <div className="space-y-1.5"><label htmlFor="current-password">Current password</label><Input id="current-password" name="current_password" type="password" autoComplete="current-password" required disabled={busy} /></div>}
    <div className="space-y-1.5"><label htmlFor="new-password">New password</label><Input id="new-password" name="password" type="password" autoComplete="new-password" required disabled={busy} /></div><div className="space-y-1.5"><label htmlFor="confirm-password">Confirm password</label><Input id="confirm-password" name="confirm" type="password" autoComplete="new-password" required disabled={busy} /></div>{error && <ErrorState error={error} />}<Button type="submit" disabled={busy}>{busy ? 'Saving…' : status.set ? 'Update password' : 'Set password'}</Button></form></Card></div>
}
