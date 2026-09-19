import { useRef, useState } from 'react'
import { Plus } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, ErrorState, ID, PageHeader, Status } from '@/components/library/patterns'

interface Operator { id: string; email: string; role: string; active: boolean }
interface Delegated { operator_id: string; key_id: string; secret: string; expires_at: string }

const roles = [
  { value: 'admin', label: 'Admin', description: 'Full read & write access to all projects, environments, and configuration.' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access. Cannot create, modify, or delete any resources.' },
]

const ttlOptions = [
  { label: '1 hour', value: '1h' },
  { label: '24 hours', value: '24h' },
  { label: '7 days', value: '168h' },
  { label: '30 days', value: '720h' },
  { label: '90 days', value: '2160h' },
  { label: '1 year', value: '8760h' },
  { label: 'No expiry', value: 'never' },
]

export default function OperatorsPage() {
  const list = useList<Operator>('/operators')
  const { principal } = useAuth()
  const isOwner = principal?.role === 'owner'
  const [search, setSearch] = useState('')
  const [add, setAdd] = useState(false)
  const [disable, setDisable] = useState<Operator | null>(null)
  const [secret, setSecret] = useState<Delegated | null>(null)
  const [role, setRole] = useState('admin')
  const [ttl, setTtl] = useState('24h')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)

  return <div className="space-y-6">
    <PageHeader title="Operators" description="Console operators and their workspace roles. Only owners can invite or disable operators." actions={isOwner && <Button onClick={() => { setAdd(true); setRole('admin'); setTtl('24h'); setError('') }}><Plus className="size-4" /> Invite operator</Button>} />
    <Input aria-label="Search operators" className="max-w-sm" placeholder="Filter by email…" value={search} onChange={e => setSearch(e.target.value)} />
    <DataTable columns={['Email', 'Role', 'Status', 'Operator ID', 'Actions']} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.filter(o => o.email.toLowerCase().includes(search.toLowerCase())).map(op => [
      op.email,
      <span className="capitalize">{op.role}</span>,
      <Status active={op.active} />,
      <ID value={op.id} />,
      isOwner && op.active && op.role !== 'owner' && <Button variant="destructive" size="sm" onClick={() => setDisable(op)}>Disable</Button>,
    ])} />

    {add && <Dialog open onOpenChange={open => { if (!open && !pending.current) setAdd(false) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">Invite operator</DialogTitle>
      <DialogDescription className="text-muted-foreground">The new operator will receive an API key. They can use it at <code className="text-xs">/setup</code> to set a console password.</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const email = String(new FormData(event.currentTarget).get('email') ?? '').trim()
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<Delegated>('/operators', { email, role, expires_in: ttl })
          setSecret(result); setAdd(false); list.reload()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invite-email">Email</label>
          <Input id="invite-email" name="email" type="email" required disabled={busy} />
        </div>
        <div className="space-y-2">
          <label className="text-sm font-medium">Role</label>
          {roles.map(r => (
            <label key={r.value} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${role === r.value ? 'border-primary bg-primary/5' : 'border-input hover:border-foreground/20'}`}>
              <input type="radio" name="role" value={r.value} checked={role === r.value} onChange={() => setRole(r.value)} className="mt-0.5 accent-primary" />
              <div>
                <p className="text-sm font-medium">{r.label}</p>
                <p className="text-xs text-muted-foreground">{r.description}</p>
              </div>
            </label>
          ))}
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invite-ttl">Key expires in</label>
          <select id="invite-ttl" className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={ttl} onChange={e => setTtl(e.target.value)}>
            {ttlOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={() => setAdd(false)}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Inviting…' : 'Invite'}</Button>
        </div>
      </form>
    </DialogContent></Dialog>}

    {disable && <ConfirmDialog title="Disable operator?" description={`${disable.email} will lose all access. Their management keys will be revoked.`} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`/operators/${disable.id}`); list.reload() }} />}

    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">Operator invited</DialogTitle>
        <DialogDescription className="text-muted-foreground">Share this API key with the operator. They can set their console password at <code className="text-xs">/setup</code>.</DialogDescription>
        <div className="space-y-2">
          <p className="text-sm">Operator ID</p>
          <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.operator_id}</code>
          <p className="text-sm">API key (shown once)</p>
          <code className="block break-all rounded-lg bg-muted p-3 text-xs select-all">{secret.secret}</code>
          <p className="text-xs text-muted-foreground">Expires {new Date(secret.expires_at).toLocaleString()}</p>
        </div>
        <Button onClick={() => setSecret(null)}>I have saved the key</Button>
      </DialogContent>
    </Dialog>}
  </div>
}
