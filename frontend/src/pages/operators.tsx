import { useRef, useState } from 'react'
import { Ban, Link2Off, Plus, UserCog } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, CopyField, DataTable, EmptyState, EntityRef, ErrorState, PageHeader, Status, Time } from '@/components/library/patterns'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'

interface Operator { id: string; email: string; role: string; active: boolean; sso_providers?: string[] | null; last_sso_login_at?: string | null }
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
  const list = usePaginatedList<Operator>('/operators')
  const { principal, options } = useAuth()
  const isOwner = principal?.role === 'owner'
  const providers = options?.providers ?? []
  const sso = providers.length > 0
  const password = options?.password !== false
  const names = new Map(providers.map(p => [p.id, p.name]))
  const [add, setAdd] = useState(false)
  const [disable, setDisable] = useState<Operator | null>(null)
  const [reset, setReset] = useState<Operator | null>(null)
  const [secret, setSecret] = useState<Delegated | null>(null)
  const [role, setRole] = useState('admin')
  const [ttl, setTtl] = useState('24h')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  const ssoHint = sso && `They can sign in with ${providers.map(p => p.name).join(' or ')} using this email.`
  const inviteHint = [ssoHint, password && <>They receive an API key to set a console password at <code className="text-xs">/setup</code>.</>, !password && 'Password sign-in is disabled; the API key is for the management API only.'].filter(Boolean)

  return <div className="space-y-6">
    <PageHeader title="Operators" description="Console operators and their workspace roles. Only owners can invite or disable operators." actions={isOwner && <Button onClick={() => { setAdd(true); setRole('admin'); setTtl('24h'); setError('') }}><Plus className="size-4" /> Invite operator</Button>} />
    <PaginationBar state={list} noun="operators" />
    <DataTable columns={['Operator', 'Role', ...(sso ? ['Single sign-on'] : []), 'Status', ...(isOwner ? ['Actions'] : [])]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<UserCog />} title="No operators yet" description="Invite teammates to help manage projects and environments." />}
      rows={list.data.map(op => {
        const linked = op.sso_providers ?? []
        const actions = [
          ...(linked.length > 0 ? [{ label: 'Reset SSO link', icon: <Link2Off />, destructive: true, onSelect: () => setReset(op) }] : []),
          ...(op.active && op.role !== 'owner' ? [{ label: 'Disable operator', icon: <Ban />, destructive: true, onSelect: () => setDisable(op) }] : []),
        ]
        return [
          <EntityRef name={op.email} id={op.id} secondary={op.id === principal?.operator_id ? 'You' : undefined} />,
          <Badge variant="secondary" className="capitalize">{op.role}</Badge>,
          ...(sso ? [linked.length > 0
            ? <span>{linked.map(id => names.get(id) ?? id).join(', ')}<span className="block text-xs text-muted-foreground">{op.last_sso_login_at ? <Time value={op.last_sso_login_at} prefix="Last sign-in" /> : 'Linked'}</span></span>
            : <span className="text-muted-foreground">Not linked</span>] : []),
          <Status active={op.active} label={op.active ? 'Active' : 'Disabled'} />,
          ...(isOwner ? [actions.length > 0 && <RowActions label={`Actions for ${op.email}`} actions={actions} />] : []),
        ]
      })} />

    {add && <Dialog open onOpenChange={open => { if (!open && !pending.current) setAdd(false) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">Invite operator</DialogTitle>
      <DialogDescription className="text-muted-foreground">{inviteHint.map((h, i) => <span key={i}>{i > 0 && ' '}{h}</span>)}</DialogDescription>
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

    {disable && <ConfirmDialog title={`Disable ${disable.email}?`} description="They are signed out of the console immediately and all their management API keys are revoked." confirmLabel="Disable operator" onClose={() => setDisable(null)} confirm={async () => { await api.delete(`/operators/${disable.id}`); toast.success('Operator disabled'); list.reload() }} />}

    {reset && <ConfirmDialog title={`Reset single sign-on for ${reset.email}?`} description="Their linked provider identities are removed and they are signed out of the console. Their next single sign-on links again by verified email." confirmLabel="Reset SSO link" onClose={() => setReset(null)} confirm={async () => { await api.delete(`/operators/${reset.id}/identities`); toast.success('Single sign-on link reset'); list.reload() }} />}

    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">Operator invited</DialogTitle>
        <DialogDescription className="text-muted-foreground">{ssoHint && <>{ssoHint} </>}{password ? <>Share this API key with the operator. They can set their console password at <code className="text-xs">/setup</code>.</> : 'This API key works with the management API only; share it only if they need API access.'}</DialogDescription>
        <div className="space-y-2">
          <CopyField label="API key (shown once)" value={secret.secret} />
          <p className="text-xs text-muted-foreground">Expires {new Date(secret.expires_at).toLocaleString()}</p>
        </div>
        <Button onClick={() => setSecret(null)}>I have saved the key</Button>
      </DialogContent>
    </Dialog>}
  </div>
}
