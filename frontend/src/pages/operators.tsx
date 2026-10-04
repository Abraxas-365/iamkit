import { useRef, useState } from 'react'
import { Ban, KeyRound, Link2Off, Plus, UserCog } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ConfirmDialog, CopyField, DataTable, EmptyState, EntityRef, ErrorState, PageHeader, Time } from '@/components/library/patterns'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { formatDateTime, language, rich, t } from '@/lib/i18n'

interface Operator { id: string; email: string; role: string; active: boolean; password_allowed?: boolean; sso_providers?: string[] | null; last_sso_login_at?: string | null }
interface Delegated { operator_id: string; key_id: string; secret: string; expires_at: string; reactivated?: boolean }

const roles = [
  { value: 'admin', label: t('Admin'), description: t('Full read & write access to all projects, environments, and configuration.') },
  { value: 'viewer', label: t('Viewer'), description: t('Read-only access. Cannot create, modify, or delete any resources.') },
]
// Role changes may also make an owner; invitations never do.
const allRoles = [
  { value: 'owner', label: t('Owner'), description: t('Everything an admin can do, plus inviting and disabling operators and changing their roles.') },
  ...roles,
]

function RoleOptions({ options, value, onChange, disabled }: { options: typeof allRoles; value: string; onChange: (role: string) => void; disabled?: (role: string) => boolean }) {
  return <div className="space-y-2">
    <label className="text-sm font-medium">{t('Role')}</label>
    {options.map(r => {
      const off = disabled?.(r.value) ?? false
      return <label key={r.value} className={`flex items-start gap-3 rounded-lg border p-3 transition-colors ${off ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${value === r.value ? 'border-primary bg-primary/5' : 'border-input hover:border-foreground/20'}`}>
        <input type="radio" name="role" value={r.value} checked={value === r.value} disabled={off} onChange={() => onChange(r.value)} className="mt-0.5 accent-primary" />
        <div>
          <p className="text-sm font-medium">{r.label}</p>
          <p className="text-xs text-muted-foreground">{r.description}</p>
        </div>
      </label>
    })}
  </div>
}

const ttlOptions = [
  { label: t('1 hour'), value: '1h' },
  { label: t('24 hours'), value: '24h' },
  { label: t('7 days'), value: '168h' },
  { label: t('30 days'), value: '720h' },
  { label: t('90 days'), value: '2160h' },
  { label: t('1 year'), value: '8760h' },
  { label: t('No expiry'), value: 'never' },
]

export default function OperatorsPage() {
  const list = usePaginatedList<Operator>('/operators')
  const { principal, options, reload: reloadAuth } = useAuth()
  const isOwner = principal?.role === 'owner'
  const providers = options?.providers ?? []
  const sso = providers.length > 0
  const password = options?.password !== false
  // break_glass: SSO is required except for operators an owner granted
  // emergency (password) access; only then does the grant matter.
  const breakGlass = sso && password && options?.password_mode === 'break_glass'
  const selfPassword = password && !breakGlass
  const names = new Map(providers.map(p => [p.id, p.name]))
  const [add, setAdd] = useState(false)
  const [email, setEmail] = useState('')
  const [change, setChange] = useState<Operator | null>(null)
  const [newRole, setNewRole] = useState('admin')
  const [disable, setDisable] = useState<Operator | null>(null)
  const [reset, setReset] = useState<Operator | null>(null)
  const [access, setAccess] = useState<Operator | null>(null)
  const [secret, setSecret] = useState<Delegated | null>(null)
  const [role, setRole] = useState('admin')
  const [ttl, setTtl] = useState('24h')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  const ssoHint = sso && t('They can sign in with {{providers}} using this email.', { providers: new Intl.ListFormat(language(), { type: 'disjunction' }).format(providers.map(p => p.name)) })
  const inviteHint = [ssoHint, selfPassword && <>{rich('They receive an API key to set a console password at {{code}}.', { code: <code className="text-xs">{'/setup'}</code> })}</>, !password && t('Password sign-in is disabled; the API key is for the management API only.'), breakGlass && t('Passwords are for emergency access only; the API key is for the management API until you allow it.')].filter(Boolean)
  // GET /operators returns every operator and ignores search and paging,
  // so the list is complete here. Disabled operators are not shown: inviting
  // the same email again reactivates them (the server starts them fresh).
  const active = list.data.filter(o => o.active)
  const needle = list.search.trim().toLowerCase()
  const shown = needle ? active.filter(o => o.email.toLowerCase().includes(needle)) : active
  const view = { ...list, data: shown, total: shown.length, from: shown.length ? 1 : 0, to: shown.length, hasPrev: false, hasNext: false }
  // The server refuses demoting the last active owner.
  const lastOwner = active.filter(o => o.role === 'owner').length <= 1
  const returning = list.data.some(o => !o.active && o.email.toLowerCase() === email.trim().toLowerCase())
  const openInvite = () => { setEmail(''); setAdd(true); setRole('admin'); setTtl('24h'); setError('') }

  return <div className="space-y-6">
    <PageHeader title={t('Operators')} description={t('Console operators and their workspace roles. Only owners can invite, disable or change the role of operators.')} actions={isOwner && <Button onClick={openInvite}><Plus className="size-4" /> {t('Invite operator')}</Button>} />
    <PaginationBar state={view} noun="operators" />
    <DataTable columns={[t('Operator'), t('Role'), ...(sso ? [t('Single sign-on')] : []), ...(isOwner ? [t('Actions')] : [])]} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<UserCog />} title={t('No operators yet')} description={t('Invite teammates to help manage projects and environments.')} />}
      rows={shown.map(op => {
        const linked = op.sso_providers ?? []
        // Removing one's own access would end this very session (and lock
        // out an owner without a linked identity): another owner does it.
        const self = op.id === principal?.operator_id
        const actions = [
          { label: t('Change role'), icon: <UserCog />, onSelect: () => { setChange(op); setNewRole(op.role); setError('') } },
          ...(breakGlass && !(self && op.password_allowed) ? [op.password_allowed
            ? { label: t('Remove emergency access'), icon: <KeyRound />, destructive: true, onSelect: () => setAccess(op) }
            : { label: t('Allow emergency access'), icon: <KeyRound />, onSelect: () => setAccess(op) }] : []),
          ...(linked.length > 0 ? [{ label: t('Reset SSO link'), icon: <Link2Off />, destructive: true, onSelect: () => setReset(op) }] : []),
          ...(op.role !== 'owner' ? [{ label: t('Disable operator'), icon: <Ban />, destructive: true, onSelect: () => setDisable(op) }] : []),
        ]
        return [
          <EntityRef name={op.email} id={op.id} secondary={op.id === principal?.operator_id ? t('You') : undefined} />,
          <span className="flex flex-wrap gap-1"><Badge variant="secondary" className="capitalize">{op.role}</Badge>{breakGlass && op.password_allowed && <Badge variant="outline">{t('Emergency access')}</Badge>}</span>,
          ...(sso ? [linked.length > 0
            ? <span>{linked.map(id => names.get(id) ?? id).join(', ')}<span className="block text-xs text-muted-foreground">{op.last_sso_login_at ? <Time value={op.last_sso_login_at} prefix={t('Last sign-in')} /> : t('Linked')}</span></span>
            : <span className="text-muted-foreground">{t('Not linked')}</span>] : []),
          ...(isOwner ? [actions.length > 0 && <RowActions label={t('Actions for {{email}}', { email: op.email })} actions={actions} />] : []),
        ]
      })} />

    {add && <Dialog open onOpenChange={open => { if (!open && !pending.current) setAdd(false) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Invite operator')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{inviteHint.map((h, i) => <span key={i}>{i > 0 && ' '}{h}</span>)}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const address = email.trim()
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<Delegated>('/operators', { email: address, role, expires_in: ttl })
          setSecret(result); setAdd(false); list.reload()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invite-email">{t('Email')}</label>
          <Input id="invite-email" name="email" type="email" required disabled={busy} value={email} onChange={e => setEmail(e.target.value)} />
          {returning && <p role="status" className="text-xs text-muted-foreground">{t('This operator was disabled. Inviting them again reactivates them with a new API key and a fresh start: earlier keys and sessions stay ended, emergency access is off, and their password and single sign-on links are cleared unless another workspace uses them.')}</p>}
        </div>
        <RoleOptions options={roles} value={role} onChange={setRole} />
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invite-ttl">{t('Key expires in')}</label>
          <select id="invite-ttl" className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={ttl} onChange={e => setTtl(e.target.value)}>
            {ttlOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={() => setAdd(false)}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{returning ? (busy ? t('Reactivating…') : t('Reactivate')) : (busy ? t('Inviting…') : t('Invite'))}</Button>
        </div>
      </form>
    </DialogContent></Dialog>}

    {change && <Dialog open onOpenChange={open => { if (!open && !pending.current) setChange(null) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Change role of {{email}}', { email: change.email })}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('The new role applies at once, to their console sessions and API keys too.')}{change.role === 'owner' && lastOwner && <> {t('A workspace keeps at least one owner: make someone else an owner first.')}</>}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current || newRole === change.role) return
        pending.current = true; setBusy(true); setError('')
        try {
          await api.put(`/operators/${change.id}/role`, { role: newRole })
          toast.success(t('Role changed')); setChange(null); list.reload()
          // Stepping down changes what this console may do.
          if (change.id === principal?.operator_id) void reloadAuth()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <RoleOptions options={allRoles} value={newRole} onChange={setNewRole} disabled={r => change.role === 'owner' && lastOwner && r !== 'owner'} />
        {change.id === principal?.operator_id && newRole !== 'owner' && <p className="text-sm text-muted-foreground">{t('You are changing your own role: you can no longer manage operators afterwards.')}</p>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={() => setChange(null)}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy || newRole === change.role}>{busy ? t('Saving…') : t('Change role')}</Button>
        </div>
      </form>
    </DialogContent></Dialog>}

    {disable && <ConfirmDialog title={t('Disable {{email}}?', { email: disable.email })} description={t('They are signed out of the console immediately and all their management API keys are revoked.')} confirmLabel={t('Disable operator')} onClose={() => setDisable(null)} confirm={async () => { await api.delete(`/operators/${disable.id}`); toast.success(t('Operator disabled')); list.reload() }} />}

    {reset && <ConfirmDialog title={t('Reset single sign-on for {{email}}?', { email: reset.email })} description={t('Their linked provider identities are removed and they are signed out of the console. Their next single sign-on links again by verified email.')} confirmLabel={t('Reset SSO link')} onClose={() => setReset(null)} confirm={async () => { await api.delete(`/operators/${reset.id}/identities`); toast.success(t('Single sign-on link reset')); list.reload() }} />}

    {access && (access.password_allowed
      ? <ConfirmDialog title={t('Remove emergency access for {{email}}?', { email: access.email })} description={t('They can no longer sign in with a password, and their password sessions end now. Single sign-on sessions stay.')} confirmLabel={t('Remove emergency access')} onClose={() => setAccess(null)} confirm={async () => { await api.put(`/operators/${access.id}/password-access`, { allowed: false }); toast.success(t('Emergency access removed')); list.reload() }} />
      : <ConfirmDialog title={t('Allow emergency access for {{email}}?', { email: access.email })} description={t('They can sign in with a password when single sign-on is unavailable. Keep this to one or two owners.')} confirmLabel={t('Allow emergency access')} onClose={() => setAccess(null)} confirm={async () => { await api.put(`/operators/${access.id}/password-access`, { allowed: true }); toast.success(t('Emergency access allowed')); list.reload() }} />)}

    {secret && <Dialog open onOpenChange={open => { if (!open) setSecret(null) }}>
      <DialogContent>
        <DialogTitle className="font-semibold">{secret.reactivated ? t('Operator reactivated') : t('Operator invited')}</DialogTitle>
        <DialogDescription className="text-muted-foreground">{ssoHint && <>{ssoHint} </>}{selfPassword ? <>{rich('Share this API key with the operator. They can set their console password at {{code}}.', { code: <code className="text-xs">{'/setup'}</code> })}</> : t('This API key works with the management API only; share it only if they need API access.')}</DialogDescription>
        <div className="space-y-2">
          <CopyField label={t('API key (shown once)')} value={secret.secret} />
          <p className="text-xs text-muted-foreground">{t('Expires {{time}}', { time: formatDateTime(secret.expires_at) })}</p>
        </div>
        <Button onClick={() => setSecret(null)}>{t('I have saved the key')}</Button>
      </DialogContent>
    </Dialog>}
  </div>
}
