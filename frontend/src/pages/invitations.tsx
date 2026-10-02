import { useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Check, Copy, MailPlus, Plus, RotateCw, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { useOrganization } from './organization-layout'
import { ConfirmDialog, DataTable, EmptyState, ErrorState, Time } from '@/components/library/patterns'
import { RowActions } from '@/components/ui/menu'
import { t } from '@/lib/i18n'

export type InvitationStatus = 'pending' | 'accepted' | 'revoked' | 'expired'

export interface Invitation {
  id: string; organization_id: string; email: string
  role_ids: string[]; group_ids: string[]; inviter: string
  expires_at: string; accepted_at: string | null; accepted_user_id?: string
  revoked_at: string | null; created_at: string; status: InvitationStatus
}

interface Issued extends Invitation { token: string; link?: string; delivery: 'sent' | 'failed' | 'skipped' }

const statusStyle: Record<InvitationStatus, string> = {
  pending: 'bg-warning/10 text-warning',
  accepted: 'bg-success/10 text-success',
  revoked: 'bg-muted text-muted-foreground',
  expired: 'bg-muted text-muted-foreground',
}

function StatusBadge({ status }: { status: InvitationStatus }) {
  return <Badge variant="secondary" className={statusStyle[status]}>{status[0].toUpperCase() + status.slice(1)}</Badge>
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return <div className="space-y-1">
    <div className="text-xs font-medium text-muted-foreground">{label}</div>
    <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
      <code className="min-w-0 flex-1 break-all text-xs">{value}</code>
      <Button variant="ghost" size="icon" aria-label={t('Copy {{field}}', { field: label })} onClick={async () => {
        try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }
        catch { toast.error(t('Copy failed')) }
      }}>{copied ? <Check className="size-4" /> : <Copy className="size-4" />}</Button>
    </div>
  </div>
}

const manualGroups = { source: 'manual' }

/** Picks several ids with SearchSelect, remembering labels for the chips. */
function MultiPick({ label, placeholder, path, params, values, onChange, disabled }: { label: string; placeholder: string; path: string; params?: Record<string, string>; values: string[]; onChange: (v: string[]) => void; disabled: boolean }) {
  const labels = useRef(new Map<string, string>())
  const [reset, setReset] = useState(0)
  const map = (item: Record<string, unknown>) => {
    const option = { id: String(item.id), label: String(item.name || item.id) }
    labels.current.set(option.id, option.label)
    return option
  }
  const id = `invite-${label.toLowerCase()}`
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{label}</label>
    <SearchSelect key={reset} id={id} name={id} path={path} params={params} mapItem={map} disabled={disabled} placeholder={placeholder}
      onChange={v => { if (v && !values.includes(v)) onChange([...values, v]); setReset(r => r + 1) }} />
    {values.length > 0 && <div className="flex flex-wrap gap-1.5">
      {values.map(v => <Badge key={v} variant="secondary" className="gap-1">
        {labels.current.get(v) ?? v}
        <button type="button" aria-label={t('Remove {{value}}', { value: labels.current.get(v) ?? v })} onClick={() => onChange(values.filter(x => x !== v))}><X className="size-3" /></button>
      </Badge>)}
    </div>}
  </div>
}

function InviteDialog({ base, path, onClose, onIssued }: { base: string; path: string; onClose: () => void; onIssued: (i: Issued) => void }) {
  const [email, setEmail] = useState('')
  const [roles, setRoles] = useState<string[]>([])
  const [groups, setGroups] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle>{t('Invite member')}</DialogTitle>
      <DialogDescription>{t('The invitee joins with these roles and groups once they accept. Invitations expire after 7 days.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault()
        setBusy(true); setError('')
        try {
          onIssued(await api.post<Issued>(path, { email: email.trim(), role_ids: roles, group_ids: groups }))
        } catch (e) { setError(message(e)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor="invite-email">{t('Email')}</label>
          <Input id="invite-email" type="email" required disabled={busy} value={email} onChange={e => setEmail(e.target.value)} autoComplete="off" />
        </div>
        <MultiPick label={t('Roles')} placeholder={t('Add a role…')} path={`${base}/roles`} values={roles} onChange={setRoles} disabled={busy} />
        <MultiPick label={t('Groups')} placeholder={t('Add a group…')} path={`${path.replace(/\/invitations$/, '')}/groups`} params={manualGroups} values={groups} onChange={setGroups} disabled={busy} />
        <p className="text-xs text-muted-foreground">{t('Only operator-managed groups are listed: a directory controls its own groups\' members.')}</p>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Sending…') : t('Send invitation')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

const deliveryText: Record<Issued['delivery'], string> = {
  sent: t('The invitation was sent to the delivery webhook.'),
  failed: t('The delivery webhook failed. Share the link or token below with the invitee yourself.'),
  skipped: t('No delivery webhook is configured. Share the link or token below with the invitee yourself.'),
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

export function InvitationsPage() {
  const { environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/invitations`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const orgName = useOrganization().org.name
  const [status, setStatus] = useState('')
  const extraParams = useMemo(() => (status ? { status } : undefined), [status])
  const list = usePaginatedList<Invitation>(path, { extraParams })
  const [inviting, setInviting] = useState(false)
  const [issued, setIssued] = useState<Issued | null>(null)
  const [revoking, setRevoking] = useState<Invitation | null>(null)
  const [resending, setResending] = useState('')

  async function resend(inv: Invitation) {
    setResending(inv.id)
    try {
      setIssued(await api.post<Issued>(`${path}/${inv.id}/resend`))
      list.reload()
    } catch (e) { toast.error(message(e)) } finally { setResending('') }
  }

  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold">{t('Invitations to {{orgName}}', { orgName })}</h2>
        <p className="max-w-2xl text-sm text-muted-foreground">{t('Invite people by email. New accounts set a password when accepting, unless the organization enforces SSO for their domain.')}</p>
      </div>
      {canWrite && <Button onClick={() => setInviting(true)}><Plus />{t('Invite member')}</Button>}
    </div>

    <PaginationBar state={list} noun="invitations" placeholder={t('Search by email…')} />

    <select aria-label={t('Filter by status')} className="h-8 rounded-md border border-input bg-background px-2 text-sm" value={status} onChange={e => setStatus(e.target.value)}>
      <option value="">{t('All statuses')}</option>
      <option value="pending">{t('Pending')}</option>
      <option value="accepted">{t('Accepted')}</option>
      <option value="expired">{t('Expired')}</option>
      <option value="revoked">{t('Revoked')}</option>
    </select>

    <DataTable
      columns={[t('Email'), t('Status'), { header: t('Access'), hideBelow: 'md' }, { header: t('Expires'), hideBelow: 'sm', nowrap: true }, ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={<EmptyState icon={<MailPlus />} title={t('No invitations')} description={t('Invite people by email; they join the organization when they accept.')} />}
      rows={list.data.map(inv => [
        <span className="font-medium">{inv.email}</span>,
        <StatusBadge status={inv.status} />,
        <span className="text-sm text-muted-foreground">{plural(inv.role_ids.length, 'role')} · {plural(inv.group_ids.length, 'group')}</span>,
        inv.status === 'accepted' && inv.accepted_at ? <Time value={inv.accepted_at} prefix={t('Accepted')} /> : <Time value={inv.expires_at} prefix={Date.parse(inv.expires_at) < Date.now() ? t('Expired') : t('Expires')} />,
        ...(canWrite ? [(inv.status === 'pending' || inv.status === 'expired') && <RowActions label={t('Actions for {{email}}', { email: inv.email })} actions={[
          { label: resending === inv.id ? t('Resending…') : t('Resend invitation'), icon: <RotateCw />, disabled: resending === inv.id, onSelect: () => resend(inv) },
          { label: t('Revoke invitation'), icon: <Trash2 />, destructive: true, onSelect: () => setRevoking(inv) },
        ]} />] : []),
      ])}
    />

    {inviting && <InviteDialog base={base} path={path} onClose={() => setInviting(false)} onIssued={i => { setInviting(false); setIssued(i); list.reload() }} />}

    {issued && <Dialog open onOpenChange={open => { if (!open) setIssued(null) }}>
      <DialogContent>
        <DialogTitle>{t('Invitation for {{email}}', { email: issued.email })}</DialogTitle>
        <DialogDescription>{t('{{deliveryText}} This is the only time the token is shown.', { deliveryText: deliveryText[issued.delivery] })}</DialogDescription>
        <div className="space-y-3">
          {issued.link && <CopyValue label={t('Link')} value={issued.link} />}
          <CopyValue label={t('Token')} value={issued.token} />
        </div>
        <div className="flex justify-end"><Button onClick={() => setIssued(null)}>{t('Done')}</Button></div>
      </DialogContent>
    </Dialog>}

    {revoking && <ConfirmDialog
      title={t('Revoke the invitation for {{email}}?', { email: revoking.email })}
      description={t('The link stops working immediately. You can invite them again later.')}
      confirmLabel={t('Revoke invitation')}
      onClose={() => setRevoking(null)}
      confirm={async () => { await api.delete(`${path}/${revoking.id}`); toast.success(t('Invitation revoked')); list.reload() }}
    />}
  </div>
}
