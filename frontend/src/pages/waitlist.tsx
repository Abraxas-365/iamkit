import { useEffect, useId, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Check, ListPlus, MailCheck, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, EmptyState, ErrorState, PageHeader, Time, selectClass } from '@/components/library/patterns'
import { rich, t } from '@/lib/i18n'

export type WaitlistStatus = 'pending' | 'approved' | 'rejected' | 'completed'

/** authentication.WaitlistEntry. */
export interface WaitlistEntry {
  id: string; environment_id: string; email: string; name: string; locale: string
  status: WaitlistStatus
  created_at: string; decided_at: string | null; decided_by: string
  expires_at: string | null; completed_user_id: string
}

interface BulkResult { approved: number; skipped: number; more: boolean }

const tones: Record<WaitlistStatus, [string, string]> = {
  pending: [t('Pending'), 'bg-warning/10 text-warning'],
  approved: [t('Approved'), 'bg-success/10 text-success'],
  rejected: [t('Rejected'), 'bg-muted text-muted-foreground'],
  completed: [t('Signed up'), 'bg-primary/10 text-primary'],
}

function StatusBadge({ status }: { status: WaitlistStatus }) {
  const [label, tone] = tones[status] ?? [status, 'bg-muted text-muted-foreground']
  return <Badge variant="secondary" className={tone}>{label}</Badge>
}

/** approveAll approves every pending entry, 500 at a time, until IAMKit
 * reports no more (or a round decides nothing, which would loop forever). */
export async function approveAll(path: string, onProgress?: (approved: number) => void): Promise<{ approved: number; skipped: number }> {
  let approved = 0
  let skipped = 0
  for (;;) {
    const out = await api.post<BulkResult>(`${path}/approve`, { all_pending: true })
    approved += out.approved; skipped += out.skipped
    onProgress?.(approved)
    if (!out.more || out.approved === 0) return { approved, skipped }
  }
}

function RejectDialog({ entry, onClose, confirm }: { entry: WaitlistEntry; onClose: () => void; confirm: (notify: boolean) => Promise<void> }) {
  const id = useId()
  const [notify, setNotify] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">{t('Reject {{email}}?', { email: entry.email })}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{entry.status === 'approved' ? t('Their approval link stops working. They can join the waitlist again once you delete the entry.') : t('They will not be able to sign up. They can join the waitlist again once you delete the entry.')}</DialogDescription>
      <div className="flex items-start gap-2">
        <input id={id} type="checkbox" className="mt-0.5 size-4" checked={notify} disabled={busy} onChange={e => setNotify(e.target.checked)} />
        <label htmlFor={id} className="text-sm">{t('Notify them by email')}<span className="block text-xs text-muted-foreground">{t('Without this the rejection is silent.')}</span></label>
      </div>
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2">
        <Button variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
        <Button variant="destructive" disabled={busy} onClick={async () => {
          setBusy(true); setError('')
          try { await confirm(notify); onClose() } catch (e) { setError(message(e)) } finally { setBusy(false) }
        }}>{busy ? t('Working…') : t('Reject')}</Button>
      </div>
    </DialogContent>
  </Dialog>
}

/** WaitlistPage lists the people waiting to sign up and lets operators
 * approve, reject or delete them, one by one or in bulk. */
export default function WaitlistPage() {
  const { project, environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/waitlist`
  const policyHref = `/projects/${project}/environments/${environment}/sign-in-policy`
  const [status, setStatus] = useState('')
  const [typed, setTyped] = useState('')
  const [email, setEmail] = useState('')
  // The backend filters by email prefix (?email=), not the generic ?search=.
  useEffect(() => { const id = setTimeout(() => setEmail(typed.trim()), 300); return () => clearTimeout(id) }, [typed])
  const extraParams = useMemo(() => Object.fromEntries(Object.entries({ status, email }).filter(([, v]) => v)), [status, email])
  const list = usePaginatedList<WaitlistEntry>(path, { extraParams })
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState('')
  const [rejecting, setRejecting] = useState<WaitlistEntry | null>(null)
  const [deleting, setDeleting] = useState<WaitlistEntry | null>(null)
  const [approvingAll, setApprovingAll] = useState(false)
  // A selection never outlives the rows it was made on.
  useEffect(() => { setSelected(new Set()) }, [list.data])

  const act = async (key: string, run: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try { await run(); toast.success(done); list.reload() } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const approve = (e: WaitlistEntry) => act(e.id, () => api.post(`${path}/${e.id}/approve`), t('Approved {{email}}', { email: e.email }))
  const pendingSelected = list.data.filter(e => selected.has(e.id) && e.status === 'pending')
  const approveSelected = () => act('bulk', async () => {
    const out = await api.post<BulkResult>(`${path}/approve`, { ids: pendingSelected.map(e => e.id) })
    toast.message(t('{{approved}} approved, {{skipped}} skipped', { approved: out.approved, skipped: out.skipped }))
  }, t('Approval emails are on their way'))
  const filtered = !!status || !!email
  const allSelected = list.data.length > 0 && list.data.every(e => selected.has(e.id))
  const toggle = (id: string, on: boolean) => setSelected(s => { const next = new Set(s); if (on) next.add(id); else next.delete(id); return next })
  const search = { ...list, rawSearch: typed, setSearch: setTyped }

  const empty = filtered
    ? <EmptyState icon={<ListPlus />} title={t('No matching entries')} description={t('Try another status or email.')} />
    : <EmptyState icon={<ListPlus />} title={t('The waitlist is empty')}
      description={rich('Nobody is waiting. To hold new sign-ups for approval, allow sign-up and turn on {{waitlist}} in {{link}}; people who then sign up are listed here.', {
        waitlist: <strong>{t('Waitlist')}</strong>, link: <Link className="underline" to={policyHref}>{t('Sign-in methods')}</Link>,
      })} />

  return <div className="space-y-4">
    <PageHeader title={t('Waitlist')} description={t('People who asked to sign up while the waitlist is on. Approving emails them a single-use link to create their account; it works for 7 days.')}
      actions={canWrite && <Button type="button" variant="outline" size="sm" disabled={!!busy} onClick={() => setApprovingAll(true)}><MailCheck className="size-3.5" /> {t('Approve all pending')}</Button>} />
    <PaginationBar state={search} noun={t('entries')} label={t('Search by email')} placeholder={t('Search by email prefix…')} />
    <div className="flex flex-wrap items-center gap-3">
      <select aria-label={t('Filter by status')} className={`${selectClass} w-auto`} value={status} onChange={e => setStatus(e.target.value)}>
        <option value="">{t('All statuses')}</option>
        <option value="pending">{t('Pending')}</option>
        <option value="approved">{t('Approved')}</option>
        <option value="rejected">{t('Rejected')}</option>
        <option value="completed">{t('Signed up')}</option>
      </select>
      {canWrite && pendingSelected.length > 0 && <Button size="sm" disabled={!!busy} onClick={() => void approveSelected()}><Check className="size-3.5" /> {t('Approve {{count}} selected', { count: pendingSelected.length })}</Button>}
    </div>

    <DataTable
      columns={[
        ...(canWrite ? [{ header: '', nowrap: true }] : []),
        t('Email'), { header: t('Name'), hideBelow: 'md' }, t('Status'),
        { header: t('Created'), hideBelow: 'sm', nowrap: true }, { header: t('Decided'), hideBelow: 'sm', nowrap: true },
        ...(canWrite ? [t('Actions')] : []),
      ]}
      loading={list.loading} error={list.error} retry={list.reload} empty={empty}
      rows={list.data.map(e => [
        ...(canWrite ? [<input type="checkbox" className="size-4" aria-label={t('Select {{email}}', { email: e.email })} checked={selected.has(e.id)} onChange={ev => toggle(e.id, ev.target.checked)} />] : []),
        <span className="font-medium">{e.email}</span>,
        <span className="text-sm text-muted-foreground">{e.name || '—'}</span>,
        <StatusBadge status={e.status} />,
        <Time value={e.created_at} />,
        <Time value={e.decided_at} />,
        ...(canWrite ? [<RowActions label={t('Actions for {{email}}', { email: e.email })} actions={[
          ...(e.status === 'pending' || e.status === 'approved' ? [
            { label: e.status === 'approved' ? t('Send a new approval link') : t('Approve'), icon: <Check />, disabled: busy === e.id, onSelect: () => void approve(e) },
            { label: t('Reject'), icon: <X />, onSelect: () => setRejecting(e) },
          ] : []),
          { label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setDeleting(e) },
        ]} />] : []),
      ])}
    />
    {canWrite && list.data.length > 0 && <label className="flex items-center gap-2 text-xs text-muted-foreground">
      <input type="checkbox" className="size-4" checked={allSelected} onChange={ev => setSelected(ev.target.checked ? new Set(list.data.map(e => e.id)) : new Set())} />
      {t('Select all on this page')}
    </label>}

    {rejecting && <RejectDialog entry={rejecting} onClose={() => setRejecting(null)}
      confirm={async notify => { await api.post(`${path}/${rejecting.id}/reject`, { notify }); toast.success(t('Rejected {{email}}', { email: rejecting.email })); list.reload() }} />}
    {deleting && <ConfirmDialog title={t('Delete {{email}}?', { email: deleting.email })}
      description={t('The entry and its approval link are removed. The address can join the waitlist again.')} confirmLabel={t('Delete')} onClose={() => setDeleting(null)}
      confirm={async () => { await api.delete(`${path}/${deleting.id}`); toast.success(t('Entry deleted')); list.reload() }} />}
    {approvingAll && <ConfirmDialog title={t('Approve every pending entry?')}
      description={t('Everyone waiting is emailed a sign-up link. This can take a moment for a long list.')} confirmLabel={t('Approve all pending')} onClose={() => setApprovingAll(false)}
      confirm={async () => {
        const out = await approveAll(path)
        toast.success(t('{{approved}} approved, {{skipped}} skipped', { approved: out.approved, skipped: out.skipped }))
        list.reload()
      }} />}
  </div>
}
