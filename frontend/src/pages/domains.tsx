import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { BadgeCheck, Check, Copy, FileText, Globe, Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { useOrganization } from './organization-layout'
import { ConfirmDialog, DataTable, EmptyState, FormDialog, Time } from '@/components/library/patterns'
import { RowActions } from '@/components/ui/menu'
import { formatDateTime, t } from '@/lib/i18n'

export interface Domain {
  id: string; organization_id: string; domain: string
  verified: boolean; verified_at: string | null; verified_by: string | null
  verification_method: 'dns' | 'manual' | null
  verification: { type: 'TXT'; name: string; value: string }
  created_at: string
}

export function DomainStatus({ domain }: { domain: Domain }) {
  if (!domain.verified) return <Badge variant="secondary" className="bg-warning/10 text-warning">{t('Pending')}</Badge>
  return <Badge variant="secondary" className="bg-success/10 text-success" title={domain.verified_at ? t('Verified {{time}}', { time: formatDateTime(domain.verified_at) }) : undefined}>
    {t('Verified')}{domain.verification_method === 'manual' ? ' (manual)' : ''}
  </Badge>
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

export function DomainsPage() {
  const { environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/domains`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const orgName = useOrganization().org.name
  const list = usePaginatedList<Domain>(path)
  const [adding, setAdding] = useState(false)
  const [instructions, setInstructions] = useState<Domain | null>(null)
  const [forcing, setForcing] = useState<Domain | null>(null)
  const [removing, setRemoving] = useState<Domain | null>(null)
  const [verifying, setVerifying] = useState('')

  async function verify(d: Domain) {
    setVerifying(d.id)
    try {
      await api.post<Domain>(`${path}/${d.id}/verify`)
      toast.success(t('{{domain}} verified', { domain: d.domain }))
      setInstructions(null)
      list.reload()
    } catch (e) {
      toast.error(message(e))
    } finally {
      setVerifying('')
    }
  }

  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold">{t('Domains of {{orgName}}', { orgName })}</h2>
        <p className="max-w-2xl text-sm text-muted-foreground">{t('Verified domains prove the organization owns an email domain. Users with a verified domain are routed to the organization\'s SSO, and SCIM can restrict member adoption to them.')}</p>
      </div>
      {canWrite && <Button onClick={() => setAdding(true)}><Plus />{t('Add domain')}</Button>}
    </div>

    <PaginationBar state={list} noun="domains" placeholder={t('Search domains…')} />

    <DataTable
      columns={[t('Domain'), t('Status'), { header: t('Added'), hideBelow: 'sm', nowrap: true }, t('Actions')]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      empty={<EmptyState icon={<Globe />} title={t('No domains yet')} description={t('Verify a domain the organization owns to route its users to SSO and auto-join them.')} />}
      rows={list.data.map(d => [
        <span className="font-medium">{d.domain}</span>,
        <DomainStatus domain={d} />,
        <Time value={d.created_at} />,
        <div className="flex items-center justify-end gap-1">
          {canWrite && !d.verified && <Button variant="outline" size="sm" aria-label={t('Verify {{domain}}', { domain: d.domain })} disabled={verifying === d.id} onClick={() => verify(d)}><RefreshCw className={verifying === d.id ? 'animate-spin' : undefined} /> {t('Verify')}</Button>}
          <RowActions label={t('Actions for {{domain}}', { domain: d.domain })} actions={[
            ...(!d.verified ? [{ label: t('Show DNS record'), icon: <FileText />, onSelect: () => setInstructions(d) }] : []),
            ...(canWrite && !d.verified ? [{ label: t('Mark verified without DNS'), icon: <ShieldAlert />, onSelect: () => setForcing(d) }] : []),
            ...(canWrite ? [{ label: t('Remove domain'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(d) }] : []),
          ]} />
        </div>,
      ])}
    />

    {adding && <FormDialog
      title={t('Add domain')}
      description={t('Enter a domain the organization owns, e.g. acme.com. Subdomains are claimed separately. A domain belongs to at most one organization per environment.')}
      fields={[{ name: 'domain', label: t('Domain'), value: '' }]}
      onClose={() => setAdding(false)}
      submit={async data => {
        const d = await api.post<Domain>(path, { domain: data.domain })
        list.reload()
        setInstructions(d)
      }}
    />}

    {instructions && <Dialog open onOpenChange={open => { if (!open) setInstructions(null) }}>
      <DialogContent>
        <DialogTitle>{t('Verify {{domain}}', { domain: instructions.domain })}</DialogTitle>
        <DialogDescription>
          {t('Publish this TXT record at your DNS provider, then check it. DNS changes can take a while to propagate.')}
        </DialogDescription>
        <div className="space-y-3">
          <CopyValue label={t('Type')} value={instructions.verification.type} />
          <CopyValue label={t('Name')} value={instructions.verification.name} />
          <CopyValue label={t('Value')} value={instructions.verification.value} />
        </div>
        {canWrite && <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setInstructions(null)}>{t('Later')}</Button>
          <Button disabled={verifying === instructions.id} onClick={() => verify(instructions)}><BadgeCheck />{t('Check DNS now')}</Button>
        </div>}
      </DialogContent>
    </Dialog>}

    {forcing && <ConfirmDialog
      title={t('Mark {{domain}} as verified?', { domain: forcing.domain })}
      description={t('Marks {{domain}} as verified without DNS proof. Only do this when ownership was confirmed another way; the action is audited.', { domain: forcing.domain })}
      confirmLabel={t('Mark verified')}
      confirmationText={forcing.domain}
      onClose={() => setForcing(null)}
      confirm={async () => { await api.post(`${path}/${forcing.id}/force-verify`); toast.success(t('{{domain}} verified manually', { domain: forcing.domain })); list.reload() }}
    />}

    {removing && <ConfirmDialog
      title={t('Remove {{domain}}?', { domain: removing.domain })}
      description={removing.verified
        ? t('{{domain}} is released and loses its verification. Another organization may claim it afterwards.', { domain: removing.domain })
        : t('{{domain}} is released. Another organization may claim it afterwards.', { domain: removing.domain })}
      confirmLabel={t('Remove domain')}
      onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success(t('Domain removed')); list.reload() }}
    />}
  </div>
}
