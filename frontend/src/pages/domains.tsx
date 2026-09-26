import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, BadgeCheck, Check, Copy, Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, DataTable, FormDialog, ID, PageHeader } from '@/components/library/patterns'

export interface Domain {
  id: string; organization_id: string; domain: string
  verified: boolean; verified_at: string | null; verified_by: string | null
  verification_method: 'dns' | 'manual' | null
  verification: { type: 'TXT'; name: string; value: string }
  created_at: string
}

export function DomainStatus({ domain }: { domain: Domain }) {
  if (!domain.verified) return <Badge variant="secondary" className="bg-warning/10 text-warning">Pending</Badge>
  return <Badge variant="secondary" className="bg-success/10 text-success" title={domain.verified_at ? `Verified ${new Date(domain.verified_at).toLocaleString()}` : undefined}>
    Verified{domain.verification_method === 'manual' ? ' (manual)' : ''}
  </Badge>
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return <div className="space-y-1">
    <div className="text-xs font-medium text-muted-foreground">{label}</div>
    <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
      <code className="min-w-0 flex-1 break-all text-xs">{value}</code>
      <Button variant="ghost" size="icon" aria-label={`Copy ${label.toLowerCase()}`} onClick={async () => {
        try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }
        catch { toast.error('Copy failed') }
      }}>{copied ? <Check className="size-4" /> : <Copy className="size-4" />}</Button>
    </div>
  </div>
}

export function DomainsPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/domains`
  const envBase = `/projects/${project}/environments/${environment}`
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [orgName, setOrgName] = useState('')
  const list = usePaginatedList<Domain>(path)
  const [adding, setAdding] = useState(false)
  const [instructions, setInstructions] = useState<Domain | null>(null)
  const [forcing, setForcing] = useState<Domain | null>(null)
  const [removing, setRemoving] = useState<Domain | null>(null)
  const [verifying, setVerifying] = useState('')

  useEffect(() => {
    api.get<{ name: string }>(`${base}/organizations/${orgId}`).then(o => setOrgName(o.name)).catch(() => {})
  }, [base, orgId])

  async function verify(d: Domain) {
    setVerifying(d.id)
    try {
      await api.post<Domain>(`${path}/${d.id}/verify`)
      toast.success(`${d.domain} verified`)
      setInstructions(null)
      list.reload()
    } catch (e) {
      toast.error(message(e))
    } finally {
      setVerifying('')
    }
  }

  return <div className="space-y-6">
    <div className="space-y-3">
      <Link to={`${envBase}/organizations/${orgId}/members`} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeft className="size-3.5" />Back to members
      </Link>
      <PageHeader
        title={orgName ? `Domains of ${orgName}` : 'Domains'}
        description="Verified domains prove the organization owns an email domain. SCIM can restrict member adoption to them, and SSO routing will use them."
        actions={canWrite && <Button onClick={() => setAdding(true)}><Plus />Add domain</Button>}
      />
    </div>

    <PaginationBar state={list} noun="domains" placeholder="Search domains…" />

    <DataTable
      columns={['Domain / ID', 'Status', 'Added', 'Actions']}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rows={list.data.map(d => [
        <div className="space-y-1"><div className="font-medium">{d.domain}</div><ID value={d.id} /></div>,
        <DomainStatus domain={d} />,
        <span className="text-sm text-muted-foreground">{new Date(d.created_at).toLocaleDateString()}</span>,
        <div className="flex gap-1">
          {!d.verified && <Button variant="ghost" size="sm" onClick={() => setInstructions(d)}>DNS record</Button>}
          {canWrite && !d.verified && <>
            <Button variant="ghost" size="icon" aria-label={`Verify ${d.domain}`} disabled={verifying === d.id} onClick={() => verify(d)}><RefreshCw className={verifying === d.id ? 'size-4 animate-spin' : 'size-4'} /></Button>
            <Button variant="ghost" size="icon" aria-label={`Force-verify ${d.domain}`} onClick={() => setForcing(d)}><ShieldAlert className="size-4" /></Button>
          </>}
          {canWrite && <Button variant="ghost" size="icon" aria-label={`Remove ${d.domain}`} onClick={() => setRemoving(d)}><Trash2 /></Button>}
        </div>,
      ])}
    />

    {adding && <FormDialog
      title="Add domain"
      description="Enter a domain the organization owns, e.g. acme.com. Subdomains are claimed separately. A domain belongs to at most one organization per environment."
      fields={[{ name: 'domain', label: 'Domain', value: '' }]}
      onClose={() => setAdding(false)}
      submit={async data => {
        const d = await api.post<Domain>(path, { domain: data.domain })
        list.reload()
        setInstructions(d)
      }}
    />}

    {instructions && <Dialog open onOpenChange={open => { if (!open) setInstructions(null) }}>
      <DialogContent>
        <DialogTitle>Verify {instructions.domain}</DialogTitle>
        <DialogDescription>
          Publish this TXT record at your DNS provider, then check it. DNS changes can take a while to propagate.
        </DialogDescription>
        <div className="space-y-3">
          <CopyValue label="Type" value={instructions.verification.type} />
          <CopyValue label="Name" value={instructions.verification.name} />
          <CopyValue label="Value" value={instructions.verification.value} />
        </div>
        {canWrite && <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setInstructions(null)}>Later</Button>
          <Button disabled={verifying === instructions.id} onClick={() => verify(instructions)}><BadgeCheck />Check DNS now</Button>
        </div>}
      </DialogContent>
    </Dialog>}

    {forcing && <ConfirmDialog
      title="Force-verify domain?"
      description={`Marks ${forcing.domain} as verified without DNS proof. Only do this when ownership was confirmed another way; the action is audited.`}
      confirmLabel="Force-verify"
      confirmationText={forcing.domain}
      onClose={() => setForcing(null)}
      confirm={async () => { await api.post(`${path}/${forcing.id}/force-verify`); toast.success(`${forcing.domain} verified manually`); list.reload() }}
    />}

    {removing && <ConfirmDialog
      title="Remove domain?"
      description={`${removing.domain} will be released${removing.verified ? ' and lose its verification' : ''}. Another organization may claim it afterwards.`}
      confirmLabel="Remove"
      onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success('Domain removed'); list.reload() }}
    />}
  </div>
}
