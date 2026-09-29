import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Ban, KeyRound, Play, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyText, DataTable, EmptyState, PageHeader, Time } from '@/components/library/patterns'

/** GET /signing-keys item (signing.Key). */
export interface SigningKey {
  kid: string
  environment_id: string
  alg: string
  state: 'next' | 'active' | 'retiring' | 'retired'
  created_at: string
  activated_at?: string | null
  retire_after?: string | null
  retired_at?: string | null
  public_jwk?: Record<string, string> | null
}

const tones: Record<SigningKey['state'], [string, string]> = {
  active: ['Active', 'bg-success/10 text-success'],
  next: ['Next', 'bg-primary/10 text-primary'],
  retiring: ['Retiring', 'bg-warning/10 text-warning'],
  retired: ['Retired', 'bg-muted text-muted-foreground'],
}

type Pending = { action: 'activate' | 'retire'; key: SigningKey; force?: boolean }

/** SigningKeysPage rotates the environment's token signing keys. */
export default function SigningKeysPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/signing-keys`
  const list = useList<SigningKey>(`${path}?limit=200`)
  const [busy, setBusy] = useState(false)
  const [createError, setCreateError] = useState('')
  const [target, setTarget] = useState<Pending | null>(null)
  const active = list.data.find(k => k.state === 'active')

  const create = async () => {
    setBusy(true); setCreateError('')
    try {
      const key = await api.post<SigningKey>(path, {})
      toast.success(`Key ${key.kid} created. Activate it once relying parties have refreshed their JWKS.`)
      list.reload()
    } catch (e) { setCreateError(message(e)) } finally { setBusy(false) }
  }
  const early = (k: SigningKey) => k.state === 'retiring' && !!k.retire_after && Date.parse(k.retire_after) > Date.now()

  return <div className="space-y-6">
    <PageHeader title="Signing keys" description="Keys this environment's access and ID tokens are signed with. A new key is published in the JWKS before it signs; the replaced key keeps verifying tokens until it is retired."
      actions={canWrite && <Button disabled={busy} onClick={() => void create()}><Plus /> {busy ? 'Creating…' : 'Create key'}</Button>} />
    {createError && <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{createError}</p>}
    {!list.loading && !list.error && !active && <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">Tokens are signed with the deployment key (<code>JWT_PRIVATE_KEY_PATH</code>) until a key of this environment is activated.</p>}
    <DataTable columns={['Key ID', 'State', { header: 'Created', nowrap: true }, { header: 'Activated', nowrap: true }, { header: 'Retire after', nowrap: true }, 'Actions']} loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title="No environment keys" description="This environment signs with the deployment key. Create a key to rotate it independently (needs IAMKIT_ENCRYPTION_KEY)." />}
      rows={list.data.map(k => {
        const [label, tone] = tones[k.state]
        return [
          <CopyText value={k.kid} label="Copy key ID" />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          <Time value={k.created_at} />,
          <Time value={k.activated_at} />,
          k.state === 'retiring' ? <Time value={k.retire_after} /> : k.state === 'retired' ? <Time value={k.retired_at} prefix="retired" /> : <span className="text-muted-foreground">—</span>,
          canWrite && <RowActions label={`Actions for key ${k.kid}`} actions={[
            ...(k.state === 'next' || k.state === 'retiring' ? [{ label: 'Activate', icon: <Play />, onSelect: () => setTarget({ action: 'activate', key: k }) }] : []),
            ...(k.state === 'next' || k.state === 'retiring' ? [{ label: early(k) ? 'Retire now (force)' : 'Retire', icon: <Ban />, destructive: true, onSelect: () => setTarget({ action: 'retire', key: k, force: early(k) }) }] : []),
          ]} />,
        ]
      })} />
    {target?.action === 'activate' && <ConfirmDialog title={`Activate key ${target.key.kid}?`}
      description={`New tokens of this environment will be signed with it${active ? `; key ${active.kid} starts retiring and keeps verifying its tokens` : ''}. Relying parties must already have this key in their cached JWKS.`}
      confirmLabel="Activate key" onClose={() => setTarget(null)}
      confirm={async () => { await api.post(`${path}/${target.key.kid}/activate`, {}); toast.success('Signing key activated'); list.reload() }} />}
    {target?.action === 'retire' && <ConfirmDialog title={`Retire key ${target.key.kid}?`}
      description={target.force ? 'Tokens signed with this key may still be valid: they stop validating immediately. Use this for a compromised key.' : 'The key is removed from the JWKS. This cannot be undone.'}
      confirmLabel={target.force ? 'Retire now' : 'Retire key'} confirmationText={target.force ? target.key.kid : undefined} onClose={() => setTarget(null)}
      confirm={async () => { await api.post(`${path}/${target.key.kid}/retire`, { force: !!target.force }); toast.success('Signing key retired'); list.reload() }} />}
  </div>
}
