import { useId, useRef, useState } from 'react'
import { KeySquare, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { RowActions } from '@/components/ui/menu'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, CopyField, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, Time, selectClass } from '@/components/library/patterns'
import { CredentialStatus, SecretDialog } from './integrations'
import { rich, t } from '@/lib/i18n'

export interface UserKey { id: string; user_id: string; public_key: { kty?: string; crv?: string; n?: string }; expires_at: string; last_used_at: string | null; created_at: string }
interface IssuedKey extends UserKey { private_key?: string }

/** keyType names a public JWK: "RSA 2048" or "EC P-256". */
export function keyType(key: UserKey['public_key']): string {
  if (key.kty === 'EC') return `EC ${key.crv ?? ''}`.trim()
  if (key.kty === 'RSA' && key.n) {
    const bytes = Math.floor(key.n.replace(/=+$/, '').length * 3 / 4)
    return `RSA ${bytes * 8}`
  }
  return key.kty ?? t('Unknown')
}

/** keyState: keys are never revoked, only removed or expired. */
const keyState = (k: UserKey) => Date.parse(k.expires_at) <= Date.now() ? 'expired' as const : 'active' as const

/** download saves text as a file in the browser. */
function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }))
  const a = document.createElement('a')
  a.href = url; a.download = name; a.click()
  URL.revokeObjectURL(url)
}

/** UserKeys lists a machine user's keys for the JWT-bearer grant and adds
 * (generated — private key shown once — or uploaded) or removes them. */
export function UserKeys({ base, user, canWrite }: { base: string; user: { id: string; name: string }; canWrite: boolean }) {
  const path = `${base}/users/${user.id}/keys`
  const list = usePaginatedList<UserKey>(path, { limit: 50 })
  const [adding, setAdding] = useState(false)
  const [issued, setIssued] = useState<IssuedKey | null>(null)
  const [remove, setRemove] = useState<UserKey | null>(null)
  const add = canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> {t('Add signing key')}</Button>
  return <DetailSection title={t('Keys')} description={t('The machine user signs a short JWT with one of its keys (kid = key ID, iss and sub = the user ID, aud = the token endpoint) and trades it at /oauth/token with grant type urn:ietf:params:oauth:grant-type:jwt-bearer for an access token.')} actions={list.data.length > 0 && add}>
    <DataTable
      columns={[t('Key'), { header: t('Type'), hideBelow: 'sm' }, { header: t('Last used'), nowrap: true, hideBelow: 'sm' }, { header: t('Expires'), nowrap: true }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeySquare />} title={t('No keys')} description={t('Generate a key pair (the private key is shown once) or upload a public key you hold.')} action={add} />}
      rows={list.data.map(k => [
        <EntityRef name="Key" id={k.id} />,
        keyType(k.public_key),
        <Time value={k.last_used_at} />,
        <Time value={k.expires_at} />,
        <CredentialStatus state={keyState(k)} />,
        ...(canWrite ? [<RowActions label={t('Actions for key {{id}}', { id: k.id })} actions={[{ label: t('Remove'), icon: <Trash2 />, destructive: true, onSelect: () => setRemove(k) }]} />] : []),
      ])} />
    {adding && <KeyForm path={path} onClose={() => setAdding(false)} onCreated={k => { if (k.private_key) setIssued(k); list.reload() }} />}
    {issued?.private_key && <SecretDialog title={t('Key created')} description={t('Download or copy the private key now — IAMKit does not keep it and cannot show it again.')} onClose={() => setIssued(null)} confirm={t('I have saved the private key')}>
      <CopyField label={t('Key ID (kid)')} value={issued.id} />
      <CopyField label={t('User ID (iss and sub)')} value={user.id} />
      <CopyField label={t('Private key')} value={issued.private_key} secret hint={<>{rich('RSA, PKCS #8 PEM. Expires {{time}}.', { time: <Time value={issued.expires_at} /> })}</>} />
      <Button variant="outline" onClick={() => download(`${user.name || 'machine-user'}-${issued.id}.pem`, issued.private_key ?? '')}>{t('Download private key')}</Button>
    </SecretDialog>}
    {remove && <ConfirmDialog title={t('Remove this key?')} description={t('Assertions signed with it are refused and access tokens obtained with it stop working immediately. This cannot be undone.')} confirmLabel={t('Remove')} onClose={() => setRemove(null)} confirm={async () => { await api.delete(`${path}/${remove.id}`); toast.success(t('Key removed')); list.reload() }} />}
  </DetailSection>
}

function KeyForm({ path, onClose, onCreated }: { path: string; onClose: () => void; onCreated: (k: IssuedKey) => void }) {
  const id = useId()
  const [mode, setMode] = useState<'generate' | 'upload'>('generate')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Add signing key')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('A machine user holds at most 10 keys.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data: Record<string, unknown> = { expires_in: String(form.get('expires_in') ?? '8760h') }
        if (mode === 'upload') {
          try { data.public_key = JSON.parse(String(form.get('public_key') ?? '')) } catch { setError(t('The public key must be a JSON Web Key (JSON).')); return }
        }
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<IssuedKey>(path, data)
          toast.success(t('Key added')); onCreated(result); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <fieldset className="space-y-2" disabled={busy}>
          <legend className="text-sm font-medium">{t('Key pair')}</legend>
          <label className="flex items-start gap-2 text-sm"><input type="radio" name="mode" className="mt-1" checked={mode === 'generate'} onChange={() => setMode('generate')} /><span>{t('Generate an RSA key pair')}<span className="block text-muted-foreground">{t('IAMKit returns the private key once and keeps only the public half.')}</span></span></label>
          <label className="flex items-start gap-2 text-sm"><input type="radio" name="mode" className="mt-1" checked={mode === 'upload'} onChange={() => setMode('upload')} /><span>{t('Upload a public key')}<span className="block text-muted-foreground">{t('The private key never leaves your system.')}</span></span></label>
        </fieldset>
        {mode === 'upload' && <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-jwk`}>{t('Public key (JWK)')}</label>
          <textarea id={`${id}-jwk`} name="public_key" required disabled={busy} className="min-h-28 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" placeholder='{"kty":"EC","crv":"P-256","x":"…","y":"…"}' />
          <p className="text-xs text-muted-foreground">{t('RSA (2048 bits or more) or EC (P-256, P-384, P-521). Private members are refused.')}</p>
        </div>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>{t('Expires in')}</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="8760h" disabled={busy}>
            <option value="720h">{t('30 days')}</option>
            <option value="2160h">{t('90 days')}</option>
            <option value="8760h">{t('1 year')}</option>
            <option value="never">{t('No expiry')}</option>
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Adding…') : mode === 'generate' ? t('Generate') : t('Upload')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
