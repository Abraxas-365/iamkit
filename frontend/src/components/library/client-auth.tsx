import { useId, useState } from 'react'
import { toast } from 'sonner'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState, RadioCards, selectClass } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** ClientAuth is how an OAuth client or a service account authenticates at
 * /oauth/token. */
export interface ClientAuth {
  token_endpoint_auth_method?: string
  token_endpoint_auth_signing_alg?: string
  jwks?: unknown
  jwks_uri?: string
}

export const authMethodLabels: Record<string, string> = {
  none: t('None (public, PKCE)'),
  client_secret_basic: t('Client secret (HTTP Basic)'),
  client_secret_post: t('Client secret (form body)'),
  private_key_jwt: t('Private key JWT'),
}

export const assertionAlgorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']

const methods = [
  { value: 'client_secret_basic', label: t('Client secret — HTTP Basic'), description: t('The default: client ID and secret in the Authorization header.') },
  { value: 'client_secret_post', label: t('Client secret — form body'), description: t('client_id and client_secret sent as form fields.') },
  { value: 'private_key_jwt', label: t('Private key JWT'), description: t('A short-lived JWT signed with your key (RFC 7523). The secret stops working.') },
]

/** authSummary describes a configuration in one line. */
export function authSummary(auth: ClientAuth) {
  const method = auth.token_endpoint_auth_method || 'client_secret_basic'
  const label = authMethodLabels[method] ?? method
  if (method !== 'private_key_jwt') return label
  return `${label} · ${auth.token_endpoint_auth_signing_alg || 'RS256'} · ${auth.jwks_uri ? t('keys from URL') : t('{{count}} keys', { count: keyCount(auth.jwks) })}`
}

function keyCount(jwks: unknown) {
  const keys = (jwks as { keys?: unknown[] } | undefined)?.keys
  return Array.isArray(keys) ? keys.length : 0
}

/** ClientAuthDialog edits token endpoint authentication and sends the
 * whole configuration to save. */
export function ClientAuthDialog({ title, current, onClose, save }: { title: string; current: ClientAuth; onClose: () => void; save: (body: ClientAuth) => Promise<void> }) {
  const id = useId()
  const [method, setMethod] = useState(current.token_endpoint_auth_method || 'client_secret_basic')
  const [alg, setAlg] = useState(current.token_endpoint_auth_signing_alg || 'RS256')
  const [source, setSource] = useState(current.jwks_uri ? 'uri' : 'inline')
  const [uri, setURI] = useState(current.jwks_uri ?? '')
  const [jwks, setJWKS] = useState(current.jwks ? JSON.stringify(current.jwks, null, 2) : '')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const body: ClientAuth = { token_endpoint_auth_method: method }
    if (method === 'private_key_jwt') {
      body.token_endpoint_auth_signing_alg = alg
      if (source === 'uri') body.jwks_uri = uri.trim()
      else {
        try { body.jwks = JSON.parse(jwks) } catch { setError(t('The key set is not valid JSON.')); return }
      }
    }
    setBusy(true)
    try { await save(body); toast.success(t('Authentication saved')); onClose() } catch (err) { setError(message(err)) } finally { setBusy(false) }
  }

  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{title}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('How the client proves its identity at the token endpoint.')}</DialogDescription>
      <form className="space-y-4" onSubmit={submit}>
        <RadioCards name="token_endpoint_auth_method" label={t('Method')} value={method} onChange={setMethod} options={methods} disabled={busy} />
        {method === 'private_key_jwt' && <>
          <div className="space-y-1.5">
            <label htmlFor={`${id}-alg`} className="text-sm font-medium">{t('Signing algorithm')}</label>
            <select id={`${id}-alg`} className={selectClass} value={alg} disabled={busy} onChange={e => setAlg(e.target.value)}>
              {assertionAlgorithms.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
          <RadioCards name="key_source" label={t('Public keys')} value={source} onChange={setSource} disabled={busy} options={[
            { value: 'inline', label: t('Paste a key set'), description: t('A JSON Web Key Set with up to 10 public RSA or EC keys.') },
            { value: 'uri', label: t('Key set URL'), description: t('An HTTPS URL IAMKit reads (cached up to an hour); rotate keys there.') },
          ]} />
          {source === 'uri'
            ? <div className="space-y-1.5">
              <label htmlFor={`${id}-uri`} className="text-sm font-medium">{t('JWKS URL')}</label>
              <Input id={`${id}-uri`} type="url" required value={uri} disabled={busy} placeholder="https://service.example.com/.well-known/jwks.json" onChange={e => setURI(e.target.value)} />
            </div>
            : <div className="space-y-1.5">
              <label htmlFor={`${id}-jwks`} className="text-sm font-medium">{t('JSON Web Key Set')}</label>
              <textarea id={`${id}-jwks`} className="min-h-32 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" required value={jwks} disabled={busy} placeholder={'{"keys":[{"kty":"RSA","kid":"…","n":"…","e":"AQAB"}]}'} onChange={e => setJWKS(e.target.value)} />
              <p className="text-xs text-muted-foreground">{t('Public keys only; the kid in your assertions\' header must match one of them.')}</p>
            </div>}
        </>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
