import { useId, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { selectClass } from '@/components/library/patterns'
import { connectionBody, initial, named, samlOptions, useCallbackURL, type ConnectionValues } from '@/pages/federation-connection-form'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { t } from '@/lib/i18n'
import { GuideView, type GuideValues } from './guide-view'
import { ldapGuide, oidcGuides, samlGuides, type Guide } from './guides'

/** ConnectionInfo is what a connection's detail answers: the service
 * provider values of a SAML connection, or an OIDC redirect URI. */
export interface ConnectionInfo { draft?: boolean; callback_url?: string; saml?: { entity_id: string; acs_url: string; metadata_url: string } }

/** GuidedTransport sends the wizard's requests: the console's management API
 * or the organization admin portal's /admin routes. */
export interface GuidedTransport {
  create: (body: Record<string, unknown>) => Promise<{ id: string }>
  find: (id: string) => Promise<ConnectionInfo>
  update: (id: string, body: Record<string, unknown>) => Promise<unknown>
  test: (id: string) => Promise<{ url: string; expires_at: string }>
  enable: (id: string) => Promise<unknown>
}

/** consoleTransport is the wizard's transport over the operator API; `base` is `/environments/:id`. */
export const consoleTransport = (base: string): GuidedTransport => {
  const path = `${base}/federation-connections`
  return {
    create: body => api.post(path, body),
    find: id => api.get(`${path}/${id}`),
    update: (id, body) => api.patch(`${path}/${id}`, body),
    test: id => api.post(`${path}/${id}/test`),
    enable: id => api.post(`${path}/${id}/enable`),
  }
}

type Phase = 'pick' | 'guide' | 'paste' | 'finish'

/** GuidedSetupDialog walks an administrator through connecting an identity
 * provider: pick it, copy IAMKit's values into it (SAML creates an inactive
 * draft first), paste what it gives back, test in a new tab, then enable. */
export function GuidedSetupDialog({ base, organization, transport, onClose, onDone, onAdvanced }: {
  base: string; organization?: { id: string; name: string }; transport: GuidedTransport
  onClose: () => void; onDone: () => void; onAdvanced: () => void
}) {
  const id = useId()
  const callback = useCallbackURL()
  const [phase, setPhase] = useState<Phase>('pick')
  const [guide, setGuide] = useState<Guide | null>(null)
  const [org, setOrg] = useState(organization?.id ?? '')
  const [name, setName] = useState('')
  const [connection, setConnection] = useState('')
  const [info, setInfo] = useState<ConnectionInfo | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [enforcement, setEnforcement] = useState('optional')
  const [tested, setTested] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const set = (key: string, value: string) => setFields(prev => ({ ...prev, [key]: value }))
  const saml = guide?.protocol === 'saml'

  async function run(action: () => Promise<void>) {
    if (pending.current) return
    pending.current = true; setBusy(true); setError('')
    try { await action() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
  }

  const pick = (g: Guide) => { setGuide(g); setName(g.label) }
  const next = () => run(async () => {
    if (!guide) return
    if (guide.protocol === 'saml') {
      const created = await transport.create({ provider: 'saml', name: name.trim(), organization_id: org, draft: true, options: {} })
      setConnection(created.id)
      setInfo(await transport.find(created.id))
    }
    setPhase('guide')
  })

  const values: GuideValues = saml ? { acs: info?.saml?.acs_url, entity_id: info?.saml?.entity_id, metadata_url: info?.saml?.metadata_url } : { redirect_uri: info?.callback_url ?? callback }

  const credentials = () => {
    const v: ConnectionValues = { ...initial, provider: guide?.preset ?? 'oidc', name: name.trim(), scope: 'organization', organization_id: org, client_id: fields.client_id ?? '', client_secret: fields.client_secret ?? '' }
    if (!guide?.preset) v.issuer = fields.issuer ?? ''
    if (guide?.preset === 'microsoft') { v.tenant = 'tenant'; v.tenant_id = fields.tenant_id ?? '' }
    if (guide?.preset === 'google') v.domains = (fields.domains ?? '').split(/[\s,]+/).filter(Boolean)
    return v
  }

  const submitPaste = () => run(async () => {
    if (saml) {
      const url = (fields.metadata_url ?? '').trim(), xml = (fields.metadata_xml ?? '').trim()
      if (!url && !xml) { setError(t('Paste the metadata URL or the metadata XML of your identity provider.')); return }
      await transport.update(connection, { options: samlOptions({ ...initial, metadata_url: url, metadata_xml: xml }) })
    } else {
      const v = credentials()
      if (v.provider === 'google' && !v.domains.length) { setError(t('Add at least one Workspace domain, so only the organization\'s Google accounts can sign in.')); return }
      const created = await transport.create(connectionBody(v))
      setConnection(created.id)
    }
    setPhase('finish')
  })

  const test = () => run(async () => {
    const ticket = await transport.test(connection)
    window.open(ticket.url, '_blank', 'noopener')
    setTested(true)
  })

  const finish = () => run(async () => {
    await transport.update(connection, { enforcement })
    if (saml) await transport.enable(connection)
    toast.success(saml ? t('Connection enabled') : t('Connection updated'))
    onDone(); onClose()
  })

  const label = (key: string, text: string, control: React.ReactNode, hint?: string) => <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={`${id}-${key}`}>{text}</label>
    {control}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
  const input = (key: string, text: string, opts: { type?: string; placeholder?: string; hint?: string } = {}) => label(key, text,
    <Input id={`${id}-${key}`} type={opts.type} value={fields[key] ?? ''} disabled={busy} placeholder={opts.placeholder} autoComplete="off" onChange={e => set(key, e.target.value)} />, opts.hint)

  const group = (title: string, guides: Guide[]) => <fieldset className="space-y-2" disabled={busy}>
    <legend className="text-sm font-medium">{title}</legend>
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {guides.map(g => <button key={g.id} type="button" aria-pressed={guide?.id === g.id} onClick={() => pick(g)}
        className={`rounded-md border px-3 py-2 text-left text-sm transition-colors ${guide?.id === g.id ? 'border-primary bg-primary/5 font-medium' : 'hover:bg-muted'}`}>{g.label}</button>)}
    </div>
  </fieldset>

  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
      <DialogTitle className="pr-6 text-base font-semibold">{organization ? t('Guided SSO setup for {{name}}', { name: organization.name }) : t('Guided SSO setup')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Pick your identity provider and follow the steps. Nothing signs in until you test it and turn it on.')}</DialogDescription>
      <div className="space-y-4">
        {phase === 'pick' && <>
          {!organization && label('organization', t('Organization'), <SearchSelect id={`${id}-organization`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder={t('Search organizations…')} onChange={setOrg} />)}
          {group(t('SAML 2.0'), samlGuides)}
          {group(t('OpenID Connect'), oidcGuides)}
          {group(t('Directory'), [ldapGuide])}
          {guide && label('name', t('Name'), <Input id={`${id}-name`} value={name} disabled={busy} onChange={e => setName(e.target.value)} />, t('Helps you recognize it in the list of connections.'))}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Button type="button" variant="ghost" onClick={onAdvanced}>{t('Advanced')}</Button>
            <Button type="button" disabled={busy || !guide || !name.trim() || !org} onClick={next}>{t('Continue')}</Button>
          </div>
        </>}

        {phase === 'guide' && guide && <>
          <GuideView guide={guide} values={values} />
          <div className="flex justify-end">
            {guide.protocol === 'ldap'
              ? <Button type="button" onClick={onAdvanced}>{t('Continue to the directory form')}</Button>
              : <Button type="button" onClick={() => setPhase('paste')}>{t('I have done this')}</Button>}
          </div>
        </>}

        {phase === 'paste' && guide && <>
          <p className="text-sm text-muted-foreground">{saml ? t('Paste what your identity provider gave you.') : t('Paste the credentials of the application you registered.')}</p>
          {saml ? <>
            {input('metadata_url', t('Identity provider metadata URL'), { placeholder: 'https://idp.example.com/metadata' })}
            {label('metadata_xml', t('Or the metadata XML'), <textarea id={`${id}-metadata_xml`} rows={5} value={fields.metadata_xml ?? ''} disabled={busy} className={`${selectClass} h-auto py-1.5 font-mono text-xs`} onChange={e => set('metadata_xml', e.target.value)} />, t('Use this when your identity provider gives a file instead of a URL.'))}
          </> : <>
            {!guide.preset && input('issuer', t('Issuer URL'), { placeholder: 'https://idp.example.com', hint: t('HTTPS; IAMKit reads /.well-known/openid-configuration.') })}
            {guide.preset === 'microsoft' && input('tenant_id', t('Directory (tenant) ID'))}
            {guide.preset === 'google' && input('domains', t('Workspace domains'), { placeholder: 'example.com', hint: t('Separate several with commas. Only accounts of these domains can sign in.') })}
            {input('client_id', t('Client ID'))}
            {input('client_secret', t('Client secret'), { type: 'password' })}
          </>}
          <div className="flex justify-end"><Button type="button" disabled={busy} onClick={submitPaste}>{saml ? t('Save metadata') : t('Save and continue')}</Button></div>
        </>}

        {phase === 'finish' && <>
          <div className="space-y-2">
            <p className="text-sm font-medium">{t('Test the connection')}</p>
            <p className="text-sm text-muted-foreground">{t('Opens a new tab that signs in at your identity provider and shows what IAMKit received. It creates no session and no user.')}</p>
            <Button type="button" variant="outline" disabled={busy} onClick={test}>{t('Test connection')}</Button>
            {tested && <p className="text-xs text-muted-foreground">{t('Test opened in a new tab. Come back here when it succeeds.')}</p>}
          </div>
          {label('enforcement', t('Sign-in mode'), <select id={`${id}-enforcement`} className={selectClass} value={enforcement} disabled={busy} onChange={e => setEnforcement(e.target.value)}>
            <option value="optional">{t('SSO optional')}</option>
            <option value="enforced">{t('SSO required')}</option>
          </select>, t('Required: members of the organization can only sign in with this provider. Test it first.'))}
          <div className="flex justify-end"><Button type="button" disabled={busy} onClick={finish}>{saml ? t('Enable connection') : t('Finish')}</Button></div>
        </>}

        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      </div>
    </DialogContent>
  </Dialog>
}
