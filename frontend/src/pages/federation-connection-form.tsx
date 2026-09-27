import { useEffect, useId, useRef, useState } from 'react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SearchSelect } from '@/components/ui/search-select'
import { TagInput } from '@/components/ui/tag-input'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState } from '@/components/library/patterns'

export type Provider = 'oidc' | 'google' | 'microsoft' | 'github' | 'apple'

export const providers: { value: Provider; label: string; hint: string }[] = [
  { value: 'google', label: 'Google', hint: 'Google accounts and Workspace. Create an OAuth client (Web application) in Google Cloud.' },
  { value: 'microsoft', label: 'Microsoft', hint: 'Microsoft Entra ID work accounts and personal Microsoft accounts. Register an app in Entra.' },
  { value: 'github', label: 'GitHub', hint: 'GitHub users (OAuth app). GitHub is OAuth 2.0, not OIDC: IAMKit reads the user and their verified primary email.' },
  { value: 'apple', label: 'Apple', hint: 'Sign in with Apple. Needs a Services ID, your Team ID, and a Sign in with Apple private key (.p8).' },
  { value: 'oidc', label: 'Other (OIDC)', hint: 'Any OpenID Connect provider with discovery (Okta, Auth0, Keycloak, Entra single tenant…).' },
]

export const providerLabel = (p: string) => providers.find(x => x.value === p)?.label ?? 'OIDC'

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

export interface ConnectionValues {
  provider: Provider; scope: 'environment' | 'organization'; organization_id: string
  name: string; issuer: string; client_id: string; client_secret: string; secret_env: string
  tenant: string; tenant_id: string; tenants: string[]; team_id: string; key_id: string
  signup: boolean; signup_organization_id: string; signup_group_id: string; link_email: boolean
}

// connectionBody is the create request for the form values: presets derive
// their issuer, and only the options of the chosen provider are sent.
export function connectionBody(v: ConnectionValues): Record<string, unknown> {
  const body: Record<string, unknown> = { provider: v.provider, name: v.name.trim(), client_id: v.client_id.trim() }
  if (v.provider === 'oidc') body.issuer = v.issuer.trim()
  if (v.client_secret) body.client_secret = v.client_secret
  else if (v.secret_env.trim() && v.provider !== 'apple') body.secret_env = v.secret_env.trim()
  if (v.provider === 'microsoft') {
    const tenant = v.tenant === 'tenant' ? v.tenant_id.trim() : v.tenant
    body.options = { tenant, ...(v.tenants.length && (tenant === 'common' || tenant === 'organizations') ? { tenants: v.tenants } : {}) }
  }
  if (v.provider === 'apple') body.options = { team_id: v.team_id.trim(), key_id: v.key_id.trim() }
  if (v.scope === 'organization') {
    body.organization_id = v.organization_id
  } else {
    if (v.signup) {
      body.signup = true
      body.signup_organization_id = v.signup_organization_id
      if (v.signup_group_id) body.signup_group_id = v.signup_group_id
    }
    if (v.link_email) body.link_email = true
  }
  return body
}

const initial: ConnectionValues = {
  provider: 'google', scope: 'environment', organization_id: '', name: 'Google', issuer: '', client_id: '', client_secret: '', secret_env: '',
  tenant: 'common', tenant_id: '', tenants: [], team_id: '', key_id: '', signup: false, signup_organization_id: '', signup_group_id: '', link_email: true,
}

// useCallbackURL is the federation redirect URI: under IAMKit's issuer,
// which differs from the console origin when a proxy sits in front.
export function useCallbackURL() {
  const [issuer, setIssuer] = useState(window.location.origin)
  useEffect(() => {
    fetch('/.well-known/openid-configuration').then(r => r.ok ? r.json() : null)
      .then(d => { if (d && typeof d.issuer === 'string') setIssuer(d.issuer.replace(/\/$/, '')) }).catch(() => {})
  }, [])
  return `${issuer}/identity/v1/federation/callback`
}

export function CreateConnectionDialog({ base, onClose, onCreated }: { base: string; onClose: () => void; onCreated: () => void }) {
  const id = useId()
  const callback = useCallbackURL()
  const [v, setV] = useState<ConnectionValues>(initial)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const set = <K extends keyof ConnectionValues>(key: K, value: ConnectionValues[K]) => setV(prev => ({ ...prev, [key]: value }))
  const pick = (provider: Provider) => setV(prev => ({
    ...prev, provider,
    name: providers.some(p => p.label === prev.name) || prev.name === '' ? (provider === 'oidc' ? '' : providerLabel(provider)) : prev.name,
    // Social presets are environment connections; organizations bring their own IdP.
    scope: provider === 'oidc' || provider === 'microsoft' ? prev.scope : 'environment',
  }))
  const social = v.scope === 'environment'
  const field = (name: string, label: string, control: React.ReactNode, hint?: string) => <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={`${id}-${name}`}>{label}</label>
    {control}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
  const check = (name: keyof ConnectionValues, label: string, hint: string) => <label className="flex items-start gap-2 text-sm">
    <input type="checkbox" className="mt-0.5 accent-primary" checked={v[name] === true} disabled={busy} onChange={e => set(name, e.target.checked as never)} />
    <span><span className="font-medium">{label}</span><span className="block text-xs text-muted-foreground">{hint}</span></span>
  </label>

  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <DialogTitle className="pr-6 text-base font-semibold">Create federation connection</DialogTitle>
      <DialogDescription className="text-muted-foreground">Add a social login provider for the whole environment, or an organization's own identity provider.</DialogDescription>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); if (pending.current) return
        pending.current = true; setBusy(true); setError('')
        try { await api.post(`${base}/federation-connections`, connectionBody(v)); toast.success('Connection created'); onCreated(); onClose() } catch (err) { setError(message(err)) } finally { pending.current = false; setBusy(false) }
      }}>
        <fieldset className="space-y-2" disabled={busy}>
          <legend className="text-sm font-medium">Provider</legend>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {providers.map(p => <button key={p.value} type="button" aria-pressed={v.provider === p.value} onClick={() => pick(p.value)}
              className={`rounded-md border px-3 py-2 text-left text-sm transition-colors ${v.provider === p.value ? 'border-primary bg-primary/5 font-medium' : 'hover:bg-muted'}`}>{p.label}</button>)}
          </div>
          <p className="text-xs text-muted-foreground">{providers.find(p => p.value === v.provider)?.hint}</p>
        </fieldset>

        {(v.provider === 'oidc' || v.provider === 'microsoft') && field('scope', 'Used by', <select id={`${id}-scope`} className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={v.scope} disabled={busy} onChange={e => set('scope', e.target.value as ConnectionValues['scope'])}>
          <option value="environment">Everyone (social login on the sign-in page)</option>
          <option value="organization">One organization (enterprise SSO)</option>
        </select>)}
        {v.scope === 'organization' && field('organization_id', 'Organization', <SearchSelect id={`${id}-organization_id`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder="Search organizations…" onChange={value => set('organization_id', value)} />,
          'Users with a verified domain of the organization are routed here. Configure just-in-time provisioning and enforcement after creating it.')}

        {field('name', 'Name', <Input id={`${id}-name`} value={v.name} required disabled={busy} onChange={e => set('name', e.target.value)} />, social ? 'Shown on the button: "Continue with …".' : undefined)}
        {v.provider === 'oidc' && field('issuer', 'Issuer URL', <Input id={`${id}-issuer`} value={v.issuer} required disabled={busy} placeholder="https://idp.example.com" onChange={e => set('issuer', e.target.value)} />, 'HTTPS; IAMKit reads /.well-known/openid-configuration.')}

        {v.provider === 'microsoft' && <>
          {field('tenant', 'Accounts', <select id={`${id}-tenant`} className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={v.tenant} disabled={busy} onChange={e => set('tenant', e.target.value)}>
            <option value="common">Work, school and personal accounts (common)</option>
            <option value="organizations">Work and school accounts (organizations)</option>
            <option value="consumers">Personal Microsoft accounts (consumers)</option>
            <option value="tenant">One tenant</option>
          </select>, 'Must match the account types of the Entra app registration.')}
          {v.tenant === 'tenant' && field('tenant_id', 'Tenant ID', <Input id={`${id}-tenant_id`} value={v.tenant_id} required disabled={busy} placeholder="00000000-0000-0000-0000-000000000000" onChange={e => set('tenant_id', e.target.value)} />)}
          {(v.tenant === 'common' || v.tenant === 'organizations') && field('tenants', 'Allowed tenants (optional)', <TagInput id={`${id}-tenants`} name="tenants" defaultValue={v.tenants} disabled={busy} placeholder="Tenant ID, then Enter…" onChange={tags => set('tenants', tags)} />, 'Only these tenant IDs may sign in. Leave empty to accept any tenant.')}
        </>}

        {v.provider === 'apple' && <div className="grid grid-cols-2 gap-3">
          {field('team_id', 'Team ID', <Input id={`${id}-team_id`} value={v.team_id} required disabled={busy} placeholder="ABCDE12345" onChange={e => set('team_id', e.target.value)} />)}
          {field('key_id', 'Key ID', <Input id={`${id}-key_id`} value={v.key_id} required disabled={busy} placeholder="KEY1234567" onChange={e => set('key_id', e.target.value)} />)}
        </div>}

        {field('client_id', v.provider === 'apple' ? 'Services ID' : 'Client ID', <Input id={`${id}-client_id`} value={v.client_id} required disabled={busy} placeholder={v.provider === 'apple' ? 'com.example.web' : undefined} onChange={e => set('client_id', e.target.value)} />)}
        {v.provider === 'apple'
          ? field('client_secret', 'Private key (.p8)', <textarea id={`${id}-client_secret`} className="min-h-24 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" value={v.client_secret} required disabled={busy} placeholder="-----BEGIN PRIVATE KEY-----" onChange={e => set('client_secret', e.target.value)} />,
            'Stored encrypted; IAMKit signs a short-lived client secret with it for each login.')
          : <>
            {field('client_secret', 'Client secret', <Input id={`${id}-client_secret`} type="password" autoComplete="new-password" value={v.client_secret} required={!v.secret_env.trim()} disabled={busy} onChange={e => set('client_secret', e.target.value)} />, 'Stored encrypted; never shown again. Requires IAMKIT_ENCRYPTION_KEY.')}
            {!v.client_secret && field('secret_env', 'Or: secret env variable', <Input id={`${id}-secret_env`} value={v.secret_env} disabled={busy} onChange={e => set('secret_env', e.target.value)} />, 'Legacy: an approved deployment variable.')}
          </>}

        {social && <fieldset className="space-y-3 rounded-md border p-3" disabled={busy}>
          <legend className="px-1 text-sm font-medium">First sign-in</legend>
          {check('link_email', 'Link existing accounts by verified email', 'A user whose provider email is verified and matches an account signs in to that account.')}
          {check('signup', 'Create accounts for new users', 'Unknown users with a verified email get an account in the organization below.')}
          {v.signup && <>
            {field('signup_organization_id', 'Sign-up organization', <SearchSelect id={`${id}-signup_organization_id`} name="signup_organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder="Search organizations…" onChange={value => setV(prev => ({ ...prev, signup_organization_id: value, signup_group_id: '' }))} />)}
            {v.signup_organization_id && field('signup_group_id', 'Default group (optional)', <SearchSelect key={v.signup_organization_id} id={`${id}-signup_group_id`} name="signup_group_id" path={`${base}/organizations/${v.signup_organization_id}/groups`} mapItem={named} disabled={busy} placeholder="Search groups…" onChange={value => set('signup_group_id', value)} />, 'New users join this group and get its roles.')}
          </>}
        </fieldset>}

        <div className="rounded-md bg-muted p-3 text-xs">
          <p className="font-medium">Redirect URI to register with the provider</p>
          <code className="mt-1 block break-all select-all">{callback}</code>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
