import { useEffect, useId, useRef, useState } from 'react'
import { ChevronRight } from 'lucide-react'
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

// ssoProviders are the providers that can be an organization's own identity
// provider: each can be limited to the organization's accounts (a Microsoft
// tenant, Google Workspace domains, or an IdP that is the organization's
// own). GitHub and Apple accounts are personal, so they stay social login.
const ssoProviders: { value: Provider; label: string; hint: string }[] = [
  { value: 'microsoft', label: 'Microsoft Entra ID', hint: "The organization's Entra tenant. Register an app in Entra and pick the tenant it accepts." },
  { value: 'google', label: 'Google Workspace', hint: "The organization's Google Workspace. Only accounts of the Workspace domains below can sign in." },
  { value: 'oidc', label: 'Other (OIDC)', hint: 'Okta, Auth0, Keycloak, OneLogin, or any OpenID Connect provider with discovery.' },
]

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

export interface ConnectionValues {
  provider: Provider; scope: 'environment' | 'organization'; organization_id: string
  name: string; issuer: string; client_id: string; client_secret: string; secret_env: string
  tenant: string; tenant_id: string; tenants: string[]; domains: string[]; team_id: string; key_id: string
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
  if (v.provider === 'google' && v.domains.length) body.options = { domains: v.domains }
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
  tenant: 'common', tenant_id: '', tenants: [], domains: [], team_id: '', key_id: '', signup: false, signup_organization_id: '', signup_group_id: '', link_email: true,
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

export type ConnectionKind = 'social' | 'sso'

export function CreateConnectionDialog({ base, kind, organization, onClose, onCreated }: { base: string; kind: ConnectionKind; organization?: { id: string; name: string }; onClose: () => void; onCreated: () => void }) {
  const id = useId()
  const callback = useCallbackURL()
  const sso = kind === 'sso' || !!organization
  // Organization SSO starts with generic OIDC (Okta, Auth0…), social login with Google.
  const [v, setV] = useState<ConnectionValues>(sso ? { ...initial, provider: 'oidc', name: '', scope: 'organization', organization_id: organization?.id ?? '' } : initial)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const pending = useRef(false)
  const set = <K extends keyof ConnectionValues>(key: K, value: ConnectionValues[K]) => setV(prev => ({ ...prev, [key]: value }))
  const choices = sso ? ssoProviders : providers
  const label = (p: Provider) => choices.find(x => x.value === p)?.label ?? providerLabel(p)
  const pick = (provider: Provider) => setV(prev => ({
    ...prev, provider,
    name: choices.some(p => p.label === prev.name) || prev.name === '' ? (provider === 'oidc' ? '' : label(provider)) : prev.name,
  }))
  const social = !sso
  const workspace = v.provider === 'google' && sso
  // An organization's Google Workspace defaults to its verified domains.
  const [verified, setVerified] = useState<string[]>([])
  useEffect(() => {
    if (v.scope !== 'organization' || !v.organization_id) return
    const ctrl = new AbortController()
    api.list<{ domain: string; verified: boolean }>(`${base}/organizations/${v.organization_id}/domains`, ctrl.signal).then(r => {
      const domains = r.data.filter(d => d.verified).map(d => d.domain)
      setVerified(domains)
      setV(prev => prev.domains.length ? prev : { ...prev, domains })
    }).catch(() => {})
    return () => ctrl.abort()
  }, [base, v.scope, v.organization_id])
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
      <DialogTitle className="pr-6 text-base font-semibold">{organization ? `Add SSO for ${organization.name}` : sso ? 'Add organization SSO' : 'Add social login'}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{organization
        ? `Let ${organization.name}'s employees sign in with their work account. Anyone whose email is on ${organization.name}'s verified domains is sent to this provider.`
        : sso
          ? "Let one organization's employees sign in with their company's login (Entra ID, Google Workspace, Okta…). Anyone whose email is on that organization's verified domains is sent to it."
          : 'Add a "Continue with …" button to the sign-in page. Anyone with an account at the provider can use it.'}</DialogDescription>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault(); if (pending.current) return
        if (workspace && !v.domains.length) { setError('Add at least one Workspace domain, so only the organization\'s Google accounts can sign in.'); return }
        pending.current = true; setBusy(true); setError('')
        try { await api.post(`${base}/federation-connections`, connectionBody(v)); toast.success(sso ? 'Organization SSO added' : 'Social login added'); onCreated(); onClose() } catch (err) { setError(message(err)) } finally { pending.current = false; setBusy(false) }
      }}>
        <fieldset className="space-y-2" disabled={busy}>
          <legend className="text-sm font-medium">Provider</legend>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {choices.map(p => <button key={p.value} type="button" aria-pressed={v.provider === p.value} onClick={() => pick(p.value)}
              className={`rounded-md border px-3 py-2 text-left text-sm transition-colors ${v.provider === p.value ? 'border-primary bg-primary/5 font-medium' : 'hover:bg-muted'}`}>{p.label}</button>)}
          </div>
          <p className="text-xs text-muted-foreground">{choices.find(p => p.value === v.provider)?.hint}</p>
          {sso && <p className="text-xs text-muted-foreground">Company SSO needs a provider that can be limited to {organization ? `${organization.name}'s` : 'the organization\'s'} accounts. GitHub and Apple accounts are personal, so they are only offered as social login.</p>}
        </fieldset>

        {sso && !organization && field('organization_id', 'Organization', <SearchSelect id={`${id}-organization_id`} name="organization_id" path={`${base}/organizations`} mapItem={named} required disabled={busy} placeholder="Search organizations…" onChange={value => setV(prev => ({ ...prev, organization_id: value, domains: [] }))} />,
          'The company whose employees sign in with this provider. You can turn on automatic account creation and make SSO mandatory after creating it.')}

        {field('name', 'Name', <Input id={`${id}-name`} value={v.name} required disabled={busy} placeholder={sso ? 'e.g. Globex Entra ID' : undefined} onChange={e => set('name', e.target.value)} />, social ? 'Shown on the button: "Continue with …".' : 'Helps you recognize it in this console.')}
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

        {v.provider === 'google' && field('domains', workspace ? 'Workspace domains' : 'Workspace domains (optional)',
          <TagInput key={`${v.organization_id}:${verified.join(',')}`} id={`${id}-domains`} name="domains" defaultValue={v.domains} disabled={busy} placeholder="example.com, then Enter…" onChange={tags => set('domains', tags)} />,
          workspace
            ? verified.length ? "Only Google accounts of these Workspace domains can sign in. Filled in from the organization's verified domains." : "Only Google accounts of these Workspace domains can sign in. Personal Gmail accounts are refused."
            : 'Only Google Workspace accounts of these domains can sign in. Leave empty to accept any Google account.')}

        {v.provider === 'apple' && <div className="grid grid-cols-2 gap-3">
          {field('team_id', 'Team ID', <Input id={`${id}-team_id`} value={v.team_id} required disabled={busy} placeholder="ABCDE12345" onChange={e => set('team_id', e.target.value)} />)}
          {field('key_id', 'Key ID', <Input id={`${id}-key_id`} value={v.key_id} required disabled={busy} placeholder="KEY1234567" onChange={e => set('key_id', e.target.value)} />)}
        </div>}

        {field('client_id', v.provider === 'apple' ? 'Services ID' : 'Client ID', <Input id={`${id}-client_id`} value={v.client_id} required disabled={busy} placeholder={v.provider === 'apple' ? 'com.example.web' : undefined} onChange={e => set('client_id', e.target.value)} />)}
        {v.provider === 'apple'
          ? field('client_secret', 'Private key (.p8)', <textarea id={`${id}-client_secret`} className="min-h-24 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" value={v.client_secret} required disabled={busy} placeholder="-----BEGIN PRIVATE KEY-----" onChange={e => set('client_secret', e.target.value)} />,
            'Stored encrypted; IAMKit signs a short-lived client secret with it for each login.')
          : <>
            {field('client_secret', 'Client secret', <Input id={`${id}-client_secret`} type="password" autoComplete="new-password" value={v.client_secret} required={!v.secret_env.trim()} disabled={busy || !!v.secret_env.trim()} onChange={e => set('client_secret', e.target.value)} />,
              v.secret_env.trim() ? 'Not needed: the secret is read from the server variable below.' : 'Stored encrypted; never shown again. Requires IAMKIT_ENCRYPTION_KEY.')}
            <div className="space-y-2">
              <button type="button" aria-expanded={advanced} aria-controls={`${id}-advanced`} disabled={busy} onClick={() => setAdvanced(a => !a)}
                className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground">
                <ChevronRight className={`size-3.5 transition-transform ${advanced ? 'rotate-90' : ''}`} aria-hidden />Advanced
              </button>
              {advanced && <div id={`${id}-advanced`} className="space-y-1.5 rounded-md border p-3">
                {field('secret_env', 'Server environment variable (instead of the secret)', <Input id={`${id}-secret_env`} value={v.secret_env} disabled={busy || !!v.client_secret} placeholder="IAMKIT_PROVIDER_…" onChange={e => set('secret_env', e.target.value)} />,
                  v.client_secret
                    ? 'Clear the client secret above to use this instead.'
                    : 'Older setups only. The name of a variable on the IAMKit server that holds the secret, approved by your server admin. Most people should paste the client secret above.')}
              </div>}
            </div>
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
