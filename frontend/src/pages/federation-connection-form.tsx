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

export type Provider = 'oidc' | 'google' | 'microsoft' | 'github' | 'apple' | 'gitlab' | 'github_enterprise' | 'oauth2' | 'saml' | 'ldap'

export const providers: { value: Provider; label: string; hint: string }[] = [
  { value: 'google', label: 'Google', hint: 'Google accounts and Workspace. Create an OAuth client (Web application) in Google Cloud.' },
  { value: 'microsoft', label: 'Microsoft', hint: 'Microsoft Entra ID work accounts and personal Microsoft accounts. Register an app in Entra.' },
  { value: 'github', label: 'GitHub', hint: 'GitHub users (OAuth app). GitHub is OAuth 2.0, not OIDC: IAMKit reads the user and their verified primary email.' },
  { value: 'apple', label: 'Apple', hint: 'Sign in with Apple. Needs a Services ID, your Team ID, and a Sign in with Apple private key (.p8).' },
  { value: 'gitlab', label: 'GitLab', hint: 'gitlab.com or your self-managed GitLab (OpenID Connect). Create an application with the openid, profile and email scopes.' },
  { value: 'github_enterprise', label: 'GitHub Enterprise', hint: 'GitHub Enterprise Server at your own URL (OAuth app). Read like GitHub: the user and their verified primary email.' },
  { value: 'oidc', label: 'Other (OIDC)', hint: 'Any OpenID Connect provider with discovery (Okta, Auth0, Keycloak, ZITADEL, another IAMKit…).' },
  { value: 'oauth2', label: 'Other (OAuth 2.0)', hint: 'A provider without OpenID Connect (Discord, Slack, a custom server…): give its endpoints and where its user API keeps the ID, email and name.' },
]

export const providerLabel = (p: string) => p === 'saml' ? 'SAML 2.0' : p === 'ldap' ? 'LDAP / AD' : providers.find(x => x.value === p)?.label ?? 'OIDC'

// ssoProviders are the providers that can be an organization's own identity
// provider: each can be limited to the organization's accounts (a Microsoft
// tenant, Google Workspace domains, or an IdP that is the organization's
// own). GitHub and Apple accounts are personal, so they stay social login.
const ssoProviders: { value: Provider; label: string; hint: string }[] = [
  { value: 'microsoft', label: 'Microsoft Entra ID', hint: "The organization's Entra tenant. Register an app in Entra and pick the tenant it accepts." },
  { value: 'google', label: 'Google Workspace', hint: "The organization's Google Workspace. Only accounts of the Workspace domains below can sign in." },
  { value: 'gitlab', label: 'GitLab self-managed', hint: "The organization's own GitLab instance. Give its URL below." },
  { value: 'oidc', label: 'Other (OIDC)', hint: 'Okta, Auth0, Keycloak, OneLogin, ZITADEL, or any OpenID Connect provider with discovery.' },
  { value: 'saml', label: 'SAML 2.0', hint: 'Okta, Entra ID, ADFS, OneLogin, PingFederate, Google Workspace or any SAML 2.0 identity provider. Paste its metadata URL or XML.' },
  { value: 'ldap', label: 'LDAP / AD', hint: 'Active Directory, OpenLDAP, FreeIPA or any LDAP directory over TLS. Users type their directory password on the sign-in page; IAMKit checks it with the directory.' },
]

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

export interface ConnectionValues {
  provider: Provider; scope: 'environment' | 'organization'; organization_id: string
  name: string; issuer: string; client_id: string; client_secret: string; secret_env: string
  tenant: string; tenant_id: string; tenants: string[]; domains: string[]; team_id: string; key_id: string
  signup: boolean; signup_organization_id: string; signup_group_id: string; link_email: boolean
  base_url: string; authorize_url: string; token_url: string; userinfo_url: string; scopes: string[]
  claim_subject: string; claim_email: string; claim_email_verified: string; claim_name: string; update_profile: boolean
  metadata_url: string; metadata_xml: string; name_id_format: string; attr_subject: string; attr_email: string; attr_name: string; sign_requests: boolean
  ldap_url: string; start_tls: boolean; bind_dn: string; user_base_dn: string; user_filter: string; ca_pem: string
}

// ldapOptions are the options of an LDAP connection: the directory, its
// service account, where users live and how to find them.
export function ldapOptions(v: Pick<ConnectionValues, 'ldap_url' | 'start_tls' | 'bind_dn' | 'user_base_dn' | 'user_filter' | 'ca_pem' | 'attr_subject' | 'attr_email' | 'attr_name'>) {
  const options: Record<string, unknown> = { url: v.ldap_url.trim(), user_base_dn: v.user_base_dn.trim() }
  if (v.start_tls && v.ldap_url.trim().toLowerCase().startsWith('ldap://')) options.start_tls = true
  if (v.bind_dn.trim()) options.bind_dn = v.bind_dn.trim()
  if (v.user_filter.trim()) options.user_filter = v.user_filter.trim()
  if (v.ca_pem.trim()) options.ca_pem = v.ca_pem.trim()
  const attributes: Record<string, string> = {}
  if (v.attr_subject.trim()) attributes.subject = v.attr_subject.trim()
  if (v.attr_email.trim()) attributes.email = v.attr_email.trim()
  if (v.attr_name.trim()) attributes.name = v.attr_name.trim()
  if (Object.keys(attributes).length) options.attributes = attributes
  return options
}

// samlOptions are the options of a SAML connection: the identity
// provider's metadata (URL or XML), NameID format and attribute names.
export function samlOptions(v: Pick<ConnectionValues, 'metadata_url' | 'metadata_xml' | 'name_id_format' | 'attr_subject' | 'attr_email' | 'attr_name' | 'sign_requests'>) {
  const options: Record<string, unknown> = v.metadata_xml.trim() ? { metadata_xml: v.metadata_xml.trim() } : { metadata_url: v.metadata_url.trim() }
  if (v.name_id_format && v.name_id_format !== 'unspecified') options.name_id_format = v.name_id_format
  const attributes: Record<string, string> = {}
  if (v.attr_subject.trim()) attributes.subject = v.attr_subject.trim()
  if (v.attr_email.trim()) attributes.email = v.attr_email.trim()
  if (v.attr_name.trim()) attributes.name = v.attr_name.trim()
  if (Object.keys(attributes).length) options.attributes = attributes
  if (v.sign_requests) options.sign_requests = true
  return options
}

// oauth2Options are the options of an OAuth 2.0 connection: endpoints,
// scopes and where the userinfo response keeps the identity.
export function oauth2Options(v: Pick<ConnectionValues, 'authorize_url' | 'token_url' | 'userinfo_url' | 'scopes' | 'claim_subject' | 'claim_email' | 'claim_email_verified' | 'claim_name'>) {
  const claims: Record<string, string> = { subject: v.claim_subject.trim() }
  if (v.claim_email.trim()) claims.email = v.claim_email.trim()
  if (v.claim_email_verified.trim()) claims.email_verified = v.claim_email_verified.trim()
  if (v.claim_name.trim()) claims.name = v.claim_name.trim()
  return { authorize_url: v.authorize_url.trim(), token_url: v.token_url.trim(), userinfo_url: v.userinfo_url.trim(), ...(v.scopes.length ? { scopes: v.scopes } : {}), claims }
}

// connectionBody is the create request for the form values: presets derive
// their issuer, and only the options of the chosen provider are sent.
export function connectionBody(v: ConnectionValues): Record<string, unknown> {
  if (v.provider === 'ldap') {
    const body: Record<string, unknown> = { provider: 'ldap', name: v.name.trim(), organization_id: v.organization_id, options: ldapOptions(v) }
    if (v.bind_dn.trim() && v.client_secret) body.client_secret = v.client_secret
    if (v.update_profile) body.update_profile = true
    return body
  }
  if (v.provider === 'saml') {
    const body: Record<string, unknown> = { provider: 'saml', name: v.name.trim(), organization_id: v.organization_id, options: samlOptions(v) }
    if (v.update_profile) body.update_profile = true
    return body
  }
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
  if ((v.provider === 'gitlab' && v.base_url.trim()) || v.provider === 'github_enterprise') body.options = { base_url: v.base_url.trim() }
  if (v.provider === 'oauth2') body.options = oauth2Options(v)
  if (v.update_profile) body.update_profile = true
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
  base_url: '', authorize_url: '', token_url: '', userinfo_url: '', scopes: [], claim_subject: 'id', claim_email: 'email', claim_email_verified: '', claim_name: 'name', update_profile: false,
  metadata_url: '', metadata_xml: '', name_id_format: 'unspecified', attr_subject: '', attr_email: '', attr_name: '', sign_requests: false,
  ldap_url: '', start_tls: false, bind_dn: '', user_base_dn: '', user_filter: '', ca_pem: '',
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
    name: choices.some(p => p.label === prev.name) || prev.name === '' ? (provider === 'oidc' || provider === 'saml' || provider === 'ldap' ? '' : label(provider)) : prev.name,
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

        {(v.provider === 'gitlab' || v.provider === 'github_enterprise') && field('base_url', v.provider === 'gitlab' && !sso ? 'GitLab URL (optional)' : v.provider === 'gitlab' ? 'GitLab URL' : 'GitHub Enterprise URL',
          <Input id={`${id}-base_url`} value={v.base_url} required={v.provider === 'github_enterprise' || sso} disabled={busy} placeholder={v.provider === 'gitlab' ? 'https://gitlab.example.com' : 'https://github.example.com'} onChange={e => set('base_url', e.target.value)} />,
          v.provider === 'gitlab' ? (sso ? 'HTTPS URL of the self-managed instance.' : 'Leave empty for gitlab.com.') : 'HTTPS URL of the server; IAMKit uses its /login/oauth and /api/v3 endpoints. It cannot change later.')}

        {v.provider === 'oauth2' && <fieldset className="space-y-3 rounded-md border p-3" disabled={busy}>
          <legend className="px-1 text-sm font-medium">Endpoints</legend>
          {field('authorize_url', 'Authorization URL', <Input id={`${id}-authorize_url`} value={v.authorize_url} required placeholder="https://provider.example/oauth/authorize" onChange={e => set('authorize_url', e.target.value)} />, 'Its host identifies the provider and cannot change later.')}
          {field('token_url', 'Token URL', <Input id={`${id}-token_url`} value={v.token_url} required placeholder="https://provider.example/oauth/token" onChange={e => set('token_url', e.target.value)} />)}
          {field('userinfo_url', 'User info URL', <Input id={`${id}-userinfo_url`} value={v.userinfo_url} required placeholder="https://api.provider.example/me" onChange={e => set('userinfo_url', e.target.value)} />, 'Called with the access token; must answer JSON.')}
          {field('scopes', 'Scopes (optional)', <TagInput id={`${id}-scopes`} name="scopes" defaultValue={v.scopes} disabled={busy} placeholder="Scope, then Enter…" onChange={tags => set('scopes', tags)} />)}
          <p className="text-xs text-muted-foreground">Where the user info JSON keeps the identity. Use dots for nested members, e.g. <code>data.id</code>.</p>
          <div className="grid grid-cols-2 gap-3">
            {field('claim_subject', 'User ID', <Input id={`${id}-claim_subject`} value={v.claim_subject} required onChange={e => set('claim_subject', e.target.value)} />)}
            {field('claim_name', 'Name', <Input id={`${id}-claim_name`} value={v.claim_name} onChange={e => set('claim_name', e.target.value)} />)}
            {field('claim_email', 'Email', <Input id={`${id}-claim_email`} value={v.claim_email} onChange={e => set('claim_email', e.target.value)} />)}
            {field('claim_email_verified', 'Email verified', <Input id={`${id}-claim_email_verified`} value={v.claim_email_verified} placeholder="e.g. verified" onChange={e => set('claim_email_verified', e.target.value)} />)}
          </div>
          <p className="text-xs text-muted-foreground">Without an “email verified” member the email is never trusted: it cannot create or link accounts.</p>
        </fieldset>}

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

        {v.provider === 'saml' && <fieldset className="space-y-3 rounded-md border p-3" disabled={busy}>
          <legend className="px-1 text-sm font-medium">Identity provider</legend>
          {field('metadata_url', 'Metadata URL', <Input id={`${id}-metadata_url`} value={v.metadata_url} required={!v.metadata_xml.trim()} disabled={busy || !!v.metadata_xml.trim()} placeholder="https://idp.example.com/app/…/sso/saml/metadata" onChange={e => set('metadata_url', e.target.value)} />,
            'HTTPS; IAMKit fetches it now and when you update the connection. Or paste the XML below.')}
          {field('metadata_xml', 'Metadata XML', <textarea id={`${id}-metadata_xml`} className="min-h-20 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" value={v.metadata_xml} disabled={busy || !!v.metadata_url.trim()} placeholder="<EntityDescriptor …>" onChange={e => set('metadata_xml', e.target.value)} />)}
          {field('name_id_format', 'NameID format', <select id={`${id}-name_id_format`} className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" value={v.name_id_format} disabled={busy} onChange={e => set('name_id_format', e.target.value)}>
            <option value="unspecified">Unspecified (the provider decides)</option>
            <option value="persistent">Persistent</option>
            <option value="email">Email address</option>
            <option value="transient">Transient (map a user ID attribute below)</option>
          </select>, 'The NameID identifies the user unless a user ID attribute is mapped.')}
          <p className="text-xs text-muted-foreground">Attribute names (optional). Leave empty to use the NameID and the usual email and name attributes.</p>
          <div className="grid grid-cols-3 gap-3">
            {field('attr_subject', 'User ID', <Input id={`${id}-attr_subject`} value={v.attr_subject} required={v.name_id_format === 'transient'} placeholder="NameID" onChange={e => set('attr_subject', e.target.value)} />)}
            {field('attr_email', 'Email', <Input id={`${id}-attr_email`} value={v.attr_email} placeholder="email" onChange={e => set('attr_email', e.target.value)} />)}
            {field('attr_name', 'Name', <Input id={`${id}-attr_name`} value={v.attr_name} placeholder="displayName" onChange={e => set('attr_name', e.target.value)} />)}
          </div>
          {check('sign_requests', 'Sign authentication requests', 'For identity providers that require signed AuthnRequests. IAMKit signs with the environment signing key.')}
        </fieldset>}

        {v.provider === 'ldap' && <fieldset className="space-y-3 rounded-md border p-3" disabled={busy}>
          <legend className="px-1 text-sm font-medium">Directory</legend>
          {field('ldap_url', 'Server URL', <Input id={`${id}-ldap_url`} value={v.ldap_url} required disabled={busy} placeholder="ldaps://dc1.example.com" onChange={e => set('ldap_url', e.target.value)} />,
            'ldaps:// (port 636), or ldap:// (port 389) with StartTLS. Plaintext is refused. The host cannot change later.')}
          {v.ldap_url.trim().toLowerCase().startsWith('ldap://') && check('start_tls', 'Use StartTLS', 'Required for ldap:// URLs: the connection is upgraded to TLS before any password is sent.')}
          {field('ca_pem', 'CA certificate (optional)', <textarea id={`${id}-ca_pem`} className="min-h-16 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" value={v.ca_pem} disabled={busy} placeholder="-----BEGIN CERTIFICATE-----" onChange={e => set('ca_pem', e.target.value)} />,
            "PEM of the CA that signed the directory's certificate, for a private CA. Leave empty to trust the system roots.")}
          {field('bind_dn', 'Service account DN (optional)', <Input id={`${id}-bind_dn`} value={v.bind_dn} disabled={busy} placeholder="CN=iamkit,OU=Service Accounts,DC=example,DC=com" onChange={e => set('bind_dn', e.target.value)} />,
            'The account IAMKit binds as to search for users. Leave empty if the directory allows anonymous search.')}
          {v.bind_dn.trim() && field('client_secret', 'Service account password', <Input id={`${id}-client_secret`} type="password" autoComplete="new-password" value={v.client_secret} required disabled={busy} onChange={e => set('client_secret', e.target.value)} />,
            'Stored encrypted; never shown again. Requires IAMKIT_ENCRYPTION_KEY.')}
          {field('user_base_dn', 'User base DN', <Input id={`${id}-user_base_dn`} value={v.user_base_dn} required disabled={busy} placeholder="OU=People,DC=example,DC=com" onChange={e => set('user_base_dn', e.target.value)} />, 'The subtree searched for users. It cannot change later.')}
          {field('user_filter', 'User filter (optional)', <Input id={`${id}-user_filter`} value={v.user_filter} disabled={busy} placeholder="(|(mail={email})(userPrincipalName={email}))" onChange={e => set('user_filter', e.target.value)} />,
            '{email} is the typed email, {username} its part before @ (e.g. (sAMAccountName={username})). It must match exactly one entry.')}
          <p className="text-xs text-muted-foreground">Attribute names (optional). Leave empty for objectGUID / entryUUID, mail or userPrincipalName, and displayName.</p>
          <div className="grid grid-cols-3 gap-3">
            {field('attr_subject', 'User ID', <Input id={`${id}-attr_subject`} value={v.attr_subject} placeholder="objectGUID" onChange={e => set('attr_subject', e.target.value)} />)}
            {field('attr_email', 'Email', <Input id={`${id}-attr_email`} value={v.attr_email} placeholder="mail" onChange={e => set('attr_email', e.target.value)} />)}
            {field('attr_name', 'Name', <Input id={`${id}-attr_name`} value={v.attr_name} placeholder="displayName" onChange={e => set('attr_name', e.target.value)} />)}
          </div>
        </fieldset>}

        {v.provider !== 'saml' && v.provider !== 'ldap' && field('client_id', v.provider === 'apple' ? 'Services ID' : 'Client ID', <Input id={`${id}-client_id`} value={v.client_id} required disabled={busy} placeholder={v.provider === 'apple' ? 'com.example.web' : undefined} onChange={e => set('client_id', e.target.value)} />)}
        {v.provider === 'saml' || v.provider === 'ldap' ? null : v.provider === 'apple'
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

        {check('update_profile', 'Keep profiles in sync', "At every sign-in, update the user's name, and the email of accounts that sign in only through providers, from the provider.")}

        {v.provider === 'ldap'
          ? <div className="rounded-md bg-muted p-3 text-xs">
            <p className="font-medium">How users sign in</p>
            <p className="mt-1 text-muted-foreground">Emails on the organization's verified domains are asked for their directory password on the sign-in page. IAMKit must reach the server: private addresses need IAMKIT_LDAP_ALLOWED_HOSTS on the IAMKit server.</p>
          </div>
          : v.provider === 'saml'
          ? <div className="rounded-md bg-muted p-3 text-xs">
            <p className="font-medium">Service provider details</p>
            <p className="mt-1 text-muted-foreground">After creating, the connection page shows the ACS URL, entity ID and metadata URL to register with the identity provider.</p>
          </div>
          : <div className="rounded-md bg-muted p-3 text-xs">
            <p className="font-medium">Redirect URI to register with the provider</p>
            <code className="mt-1 block break-all select-all">{callback}</code>
          </div>}
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
