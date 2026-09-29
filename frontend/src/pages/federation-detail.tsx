import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { SearchSelect } from '@/components/ui/search-select'
import { ConfirmDialog, DataTable, FormDialog, ID, PageHeader, Status, type Field } from '@/components/library/patterns'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { providerLabel, oauth2Options, samlOptions, ldapOptions } from './federation-connection-form'

export interface ConnectionDetail {
  id: string; organization_id: string | null; name: string; issuer: string; client_id: string
  provider?: string; options?: {
    tenant?: string; tenants?: string[]; domains?: string[]; team_id?: string; key_id?: string; base_url?: string
    authorize_url?: string; token_url?: string; userinfo_url?: string; scopes?: string[]
    claims?: { subject?: string; email?: string; email_verified?: string; name?: string }
    metadata_url?: string; metadata_xml?: string; name_id_format?: string; sign_requests?: boolean
    attributes?: { subject?: string; email?: string; name?: string }
    url?: string; start_tls?: boolean; bind_dn?: string; user_base_dn?: string; user_filter?: string; ca_pem?: string
  }
  saml?: { entity_id: string; acs_url: string; metadata_url: string }
  secret_env: string; secret_source: 'env' | 'sealed' | 'none'; active: boolean; linked: number
  jit_provisioning: boolean; jit_group_id: string | null; enforcement: 'optional' | 'enforced'
  signup?: boolean; link_email?: boolean; signup_organization_id?: string | null; signup_group_id?: string | null
  update_profile?: boolean; callback_url?: string; created_at: string
}
interface ExternalIdentity {
  connection_id: string; subject: string
  user_id: string; user_name: string; user_email: string
  origin: 'linked' | 'jit' | 'email' | 'signup'; created_at: string
}

const origins: Record<string, string> = { jit: 'Just-in-time', email: 'Verified email', signup: 'Sign-up', linked: 'Linked' }
const tenants: Record<string, string> = { common: 'Work, school and personal accounts', organizations: 'Work and school accounts', consumers: 'Personal accounts' }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.email || item.id), inactive: item.active === false })

export default function FederationDetailPage() {
  const { project, environment, connectionId } = useParams()
  const base = `/environments/${environment}`
  const backPath = `/projects/${project}/environments/${environment}/federation`

  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'

  const [conn, setConn] = useState<ConnectionDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const identities = usePaginatedList<ExternalIdentity>(`${base}/federation-connections/${connectionId}/identities`)

  const [linking, setLinking] = useState(false)
  const [unlinking, setUnlinking] = useState<ExternalIdentity | null>(null)
  const [editing, setEditing] = useState(false)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    if (!environment || !connectionId) return
    setLoading(true)
    api.get<ConnectionDetail>(`${base}/federation-connections/${connectionId}`)
      .then(data => { setConn(data); setLoading(false); setError('') })
      .catch(e => { setError(message(e)); setLoading(false) })
  }, [environment, connectionId, base, version])

  if (loading) return <div className="space-y-6">
    <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to sign-in providers
    </Link>
    <p className="text-sm text-muted-foreground">Loading connection…</p>
  </div>

  if (error || !conn) return <div className="space-y-6">
    <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
      <ArrowLeft className="size-3.5" />Back to sign-in providers
    </Link>
    <p className="text-sm text-destructive">{error || 'Connection not found'}</p>
  </div>

  return <div className="space-y-8">
    <div className="space-y-3">
      <Link to={backPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to sign-in providers
      </Link>
      <PageHeader title={conn.name} description={conn.id} actions={<div className="flex items-center gap-2">
        <Status active={conn.active} />
        {canWrite && conn.active && <Button variant="outline" onClick={() => setEditing(true)}><Pencil className="size-4" /> Edit</Button>}
      </div>} />
    </div>

    {/* Connection info */}
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <InfoCard label="Provider" value={providerLabel(conn.provider ?? 'oidc')} />
      <InfoCard label="Scope" value={conn.organization_id ? `Organization ${conn.organization_id}` : 'Environment-wide'} mono={!!conn.organization_id} />
      <InfoCard label={conn.saml ? 'IdP entity ID' : conn.provider === 'ldap' ? 'Directory' : 'Issuer'} value={conn.issuer + (conn.options?.start_tls ? ' (StartTLS)' : '')} mono />
      {conn.provider === 'ldap' ? <>
        <InfoCard label="User base DN" value={conn.options?.user_base_dn ?? ''} mono />
        <InfoCard label="User filter" value={conn.options?.user_filter || '(|(mail={email})(userPrincipalName={email}))'} mono />
        <InfoCard label="Service account" value={conn.options?.bind_dn || 'Anonymous search'} mono={!!conn.options?.bind_dn} />
        <InfoCard label="Certificate trust" value={conn.options?.ca_pem ? 'Custom CA certificate' : 'System roots'} />
        {conn.options?.attributes && <InfoCard label="Attributes" value={Object.entries(conn.options.attributes).map(([k, name]) => `${k} ← ${name}`).join(', ')} mono />}
      </> : conn.saml ? <>
        <InfoCard label="SP entity ID (audience)" value={conn.saml.entity_id} mono />
        <InfoCard label="ACS URL (HTTP-POST)" value={conn.saml.acs_url} mono />
        <InfoCard label="SP metadata URL" value={conn.saml.metadata_url} mono />
        <InfoCard label="IdP metadata" value={conn.options?.metadata_url || 'Pasted XML'} mono={!!conn.options?.metadata_url} />
        <InfoCard label="NameID / attributes" value={`${conn.options?.name_id_format || 'unspecified'}` + (conn.options?.attributes ? ' · ' + Object.entries(conn.options.attributes).map(([k, name]) => `${k} ← ${name}`).join(', ') : '') + (conn.options?.sign_requests ? ' · signed requests' : '')} mono />
      </> : <InfoCard label={conn.provider === 'apple' ? 'Services ID' : 'Client ID'} value={conn.client_id} mono />}
      {conn.provider === 'microsoft' && conn.options?.tenant && <InfoCard label="Accounts" value={(tenants[conn.options.tenant] ?? `Tenant ${conn.options.tenant}`) + (conn.options.tenants?.length ? ` · only ${conn.options.tenants.length} allowed tenant${conn.options.tenants.length > 1 ? 's' : ''}` : '')} />}
      {conn.provider === 'apple' && <InfoCard label="Apple team / key" value={`${conn.options?.team_id ?? ''} / ${conn.options?.key_id ?? ''}`} mono />}
      {conn.provider === 'google' && <InfoCard label="Accounts" value={conn.options?.domains?.length ? `Google Workspace: ${conn.options.domains.join(', ')}` : 'Any Google account'} />}
      {conn.options?.base_url && <InfoCard label={conn.provider === 'gitlab' ? 'GitLab URL' : 'Server URL'} value={conn.options.base_url} mono />}
      {conn.provider === 'oauth2' && <>
        <InfoCard label="Endpoints" value={`${conn.options?.authorize_url ?? ''} · ${conn.options?.token_url ?? ''} · ${conn.options?.userinfo_url ?? ''}`} mono />
        <InfoCard label="Claim mapping" value={Object.entries(conn.options?.claims ?? {}).map(([k, path]) => `${k} ← ${path}`).join(', ') + (conn.options?.claims?.email_verified ? '' : ' (email never verified)')} mono />
      </>}
      <InfoCard label="Profile sync" value={conn.update_profile ? 'On: name and passwordless emails follow the provider at every sign-in' : 'Off'} />
      {!conn.organization_id && <>
        <InfoCard label="Sign-up" value={conn.signup ? (conn.signup_group_id ? `On, joins organization ${conn.signup_organization_id} and group ${conn.signup_group_id}` : `On, joins organization ${conn.signup_organization_id}`) : 'Off: only existing or linked users'} />
        <InfoCard label="Email linking" value={conn.link_email ? 'On: verified email signs in to the matching account' : 'Off'} />
      </>}
      {conn.callback_url && !conn.saml && <InfoCard label="Redirect URI" value={conn.callback_url} mono />}
      {conn.secret_source !== 'none' && <InfoCard label={conn.provider === 'ldap' ? 'Service account password' : 'Client secret'} value={conn.secret_source === 'sealed' ? 'Stored encrypted' : `Env variable ${conn.secret_env}`} mono={conn.secret_source !== 'sealed'} />}
      {conn.organization_id && <>
        <InfoCard label="Just-in-time provisioning" value={conn.jit_provisioning ? (conn.jit_group_id ? `On, joins group ${conn.jit_group_id}` : 'On, no default group') : 'Off'} />
        <InfoCard label="Enforcement" value={conn.enforcement === 'enforced' ? 'Enforced: password login blocked for verified domains' : 'Optional'} />
        <InfoCard label="Email linking" value={conn.link_email ? "On: members on the organization's verified domains are linked by email" : 'Off'} />
      </>}
    </div>

    {/* Linked identities */}
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-mono text-lg font-semibold">Linked identities</h2>
          <p className="text-sm text-muted-foreground">Users authenticated through this provider.</p>
        </div>
        {canWrite && <Button variant="outline" onClick={() => setLinking(true)}><Plus className="size-4" /> Link identity</Button>}
      </div>

      <PaginationBar state={identities} noun="identities" />

      <DataTable
        columns={['User', 'Subject', 'Origin', ...(canWrite ? ['Actions'] : [])]}
        loading={identities.loading}
        error={identities.error}
        retry={identities.reload}
        rows={identities.data.map(id => {
          const cells: React.ReactNode[] = [
            <div className="space-y-1">
              <p className="font-medium">{id.user_name}</p>
              <p className="text-xs text-muted-foreground">{id.user_email}</p>
              <ID value={id.user_id} />
            </div>,
            <span className="break-all font-mono text-xs">{id.subject}</span>,
            <span className="text-xs text-muted-foreground" title={id.created_at ? new Date(id.created_at).toLocaleString() : undefined}>{origins[id.origin] ?? 'Linked'}</span>,
          ]
          if (canWrite) cells.push(
            <Button variant="ghost" size="icon" aria-label={`Unlink ${id.user_name || id.user_id}`} onClick={() => setUnlinking(id)}>
              <Trash2 className="size-4" />
            </Button>,
          )
          return cells
        })}
      />
    </div>

    {/* Link identity dialog */}
    {linking && <LinkIdentityDialog
      base={base}
      connectionId={connectionId!}
      onClose={() => setLinking(false)}
      onLinked={() => { identities.reload(); setLinking(false); setConn(c => c ? { ...c, linked: c.linked + 1 } : c) }}
    />}

    {editing && <FormDialog
      title="Edit connection"
      description={conn.organization_id ? 'Leave the secret empty to keep the current one. Enforcement requires a verified domain.' : 'Leave the secret empty to keep the current one. Sign-up needs an organization for new users.'}
      fields={editFields(conn, base)}
      onClose={() => setEditing(false)}
      submit={async values => {
        await api.patch(`${base}/federation-connections/${connectionId}`, connectionPatch(conn, values))
        setVersion(v => v + 1)
      }}
    />}

    {/* Unlink confirm */}
    {unlinking && (
      <ConfirmDialog
        title={`Unlink ${unlinking.user_name || 'this user'}?`}
        description={`${unlinking.user_name || unlinking.user_id} can no longer sign in through this connection. Their user account and other sign-in methods are kept.`}
        confirmLabel="Unlink"
        onClose={() => setUnlinking(null)}
        confirm={async () => {
          await api.delete(`${base}/external-identities/${connectionId}/${unlinking.user_id}`)
          toast.success('Identity unlinked')
          identities.reload()
          setConn(c => c ? { ...c, linked: Math.max(0, c.linked - 1) } : c)
        }}
      />
    )}
  </div>
}

export function editFields(conn: ConnectionDetail, base: string): Field[] {
  const apple = conn.provider === 'apple'
  const fields: Field[] = [{ name: 'name', label: 'Name', value: conn.name }]
  if (conn.provider === 'saml') {
    const o = conn.options ?? {}
    fields.push(
      { name: 'metadata_url', label: 'IdP metadata URL', optional: true, value: o.metadata_url ?? '', hint: 'Saving refetches it (a new signing certificate, for instance). Empty keeps the pasted XML unless you paste new XML below.' },
      { name: 'metadata_xml', label: 'New IdP metadata XML', optional: true, value: '', hint: 'Replaces the metadata; the IdP entity ID must stay the same.' },
      { name: 'name_id_format', label: 'NameID format', type: 'dropdown', value: o.name_id_format || 'unspecified', options: [{ label: 'Unspecified', value: 'unspecified' }, { label: 'Persistent', value: 'persistent' }, { label: 'Email address', value: 'email' }, { label: 'Transient', value: 'transient' }] },
      { name: 'attr_subject', label: 'User ID attribute', optional: true, value: o.attributes?.subject ?? '', hint: 'Required with transient NameIDs.' },
      { name: 'attr_email', label: 'Email attribute', optional: true, value: o.attributes?.email ?? '' },
      { name: 'attr_name', label: 'Name attribute', optional: true, value: o.attributes?.name ?? '' },
      { name: 'sign_requests', label: 'Sign authentication requests', type: 'checkbox', value: !!o.sign_requests },
    )
  } else if (conn.provider === 'ldap') {
    const o = conn.options ?? {}
    fields.push(
      { name: 'ldap_url', label: 'Server URL', value: o.url ?? conn.issuer, hint: 'Same host and port; ldaps:// or ldap:// with StartTLS.' },
      { name: 'start_tls', label: 'Use StartTLS (ldap:// only)', type: 'checkbox', value: !!o.start_tls },
      { name: 'user_base_dn', label: 'User base DN', value: o.user_base_dn ?? '', hint: 'Cannot change: create another connection for another subtree.' },
      { name: 'user_filter', label: 'User filter', optional: true, value: o.user_filter ?? '', hint: 'With {email} or {username}; empty uses (|(mail={email})(userPrincipalName={email})).' },
      { name: 'bind_dn', label: 'Service account DN', optional: true, value: o.bind_dn ?? '', hint: 'Empty searches anonymously.' },
      { name: 'client_secret', label: conn.secret_source === 'sealed' ? 'New service account password' : 'Service account password', type: 'password', optional: true, hint: 'Stored encrypted. Needed when you set a service account DN for the first time.' },
      { name: 'ca_pem', label: 'CA certificate (PEM)', optional: true, value: o.ca_pem ?? '', hint: 'Empty trusts the system roots.' },
      { name: 'attr_subject', label: 'User ID attribute', optional: true, value: o.attributes?.subject ?? '', hint: 'Empty: objectGUID, entryUUID, else the DN.' },
      { name: 'attr_email', label: 'Email attribute', optional: true, value: o.attributes?.email ?? '' },
      { name: 'attr_name', label: 'Name attribute', optional: true, value: o.attributes?.name ?? '' },
    )
  } else fields.push(
    { name: 'client_secret', label: apple ? 'New private key (.p8)' : conn.secret_source === 'sealed' ? 'New client secret' : 'Client secret (replaces env variable)', type: 'password', optional: true, hint: apple ? 'Paste the whole key, including the BEGIN and END lines. Stored encrypted.' : 'Stored encrypted.' },
  )
  if (apple) fields.push({ name: 'key_id', label: 'Key ID', value: conn.options?.key_id ?? '', hint: 'Change it together with the new private key.' })
  if (conn.provider === 'microsoft' && (conn.options?.tenant === 'common' || conn.options?.tenant === 'organizations')) {
    fields.push({ name: 'tenants', label: 'Allowed tenants', type: 'tags', optional: true, tags: conn.options?.tenants ?? [], hint: 'Only these tenant IDs may sign in; empty accepts any tenant.' })
  }
  if (conn.provider === 'google') {
    fields.push({ name: 'domains', label: 'Workspace domains', type: 'tags', optional: true, tags: conn.options?.domains ?? [], hint: conn.organization_id ? "Only Google accounts of these Workspace domains can sign in. Keep the organization's domains here." : 'Only Google Workspace accounts of these domains can sign in; empty accepts any Google account.' })
  }
  if (conn.provider === 'oauth2') {
    const o = conn.options ?? {}
    fields.push(
      { name: 'authorize_url', label: 'Authorization URL', value: o.authorize_url ?? '', hint: 'Must stay on the same host.' },
      { name: 'token_url', label: 'Token URL', value: o.token_url ?? '' },
      { name: 'userinfo_url', label: 'User info URL', value: o.userinfo_url ?? '' },
      { name: 'scopes', label: 'Scopes', type: 'tags', optional: true, tags: o.scopes ?? [] },
      { name: 'claim_subject', label: 'User ID member', value: o.claims?.subject ?? '' },
      { name: 'claim_email', label: 'Email member', optional: true, value: o.claims?.email ?? '' },
      { name: 'claim_email_verified', label: 'Email verified member', optional: true, value: o.claims?.email_verified ?? '', hint: 'Empty: the email is never trusted.' },
      { name: 'claim_name', label: 'Name member', optional: true, value: o.claims?.name ?? '' },
    )
  }
  fields.push({ name: 'update_profile', label: 'Keep profiles in sync', type: 'checkbox', value: !!conn.update_profile, hint: "Update the user's name, and the email of passwordless accounts, at every sign-in." })
  if (!conn.organization_id) return [...fields,
    { name: 'link_email', label: 'Link existing accounts by verified email', type: 'checkbox', value: !!conn.link_email },
    { name: 'signup', label: 'Create accounts for new users', type: 'checkbox', value: !!conn.signup },
    { name: 'signup_organization_id', label: 'Sign-up organization', type: 'select', optional: true, value: conn.signup_organization_id ?? '', selectPath: `${base}/organizations`, selectMap: named, hint: 'Required for sign-up.' },
    ...(conn.signup_organization_id ? [{ name: 'signup_group_id', label: 'Sign-up default group', type: 'select' as const, optional: true, value: conn.signup_group_id ?? '', selectPath: `${base}/organizations/${conn.signup_organization_id}/groups`, selectMap: named, hint: 'Save a new organization first to pick one of its groups.' }] : []),
  ]
  return [...fields,
    { name: 'jit_provisioning', label: 'Just-in-time provisioning', type: 'checkbox', value: conn.jit_provisioning },
    { name: 'jit_group_id', label: 'Default group', type: 'select', optional: true, value: conn.jit_group_id ?? '', selectPath: `${base}/organizations/${conn.organization_id}/groups`, selectMap: named, hint: 'Users provisioned on first login join this operator-managed group.' },
    { name: 'enforcement', label: 'Enforcement', type: 'dropdown', value: conn.enforcement, options: [{ label: 'Optional', value: 'optional' }, { label: 'Enforced', value: 'enforced' }] },
    { name: 'link_email', label: 'Link members by email', type: 'checkbox', value: !!conn.link_email, hint: "A member whose provider email is on the organization's verified domains signs in to their account, even without just-in-time provisioning." },
  ]
}

// connectionPatch sends only what the form may change; an empty default
// group clears it.
export function connectionPatch(conn: ConnectionDetail, values: Record<string, string | boolean>) {
  const patch: Record<string, unknown> = {}
  if (values.name !== conn.name) patch.name = values.name
  if (values.client_secret) patch.client_secret = values.client_secret
  if (conn.provider === 'apple' && typeof values.key_id === 'string' && values.key_id !== (conn.options?.key_id ?? '')) patch.options = { ...conn.options, key_id: values.key_id }
  if (typeof values.tenants === 'string') {
    const next = values.tenants.split(',').map(t => t.trim()).filter(Boolean)
    if (next.join(',') !== (conn.options?.tenants ?? []).join(',')) patch.options = { ...conn.options, tenants: next }
  }
  if (typeof values.domains === 'string') {
    const next = values.domains.split(',').map(d => d.trim()).filter(Boolean)
    if (next.join(',') !== (conn.options?.domains ?? []).join(',')) patch.options = { ...conn.options, domains: next }
  }
  if (conn.provider === 'saml' && typeof values.name_id_format === 'string') {
    // New XML replaces the metadata; a URL is refetched at every save (a
    // rotated IdP certificate); with neither, the stored XML stays.
    const str = (key: string) => typeof values[key] === 'string' ? (values[key] as string).trim() : ''
    const o = conn.options ?? {}
    const xml = str('metadata_xml'), url = str('metadata_url')
    const next = samlOptions({ metadata_url: url, metadata_xml: xml || (url ? '' : o.metadata_xml ?? ''), name_id_format: str('name_id_format'), attr_subject: str('attr_subject'), attr_email: str('attr_email'), attr_name: str('attr_name'), sign_requests: values.sign_requests === true })
    const was = samlOptions({ metadata_url: o.metadata_url ?? '', metadata_xml: o.metadata_url ? '' : o.metadata_xml ?? '', name_id_format: o.name_id_format || 'unspecified', attr_subject: o.attributes?.subject ?? '', attr_email: o.attributes?.email ?? '', attr_name: o.attributes?.name ?? '', sign_requests: !!o.sign_requests })
    if (xml || url || JSON.stringify(next) !== JSON.stringify(was)) patch.options = next
  }
  if (conn.provider === 'ldap' && typeof values.ldap_url === 'string') {
    const str = (key: string) => typeof values[key] === 'string' ? values[key] as string : ''
    const o = conn.options ?? {}
    const next = ldapOptions({ ldap_url: str('ldap_url'), start_tls: values.start_tls === true, bind_dn: str('bind_dn'), user_base_dn: str('user_base_dn'), user_filter: str('user_filter'), ca_pem: str('ca_pem'), attr_subject: str('attr_subject'), attr_email: str('attr_email'), attr_name: str('attr_name') })
    const was = ldapOptions({ ldap_url: o.url ?? '', start_tls: !!o.start_tls, bind_dn: o.bind_dn ?? '', user_base_dn: o.user_base_dn ?? '', user_filter: o.user_filter ?? '', ca_pem: o.ca_pem ?? '', attr_subject: o.attributes?.subject ?? '', attr_email: o.attributes?.email ?? '', attr_name: o.attributes?.name ?? '' })
    if (JSON.stringify(next) !== JSON.stringify(was)) patch.options = next
    if (!next.bind_dn) delete patch.client_secret
  }
  if (conn.provider === 'oauth2' && typeof values.authorize_url === 'string') {
    const str = (key: string) => typeof values[key] === 'string' ? values[key] as string : ''
    const next = oauth2Options({
      authorize_url: str('authorize_url'), token_url: str('token_url'), userinfo_url: str('userinfo_url'),
      scopes: str('scopes').split(',').map(t => t.trim()).filter(Boolean),
      claim_subject: str('claim_subject'), claim_email: str('claim_email'), claim_email_verified: str('claim_email_verified'), claim_name: str('claim_name'),
    })
    const was = conn.options ?? {}
    if (JSON.stringify(next) !== JSON.stringify(oauth2Options({
      authorize_url: was.authorize_url ?? '', token_url: was.token_url ?? '', userinfo_url: was.userinfo_url ?? '', scopes: was.scopes ?? [],
      claim_subject: was.claims?.subject ?? '', claim_email: was.claims?.email ?? '', claim_email_verified: was.claims?.email_verified ?? '', claim_name: was.claims?.name ?? '',
    }))) patch.options = next
  }
  if (values.update_profile !== undefined && values.update_profile !== !!conn.update_profile) patch.update_profile = values.update_profile
  if (values.link_email !== undefined && values.link_email !== !!conn.link_email) patch.link_email = values.link_email
  if (!conn.organization_id) {
    if (values.signup !== undefined && values.signup !== !!conn.signup) patch.signup = values.signup
    const org = values.signup ? values.signup_organization_id : ''
    if (values.signup && org !== (conn.signup_organization_id ?? '')) { patch.signup_organization_id = org; patch.signup_group_id = '' }
    else if (values.signup && values.signup_group_id !== undefined && values.signup_group_id !== (conn.signup_group_id ?? '')) patch.signup_group_id = values.signup_group_id
  }
  if (conn.organization_id) {
    if (values.jit_provisioning !== conn.jit_provisioning) patch.jit_provisioning = values.jit_provisioning
    if (values.jit_group_id !== (conn.jit_group_id ?? '')) patch.jit_group_id = values.jit_group_id
    if (values.enforcement !== conn.enforcement) patch.enforcement = values.enforcement
  }
  return patch
}

function InfoCard({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="rounded-lg border bg-card p-4">
    <p className="text-xs font-medium text-muted-foreground">{label}</p>
    <p className={`mt-1 text-sm ${mono ? 'break-all font-mono' : ''}`}>{value}</p>
  </div>
}

function LinkIdentityDialog({ base, connectionId, onClose, onLinked }: { base: string; connectionId: string; onClose: () => void; onLinked: () => void }) {
  const [userId, setUserId] = useState('')
  const [subject, setSubject] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">Link external identity</DialogTitle>
      <DialogDescription className="text-muted-foreground">Link a user to this provider by their external subject identifier.</DialogDescription>
      <form className="space-y-4" onSubmit={async e => {
        e.preventDefault()
        if (!userId || !subject.trim() || busy) return
        setBusy(true); setError('')
        try {
          await api.post(`${base}/external-identities`, { connection_id: connectionId, user_id: userId, subject: subject.trim() })
          toast.success('Identity linked')
          onLinked()
        } catch (err) { setError(message(err)) } finally { setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">User</label>
          <SearchSelect
            name="user_id"
            path={`${base}/users`}
            mapItem={named}
            required
            disabled={busy}
            placeholder="Search users…"
            onChange={setUserId}
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">External subject</label>
          <Input
            value={subject}
            onChange={e => setSubject(e.target.value)}
            required
            disabled={busy}
            placeholder="e.g. 110248495921238986420"
          />
          <p className="text-xs text-muted-foreground">The unique identifier from the identity provider (OIDC sub claim).</p>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={busy || !userId || !subject.trim()}>{busy ? 'Linking…' : 'Link'}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}
