import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { AppWindow, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, DataTable, EmptyState, FormDialog, PageHeader, type Field } from '@/components/library/patterns'

/** GET /saml/service-providers item (samlidp.ServiceProvider). */
export interface ServiceProvider {
  id: string
  name: string
  application_id: string
  application_name: string
  resource_id: string
  resource_name: string
  entity_id: string
  acs_urls: string[]
  name_id_format: 'email' | 'persistent'
  attributes: Record<string, string>
  created_at: string
}

/** GET /saml/identity-provider (samlidp.IdentityProvider). */
interface IdentityProvider { entity_id: string; sso_url: string; metadata_url: string; certificate: string }

export const attributeSources = ['email', 'name', 'user_id', 'organization_id', 'permissions']

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })
const list = (raw: string | boolean) => String(raw).split(/[,\n]/).map(s => s.trim()).filter(Boolean)

/** parseAttributes turns `name=source` tags into the attribute map. */
export function parseAttributes(tags: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const tag of tags) {
    const [name, source] = tag.split('=').map(s => s.trim())
    if (!name || !source) throw new Error(`Attribute "${tag}" must be written name=source`)
    if (!attributeSources.includes(source)) throw new Error(`Attribute "${name}": source must be one of ${attributeSources.join(', ')}`)
    out[name] = source
  }
  return out
}

const nameIDOptions = [
  { value: 'email', label: 'Email address', description: 'NameID is the user\'s email (format emailAddress).' },
  { value: 'persistent', label: 'User ID', description: 'NameID is IAMKit\'s stable user ID (format persistent).' },
]

/** SAMLAppsPage registers applications that sign users in with SAML 2.0,
 * IAMKit being the identity provider. */
export default function SAMLAppsPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const path = `${base}/saml/service-providers`
  const providers = useList<ServiceProvider>(`${path}?limit=200`)
  const [idp, setIdP] = useState<IdentityProvider | null>(null)
  useEffect(() => {
    const controller = new AbortController()
    api.get<IdentityProvider>(`${base}/saml/identity-provider`, controller.signal).then(setIdP).catch(() => undefined)
    return () => controller.abort()
  }, [base])
  const [editing, setEditing] = useState<ServiceProvider | 'new' | null>(null)
  const [removing, setRemoving] = useState<ServiceProvider | null>(null)

  const fields = (sp?: ServiceProvider): Field[] => [
    { name: 'name', label: 'Name', value: sp?.name ?? '' },
    ...(sp ? [] : [
      { name: 'application_id', label: 'Application', type: 'select', selectPath: `${base}/applications`, selectMap: named } as Field,
      { name: 'resource_id', label: 'Resource', type: 'select', selectPath: `${base}/resources`, selectMap: named, hint: 'Linked to the application; its permissions can be sent as an attribute.' } as Field,
      { name: 'entity_id', label: 'Entity ID', hint: 'The service provider\'s entity ID (Issuer of its AuthnRequests), from its metadata.' } as Field,
    ]),
    { name: 'acs_urls', label: 'Assertion consumer service URLs', type: 'tags', tags: sp?.acs_urls ?? [], hint: 'HTTPS URLs the signed response may be posted to; the first is the default.' },
    { name: 'name_id_format', label: 'NameID', type: 'radio', value: sp?.name_id_format ?? 'email', options: nameIDOptions },
    { name: 'attributes', label: 'Attributes', type: 'tags', optional: true, tags: Object.entries(sp?.attributes ?? {}).map(([k, v]) => `${k}=${v}`), hint: `name=source, source one of ${attributeSources.join(', ')} (e.g. mail=email).` },
  ]

  const save = async (data: Record<string, string | boolean>) => {
    const body = { name: data.name, acs_urls: list(data.acs_urls), name_id_format: data.name_id_format, attributes: parseAttributes(list(data.attributes)) }
    if (editing === 'new') await api.post(path, { ...body, application_id: data.application_id, resource_id: data.resource_id, entity_id: data.entity_id })
    else if (editing) await api.patch(`${path}/${editing.id}`, body)
    providers.reload()
  }

  return <div className="space-y-6">
    <PageHeader title="SAML applications" description="Applications that sign users in with SAML 2.0, IAMKit being their identity provider. Users sign in on the hosted pages and are sent back with a signed assertion."
      actions={canWrite && <Button onClick={() => setEditing('new')}><Plus /> Add SAML application</Button>} />
    {idp && <section aria-label="Identity provider settings" className="grid gap-3 rounded-lg border p-4 md:grid-cols-2">
      <CopyField label="Metadata URL" value={idp.metadata_url} hint="Give this URL to the service provider, or the values below." />
      <CopyField label="Single sign-on URL" value={idp.sso_url} />
      <CopyField label="Entity ID (Issuer)" value={idp.entity_id} />
      <CopyField label="Signing certificate" value={idp.certificate} hint="Changes when the environment's signing key is rotated; service providers reading the metadata pick it up." />
    </section>}
    <DataTable columns={['Name', 'Entity ID', 'Signs in to', 'NameID', 'Actions']} loading={providers.loading} error={providers.error} retry={providers.reload}
      empty={<EmptyState icon={<AppWindow />} title="No SAML applications" description="Register a service provider with its entity ID and assertion consumer service URL." />}
      rows={providers.data.map(sp => [
        <span className="font-medium">{sp.name}</span>,
        <code className="break-all text-xs">{sp.entity_id}</code>,
        <span>{sp.application_name} · {sp.resource_name}</span>,
        <Badge variant="secondary">{sp.name_id_format === 'email' ? 'Email' : 'User ID'}</Badge>,
        canWrite && <RowActions label={`Actions for ${sp.name}`} actions={[
          { label: 'Edit', icon: <Pencil />, onSelect: () => setEditing(sp) },
          { label: 'Delete', icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(sp) },
        ]} />,
      ])} />
    {editing && <FormDialog title={editing === 'new' ? 'Add SAML application' : `Edit ${editing.name}`} description="IAMKit accepts AuthnRequests only from this entity ID and posts responses only to these URLs."
      fields={fields(editing === 'new' ? undefined : editing)} submit={save} onClose={() => setEditing(null)} success={editing === 'new' ? 'SAML application added' : 'SAML application saved'} />}
    {removing && <ConfirmDialog title={`Delete ${removing.name}?`} description="Its users can no longer sign in to it through IAMKit. Sessions already open in the application are not affected."
      confirmLabel="Delete application" onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success('SAML application deleted'); providers.reload() }} />}
  </div>
}
