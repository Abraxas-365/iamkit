import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { AppWindow, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, DataTable, EmptyState, FormDialog, PageHeader, type Field } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

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
    if (!name || !source) throw new Error(t('Attribute "{{tag}}" must be written name=source', { tag }))
    if (!attributeSources.includes(source)) throw new Error(t('Attribute “{{name}}”: source must be one of {{sources}}', { name, sources: attributeSources.join(', ') }))
    out[name] = source
  }
  return out
}

const nameIDOptions = [
  { value: 'email', label: t('Email address'), description: t('NameID is the user\'s email (format emailAddress).') },
  { value: 'persistent', label: t('User ID'), description: t('NameID is IAMKit\'s stable user ID (format persistent).') },
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
  // The deployment's saml_idp feature off: the SAML routes are absent (404).
  const [off, setOff] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    api.get<IdentityProvider>(`${base}/saml/identity-provider`, controller.signal).then(setIdP)
      .catch(e => { if (!controller.signal.aborted && e instanceof ApiError && e.status === 404) setOff(true) })
    return () => controller.abort()
  }, [base])
  const [editing, setEditing] = useState<ServiceProvider | 'new' | null>(null)
  const [removing, setRemoving] = useState<ServiceProvider | null>(null)

  const fields = (sp?: ServiceProvider): Field[] => [
    { name: 'name', label: t('Name'), value: sp?.name ?? '' },
    ...(sp ? [] : [
      { name: 'application_id', label: t('Application'), type: 'select', selectPath: `${base}/applications`, selectMap: named } as Field,
      { name: 'resource_id', label: t('Resource'), type: 'select', selectPath: `${base}/resources`, selectMap: named, hint: t('Linked to the application; its permissions can be sent as an attribute.') } as Field,
      { name: 'entity_id', label: t('Entity ID'), hint: t('The service provider\'s entity ID (Issuer of its AuthnRequests), from its metadata.') } as Field,
    ]),
    { name: 'acs_urls', label: t('Assertion consumer service URLs'), type: 'tags', tags: sp?.acs_urls ?? [], hint: t('HTTPS URLs the signed response may be posted to; the first is the default.') },
    { name: 'name_id_format', label: t('NameID'), type: 'radio', value: sp?.name_id_format ?? 'email', options: nameIDOptions },
    { name: 'attributes', label: t('Attributes'), type: 'tags', optional: true, tags: Object.entries(sp?.attributes ?? {}).map(([k, v]) => `${k}=${v}`), hint: t('name=source, source one of {{sources}} (e.g. mail=email).', { sources: attributeSources.join(', ') }) },
  ]

  const save = async (data: Record<string, string | boolean>) => {
    const body = { name: data.name, acs_urls: list(data.acs_urls), name_id_format: data.name_id_format, attributes: parseAttributes(list(data.attributes)) }
    if (editing === 'new') await api.post(path, { ...body, application_id: data.application_id, resource_id: data.resource_id, entity_id: data.entity_id })
    else if (editing) await api.patch(`${path}/${editing.id}`, body)
    providers.reload()
  }

  const header = <PageHeader title={t('SAML applications')} description={t('Applications that sign users in with SAML 2.0, IAMKit being their identity provider. Users sign in on the hosted pages and are sent back with a signed assertion.')}
    actions={canWrite && !off && <Button onClick={() => setEditing('new')}><Plus /> {t('Add SAML application')}</Button>} />
  if (off) return <div className="space-y-6">{header}
    <EmptyState icon={<AppWindow />} title={t('SAML identity provider turned off')} description={t('This deployment does not serve IAMKit as a SAML identity provider (feature saml_idp, set with IAMKIT_FEATURES). Turn it on to register SAML applications.')} />
  </div>

  return <div className="space-y-6">
    {header}
    {idp && <section aria-label={t('Identity provider settings')} className="grid gap-3 rounded-lg border p-4 md:grid-cols-2">
      <CopyField label={t('Metadata URL')} value={idp.metadata_url} hint={t('Give this URL to the service provider, or the values below.')} />
      <CopyField label={t('Single sign-on URL')} value={idp.sso_url} />
      <CopyField label={t('Entity ID (Issuer)')} value={idp.entity_id} />
      <CopyField label={t('Signing certificate')} value={idp.certificate} hint={t('Changes when the environment\'s signing key is rotated; service providers reading the metadata pick it up.')} />
    </section>}
    <DataTable columns={[t('Name'), t('Entity ID'), t('Signs in to'), t('NameID'), t('Actions')]} loading={providers.loading} error={providers.error} retry={providers.reload}
      empty={<EmptyState icon={<AppWindow />} title={t('No SAML applications')} description={t('Register a service provider with its entity ID and assertion consumer service URL.')} />}
      rows={providers.data.map(sp => [
        <span className="font-medium">{sp.name}</span>,
        <code className="break-all text-xs">{sp.entity_id}</code>,
        <span>{sp.application_name} · {sp.resource_name}</span>,
        <Badge variant="secondary">{sp.name_id_format === 'email' ? t('Email') : t('User ID')}</Badge>,
        canWrite && <RowActions label={t('Actions for {{name}}', { name: sp.name })} actions={[
          { label: t('Edit'), icon: <Pencil />, onSelect: () => setEditing(sp) },
          { label: t('Delete'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(sp) },
        ]} />,
      ])} />
    {editing && <FormDialog title={editing === 'new' ? t('Add SAML application') : t('Edit {{name}}', { name: editing.name })} description={t('IAMKit accepts AuthnRequests only from this entity ID and posts responses only to these URLs.')}
      fields={fields(editing === 'new' ? undefined : editing)} submit={save} onClose={() => setEditing(null)} success={editing === 'new' ? t('SAML application added') : t('SAML application saved')} />}
    {removing && <ConfirmDialog title={t('Delete {{name}}?', { name: removing.name })} description={t('Its users can no longer sign in to it through IAMKit. Sessions already open in the application are not affected.')}
      confirmLabel={t('Delete application')} onClose={() => setRemoving(null)}
      confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success(t('SAML application deleted')); providers.reload() }} />}
  </div>
}
