import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { FileJson, Pencil, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog, DetailSection, EmptyState, ErrorState, PageHeader, Time } from '@/components/library/patterns'
import { JSONDialog } from '@/components/library/metadata-editor'
import { rich, t } from '@/lib/i18n'

/** GET/PUT /user-schema (user.Schema; PUT adds non_conforming). */
export interface UserSchema { schema: Record<string, unknown>; version: number; updated_at?: string; non_conforming?: number }

interface Property { name: string; type: string; self: string; claim: string; required: boolean }

/** properties lists the schema's top-level properties and annotations. */
export function properties(schema: Record<string, unknown>): Property[] {
  const props = (schema.properties ?? {}) as Record<string, Record<string, unknown>>
  const required = Array.isArray(schema.required) ? schema.required as string[] : []
  return Object.entries(props).sort(([a], [b]) => a.localeCompare(b)).map(([name, p]) => ({
    name,
    type: Array.isArray(p?.type) ? (p.type as string[]).join(' | ') : String(p?.type ?? (p?.$ref ? 'ref' : 'any')),
    self: String(p?.['x-iamkit-self'] ?? ''),
    claim: String(p?.['x-iamkit-claim'] ?? ''),
    required: required.includes(name),
  }))
}

const example = {
  type: 'object',
  additionalProperties: false,
  properties: {
    department: { type: 'string', enum: ['sales', 'engineering'], 'x-iamkit-claim': 'department', 'x-iamkit-self': 'read' },
    nickname: { type: 'string', maxLength: 40, 'x-iamkit-self': 'write' },
  },
}

/** UserSchemaPage edits the environment's user profile schema. */
export default function UserSchemaPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/user-schema`
  const [schema, setSchema] = useState<UserSchema | null | undefined>(undefined) // null: none saved
  const [error, setError] = useState('')
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const load = useCallback(() => {
    setError('')
    api.get<UserSchema>(path).then(setSchema).catch(e => e instanceof ApiError && e.status === 404 ? setSchema(null) : setError(message(e)))
  }, [path])
  useEffect(load, [load])

  const header = <PageHeader title={t('User schema')} description={t('A JSON Schema (2020-12) for user profile attributes. Profiles are checked on every write; annotated properties reach tokens and the user\'s self-service profile.')}
    actions={canWrite && schema !== undefined && <Button onClick={() => setEditing(true)}>{schema ? <><Pencil /> {t('Edit schema')}</> : <><FileJson /> {t('Create schema')}</>}</Button>} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (schema === undefined) return <div role="status" className="space-y-6">{header}<Skeleton className="h-64" /><span className="sr-only">{t('Loading schema…')}</span></div>

  return <div className="space-y-6">{header}
    {schema === null ? <EmptyState icon={<FileJson />} title={t('No user schema')} description={t('Profiles accept any JSON object until you save a schema.')} /> : <>
      <DetailSection title={t('Properties')} description={schema.updated_at ? rich('Version {{version}}, updated {{time}}.', { version: schema.version, time: <Time value={schema.updated_at} /> }) : t('Version {{version}}.', { version: schema.version })}>
        {properties(schema.schema).length === 0 ? <p className="text-sm text-muted-foreground">{t('The schema declares no properties.')}</p> :
          <div className="overflow-x-auto rounded-lg border"><table className="w-full text-sm">
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground"><tr><th className="px-3 py-2 font-medium">{t('Property')}</th><th className="px-3 py-2 font-medium">{t('Type')}</th><th className="px-3 py-2 font-medium">{t('Self-service')}</th><th className="px-3 py-2 font-medium">{t('Token claim')}</th></tr></thead>
            <tbody className="divide-y">{properties(schema.schema).map(p => <tr key={p.name}>
              <td className="px-3 py-2 font-mono text-xs">{p.name}{p.required && <Badge variant="secondary" className="ml-2">{t('required')}</Badge>}</td>
              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{p.type}</td>
              <td className="px-3 py-2">{p.self === 'write' ? t('Read & write') : p.self === 'read' ? t('Read') : <span className="text-muted-foreground">{t('Hidden')}</span>}</td>
              <td className="px-3 py-2 font-mono text-xs">{p.claim || <span className="font-sans text-muted-foreground">—</span>}</td>
            </tr>)}</tbody>
          </table></div>}
      </DetailSection>
      <DetailSection title={t('Schema')}>
        <pre className="max-h-96 overflow-auto rounded-md bg-muted/50 p-3 font-mono text-xs">{JSON.stringify(schema.schema, null, 2)}</pre>
      </DetailSection>
      {canWrite && <DetailSection danger title={t('Delete schema')} description={t('Profiles are no longer checked; existing attributes stay.')}>
        <Button variant="destructive" onClick={() => setRemoving(true)}><Trash2 /> {t('Delete schema')}</Button>
      </DetailSection>}
    </>}
    {editing && <JSONDialog title={schema ? t('Edit user schema') : t('Create user schema')} label={t('Schema')}
      description={t('Type "object" at the top. Annotate properties with "x-iamkit-self": "read" | "write" and "x-iamkit-claim": "<claim>". Remote $ref are refused.')}
      value={schema?.schema ?? example} success="" onClose={() => setEditing(false)} submit={async next => {
        const out = await api.put<UserSchema>(path, { schema: next })
        setSchema(out)
        toast.success(out.non_conforming ? t('Schema saved; {{non_conforming}} existing profile(s) do not conform and must on their next change', { non_conforming: out.non_conforming }) : t('Schema saved'))
      }} />}
    {removing && <ConfirmDialog title={t('Delete the user schema?')} description={t('Profiles are no longer checked and annotated claims are no longer released.')} confirmLabel={t('Delete')} onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success(t('Schema deleted')); setSchema(null) }} />}
  </div>
}
