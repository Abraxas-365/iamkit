import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, PageHeader, SwitchField, Time } from '@/components/library/patterns'
import { rich, t } from '@/lib/i18n'

/** GET /features (feature.Feature): IAMKit's own feature flags. */
export interface Feature {
  name: string
  description: string
  scope: 'environment' | 'deployment'
  default: boolean
  deployment: boolean | null
  environment: boolean | null
  enabled: boolean
  updated_at?: string
}

const onOff = (v: boolean) => v ? t('on') : t('off')

/** source explains where a feature's value comes from. */
function source(f: Feature) {
  if (f.environment !== null) return f.updated_at ? rich('Set for this environment, {{time}}.', { time: <Time value={f.updated_at} /> }) : t('Set for this environment.')
  if (f.deployment !== null) return <>{t('Set for the deployment (IAMKIT_FEATURES): {{onOff}}.', { onOff: onOff(f.deployment) })}</>
  return <>{t('Default: {{onOff}}.', { onOff: onOff(f.default) })}</>
}

/** FeaturesPage turns IAMKit's beta features on and off for the
 * environment. Deployment-scoped features are read-only here. */
export default function FeaturesPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/features`
  const [features, setFeatures] = useState<Feature[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const load = useCallback(() => {
    setError('')
    api.get<{ items: Feature[] }>(path).then(r => setFeatures(r.items)).catch(e => setError(message(e)))
  }, [path])
  useEffect(load, [load])

  const header = <PageHeader title={t('Features (beta)')} description={t('Turn IAMKit\'s beta features on and off. Each value comes from this environment, else the deployment (IAMKIT_FEATURES), else IAMKit\'s default.')} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!features) return <div role="status" className="space-y-6">{header}<Skeleton className="h-48" /><span className="sr-only">{t('Loading features…')}</span></div>

  const change = async (f: Feature, request: () => Promise<Feature>, done: string) => {
    setBusy(f.name)
    try {
      const out = await request()
      setFeatures(list => list && list.map(x => x.name === out.name ? out : x))
      toast.success(done)
    } catch (e) { toast.error(message(e)) } finally { setBusy('') }
  }
  const environmentScoped = features.filter(f => f.scope === 'environment')
  const deploymentScoped = features.filter(f => f.scope === 'deployment')

  return <div className="space-y-6">{header}
    <DetailSection title={t('This environment')} description={t('Overrides apply to this environment only.')}>
      <div className="space-y-3">
        {environmentScoped.length === 0 && <p className="text-sm text-muted-foreground">{t('No features can be set per environment.')}</p>}
        {environmentScoped.map(f => <div key={f.name} className="space-y-1.5">
          <SwitchField label={f.name} hint={<>{f.description}. {source(f)}</>} checked={f.enabled} disabled={!canWrite || busy === f.name}
            onCheckedChange={enabled => void change(f, () => api.put<Feature>(`${path}/${f.name}`, { enabled }), enabled ? t('{{feature}} turned on', { feature: f.name }) : t('{{feature}} turned off', { feature: f.name }))} />
          {canWrite && f.environment !== null && <Button type="button" variant="link" size="sm" className="h-auto px-0" disabled={busy === f.name}
            onClick={() => void change(f, async () => { await api.delete(`${path}/${f.name}`); return api.get<Feature>(`${path}/${f.name}`) }, t('{{feature}} reset', { feature: f.name }))}>{f.deployment !== null ? t('Use the deployment value ({{onOff}})', { onOff: onOff(f.deployment) }) : t('Use the default ({{onOff}})', { onOff: onOff(f.default) })}</Button>}
        </div>)}
      </div>
    </DetailSection>
    {deploymentScoped.length > 0 && <DetailSection title={t('Deployment')} description={t('Set with IAMKIT_FEATURES on the server; the same in every environment.')}>
      <ul className="space-y-3">
        {deploymentScoped.map(f => <li key={f.name} className="flex items-start justify-between gap-4 rounded-lg border p-3">
          <div className="space-y-0.5"><p className="text-sm font-medium">{f.name}</p><p className="text-xs text-muted-foreground">{f.description}. {source(f)}</p></div>
          <Badge variant="secondary">{onOff(f.enabled)}</Badge>
        </li>)}
      </ul>
    </DetailSection>}
  </div>
}
