import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState, PageHeader } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** GET|PUT …/event-retention (event.RetentionPolicy): the environment's own
 * values (null = the server's ceiling), the ceilings and what is in effect. */
export interface EventRetention {
  security_retention_seconds: number | null
  default_retention_seconds: number | null
  ceilings: { security: number; default: number }
  effective: { security: number; default: number }
}

type Class = 'security' | 'default'
const DAY = 86400
const days = (seconds: number) => Math.round(seconds / DAY)

/** EventRetentionPage shows how long the environment keeps events, per
 * class; workspace owners shorten it below the server's ceilings. */
export default function EventRetentionPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const isOwner = principal?.role === 'owner'
  const path = `/environments/${environment}/event-retention`
  const [saved, setSaved] = useState<EventRetention | null>(null)
  const [draft, setDraft] = useState<Record<Class, string>>({ security: '', default: '' })
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const fill = (r: EventRetention) => {
    setSaved(r)
    setDraft({ security: r.security_retention_seconds === null ? '' : String(days(r.security_retention_seconds)), default: r.default_retention_seconds === null ? '' : String(days(r.default_retention_seconds)) })
  }
  const load = useCallback(() => { setError(''); api.get<EventRetention>(path).then(fill).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])

  const header = <PageHeader title={t('Event retention')} description={t('How long this environment keeps its events. The server sets a ceiling per class; this environment can only shorten it. The database is not an archive: stream events to S3 or Datadog with log streams to keep them longer.')} />
  if (error) return <div className="space-y-6">{header}<ErrorState error={error} retry={load} /></div>
  if (!saved) return <div role="status" className="space-y-6">{header}<Skeleton className="h-48" /><span className="sr-only">{t('Loading event retention…')}</span></div>

  const save = async (e: FormEvent) => {
    e.preventDefault()
    const seconds = (c: Class) => draft[c].trim() === '' ? null : Number(draft[c]) * DAY
    setSaving(true)
    try {
      fill(await api.put<EventRetention>(path, { security_retention_seconds: seconds('security'), default_retention_seconds: seconds('default') }))
      toast.success(t('Event retention saved'))
    } catch (err) { toast.error(message(err)) } finally { setSaving(false) }
  }
  const classes: [Class, string, string][] = [
    ['security', t('Security events'), t('Sign-ins, sessions, tokens, credentials, consents and other events that investigate an incident.')],
    ['default', t('Other events'), t('Every other event: changes to users, organizations, settings and so on.')],
  ]
  return <div className="space-y-6">
    {header}
    <DetailSection title={t('Retention')} description={t('Days to keep each class. Leave a field empty to keep the server\'s ceiling; at least 1 day.')}>
      <form onSubmit={save} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          {classes.map(([name, label, hint]) => {
            const id = `retention-${name}`
            return <div key={name} className="space-y-1.5">
              <label htmlFor={id} className="text-sm font-medium">{label}</label>
              <Input id={id} type="number" inputMode="numeric" min={1} max={days(saved.ceilings[name])} placeholder={t('{{days}} days', { days: days(saved.ceilings[name]) })} value={draft[name]} disabled={!isOwner || saving} aria-describedby={`${id}-hint`}
                onChange={e => setDraft(d => ({ ...d, [name]: e.target.value }))} />
              <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint} {t('Server: {{ceiling}} days · in effect: {{effective}} days', { ceiling: days(saved.ceilings[name]), effective: days(saved.effective[name]) })}</p>
            </div>
          })}
        </div>
        {isOwner ? <Button type="submit" disabled={saving}>{t('Save retention')}</Button> : <p className="text-sm text-muted-foreground">{t('Only workspace owners change event retention.')}</p>}
      </form>
    </DetailSection>
  </div>
}
