import { useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DetailSection, ErrorState } from '@/components/library/patterns'
import { MAX_DESCRIPTION, MAX_DISPLAY_NAME, type PermissionDescription } from '@/lib/descriptions'
import { localeLabel, type Locale } from '@/lib/delivery'
import { t } from '@/lib/i18n'

/** The default text tab: shown to readers whose language has no text. */
const DEFAULT = ''

const key = (d: Pick<PermissionDescription, 'permission' | 'locale'>) => `${d.permission}\u0000${d.locale}`
/** Rows with neither text are not stored: the server replaces the whole set. */
const clean = (items: PermissionDescription[], catalog: string[]) => items
  .map(d => ({ ...d, display_name: d.display_name.trim(), description: d.description.trim() }))
  .filter(d => (d.display_name || d.description) && catalog.includes(d.permission))
  .sort((a, b) => key(a).localeCompare(key(b)))

/** PermissionDescriptionsEditor edits how people read each permission of a
 * resource (GET/PUT …/resources/:id/permission-descriptions): a display name
 * and a sentence per permission, in a default text and one per language. The
 * permission's name stays the identifier; consent screens, connected apps and
 * the console show these texts with the name as subtitle. */
export function PermissionDescriptionsEditor({ base, resource, canWrite }: {
  base: string
  resource: { id: string; permissions: string[] }
  canWrite: boolean
}) {
  const path = `${base}/resources/${resource.id}/permission-descriptions`
  const [saved, setSaved] = useState<PermissionDescription[] | null>(null)
  const [draft, setDraft] = useState<PermissionDescription[]>([])
  const [locales, setLocales] = useState<Locale[]>([])
  const [locale, setLocale] = useState(DEFAULT)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  const pending = useRef(false)
  const catalog = resource.permissions
  useEffect(() => {
    setError('')
    api.get<{ items: PermissionDescription[] | null }>(path).then(r => { setSaved(r.items ?? []); setDraft(r.items ?? []) }).catch(e => setError(message(e)))
  }, [path, version])
  useEffect(() => { api.get<{ items: Locale[] }>(`${base}/login-settings/locales`).then(r => setLocales(r.items ?? [])).catch(() => {}) }, [base])
  const tabs = useMemo<[string, string][]>(() => [[DEFAULT, t('Default')], ...(locales.length ? locales : [{ code: 'en', name: 'English' }, { code: 'es', name: 'Español' }]).map((l): [string, string] => [l.code, localeLabel(l)])], [locales])
  const current = (permission: string) => draft.find(d => d.permission === permission && d.locale === locale)
  const edit = (permission: string, field: 'display_name' | 'description', value: string) => setDraft(items => {
    const at = items.findIndex(d => d.permission === permission && d.locale === locale)
    if (at < 0) return [...items, { permission, locale, display_name: '', description: '', [field]: value }]
    return items.map((d, i) => i === at ? { ...d, [field]: value } : d)
  })
  const count = (l: string) => draft.filter(d => d.locale === l && catalog.includes(d.permission) && (d.display_name.trim() || d.description.trim())).length
  const next = clean(draft, catalog)
  const changed = saved !== null && JSON.stringify(next) !== JSON.stringify(clean(saved, catalog))
  const title = t('Permission descriptions')
  if (error && saved === null) return <DetailSection title={title}><ErrorState error={error} retry={() => setVersion(v => v + 1)} /></DetailSection>
  return <DetailSection title={title} description={t('How people read each permission: consent screens, connected apps and this console show the display name, with the permission\'s name beside it. Text in a language is used for readers of that language; Default is the fallback.')}>
    <div className="space-y-4">
      {catalog.length === 0
        ? <p className="text-sm text-muted-foreground">{t('This resource has no permissions yet. Add some to describe them.')}</p>
        : <>
          <div role="tablist" aria-label={t('Language')} className="flex flex-wrap gap-1">
            {tabs.map(([code, name]) => <Button key={code || 'default'} role="tab" aria-selected={locale === code} size="xs" variant={locale === code ? 'secondary' : 'outline'} onClick={() => setLocale(code)}>
              {name}{count(code) > 0 && <span className="ml-1 text-muted-foreground">{count(code)}</span>}
            </Button>)}
          </div>
          <div className="grid gap-3">
            {catalog.map(p => {
              const d = current(p)
              return <div key={p} role="group" aria-label={p} className="grid gap-2 rounded-lg border p-3 sm:grid-cols-[minmax(8rem,12rem)_1fr_2fr]">
                <code className="break-all self-center font-mono text-xs">{p}</code>
                <Input aria-label={t('Display name: {{permission}}', { permission: p })} maxLength={MAX_DISPLAY_NAME} placeholder={t('Display name')} disabled={!canWrite || busy} value={d?.display_name ?? ''} onChange={e => edit(p, 'display_name', e.target.value)} />
                <Input aria-label={t('Description: {{permission}}', { permission: p })} maxLength={MAX_DESCRIPTION} placeholder={t('What it lets an app do')} disabled={!canWrite || busy} value={d?.description ?? ''} onChange={e => edit(p, 'description', e.target.value)} />
              </div>
            })}
          </div>
        </>}
      {error && <ErrorState error={error} />}
      {canWrite && catalog.length > 0 && <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !changed} onClick={async () => {
          if (pending.current) return
          pending.current = true; setBusy(true); setError('')
          try { await api.put(path, { items: next }); setSaved(next); setDraft(next); toast.success(t('Permission descriptions saved')) }
          catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
        }}>{busy ? t('Saving…') : t('Save descriptions')}</Button>
        {changed && <Button variant="outline" disabled={busy} onClick={() => setDraft(saved ?? [])}>{t('Discard changes')}</Button>}
      </div>}
    </div>
  </DetailSection>
}
