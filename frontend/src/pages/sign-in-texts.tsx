import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { RotateCcw, Search } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { pages, type Page } from '@/lib/branding'
import { localeLabel, type Locale } from '@/lib/delivery'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { BackLink, ConfirmDialog, ErrorState, PageHeader, selectClass } from '@/components/library/patterns'
import { UnsavedChangesGuard } from '@/components/library/unsaved-changes'
import { clientName, PreviewFrame } from '@/components/library/preview-frame'
import { t } from '@/lib/i18n'

export interface TextKey { key: string; default: string; placeholders: string[]; max_length: number }
export interface TextSet { client_id?: string; organization_id?: string; locale: string; texts: Record<string, string>; updated_at?: string }
interface Option { id: string; name: string }

// scopePath is the API path of a scope's texts: '' (environment),
// 'client:<id>' or 'organization:<id>'.
export function scopePath(base: string, scope: string, locale: string) {
  const [kind, id] = scope.split(':')
  const prefix = kind === 'client' ? `/clients/${id}` : kind === 'organization' ? `/organizations/${id}` : ''
  return `${base}/login-settings${prefix}/texts/${locale}`
}

// textProblem says why a custom text would be refused (the server checks
// it again): too long, or placeholders not kept.
export function textProblem(value: string, key: TextKey): string {
  const text = value.trim()
  if (!text) return ''
  if ([...text].length > key.max_length) return t('At most {{count}} characters.', { count: key.max_length })
  const missing = key.placeholders.filter(p => p !== '%%' && !text.includes(p))
  if (missing.length) return t('Keep {{placeholders}}.', { placeholders: missing.join(', ') })
  return ''
}

// group is the section of a key: hosted.<group>.…
const group = (key: string) => key.split('.')[1] ?? ''
const groups: Record<string, string> = { title: t('Titles'), subtitle: t('Subtitles'), form: t('Labels and buttons'), notice: t('Notices'), error: t('Errors'), invitation: t('Invitations'), device: t('Device sign-in'), directory: t('Directory sign-in'), legal: t('Legal links') }

// SignInTextsPage rewords the hosted pages per language for the
// environment, an OAuth client or an organization, with a live preview.
export default function SignInTextsPage() {
  const { project, environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}`
  const [locales, setLocales] = useState<Option[]>([])
  const [clients, setClients] = useState<Option[]>([])
  const [organizations, setOrganizations] = useState<Option[]>([])
  const [sets, setSets] = useState<TextSet[]>([])
  const [scope, setScope] = useState('')
  const [locale, setLocale] = useState('en')
  const [catalog, setCatalog] = useState<TextKey[] | null>(null)
  const [saved, setSaved] = useState<Record<string, string>>({})
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [filter, setFilter] = useState('')
  const [onlyCustom, setOnlyCustom] = useState(false)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState(false)

  const loadSets = () => api.get<{ items: TextSet[] }>(`${base}/login-settings/texts?limit=100`).then(r => setSets(r.items ?? [])).catch(() => {})
  useEffect(() => {
    api.get<{ items: Locale[] }>(`${base}/login-settings/locales`).then(r => setLocales((r.items ?? []).map(l => ({ id: l.code, name: localeLabel(l) })))).catch(() => {})
    api.get<{ items: { id: string; application_name: string; resource_name: string; hosted_login: boolean }[] }>(`${base}/oauth-clients?limit=100`)
      .then(r => setClients(r.items.filter(c => c.hosted_login).map(c => ({ id: c.id, name: clientName(c) || c.id })))).catch(() => {})
    api.get<{ items: Option[] }>(`${base}/organizations?limit=100`).then(r => setOrganizations(r.items.map(o => ({ id: o.id, name: o.name })))).catch(() => {})
    loadSets()
  }, [base])

  const load = () => {
    setError(''); setCatalog(null)
    Promise.all([
      api.get<{ items: TextKey[] }>(`${base}/login-settings/texts/catalog?locale=${locale}`),
      api.get<TextSet>(scopePath(base, scope, locale)),
    ]).then(([c, s]) => { setCatalog(c.items); setSaved(s.texts ?? {}); setDraft(s.texts ?? {}) }).catch(e => setError(message(e)))
  }
  useEffect(load, [base, scope, locale])

  const changed = JSON.stringify(clean(draft)) !== JSON.stringify(clean(saved))
  const problems = useMemo(() => Object.fromEntries((catalog ?? []).map(k => [k.key, textProblem(draft[k.key] ?? '', k)]).filter(([, p]) => p)), [catalog, draft])
  const invalid = Object.keys(problems).length > 0
  const shown = (catalog ?? []).filter(k => (!onlyCustom || draft[k.key]?.trim()) &&
    (!filter || `${k.key} ${k.default} ${draft[k.key] ?? ''}`.toLowerCase().includes(filter.toLowerCase())))
  const count = Object.keys(clean(saved)).length

  const save = async () => {
    setSaving(true)
    try {
      const texts = clean(draft)
      if (Object.keys(texts).length === 0) {
        await api.delete(scopePath(base, scope, locale))
        setSaved({}); setDraft({})
      } else {
        const out = await api.put<TextSet>(scopePath(base, scope, locale), { texts })
        setSaved(out.texts); setDraft(out.texts)
      }
      toast.success(t('Sign-in texts saved')); loadSets()
    } catch (e) { toast.error(message(e)) } finally { setSaving(false) }
  }

  const label = (s: TextSet) => s.client_id ? clients.find(c => c.id === s.client_id)?.name ?? t('Client') : s.organization_id ? organizations.find(o => o.id === s.organization_id)?.name ?? t('Organization') : t('Environment')
  const header = <PageHeader title={t('Sign-in texts')} description={t('Reword any text of the hosted pages, per language. Organization texts win over client texts, client texts over the environment\'s; empty fields keep the inherited wording.')} />
  return <div className="space-y-6">
    <BackLink to={`/projects/${project}/environments/${environment}/hosted-login`}>{t('Hosted login')}</BackLink>
    {header}
    <UnsavedChangesGuard when={changed} />
    <div className="flex flex-wrap items-end gap-3">
      <label className="space-y-1 text-sm font-medium">{t('For')}
        <select aria-label={t('Texts for')} className={cn(selectClass, 'block w-64')} value={scope} disabled={changed} onChange={e => setScope(e.target.value)}>
          <option value="">{t('Environment (every page)')}</option>
          {clients.length > 0 && <optgroup label={t('OAuth clients')}>{clients.map(c => <option key={c.id} value={`client:${c.id}`}>{c.name}</option>)}</optgroup>}
          {organizations.length > 0 && <optgroup label={t('Organizations')}>{organizations.map(o => <option key={o.id} value={`organization:${o.id}`}>{o.name}</option>)}</optgroup>}
        </select>
      </label>
      <label className="space-y-1 text-sm font-medium">{t('Language')}
        <select aria-label={t('Language')} className={cn(selectClass, 'block w-40')} value={locale} disabled={changed} onChange={e => setLocale(e.target.value)}>
          {(locales.length ? locales : [{ id: 'en', name: 'English' }]).map(l => <option key={l.id} value={l.id}>{l.name}</option>)}
        </select>
      </label>
      {changed && <p className="text-xs text-muted-foreground">{t('Save or discard to switch.')}</p>}
    </div>
    {sets.length > 0 && <div className="flex flex-wrap gap-2" aria-label={t('Customized')}>
      {sets.map(s => {
        const value = s.client_id ? `client:${s.client_id}` : s.organization_id ? `organization:${s.organization_id}` : ''
        return <Button key={`${value}-${s.locale}`} size="xs" variant="outline" disabled={changed} className={cn(value === scope && s.locale === locale && 'bg-muted')} onClick={() => { setScope(value); setLocale(s.locale) }}>
          {label(s)} · {s.locale} <Badge variant="secondary">{Object.keys(s.texts).length}</Badge>
        </Button>
      })}
    </div>}
    {error ? <ErrorState error={error} retry={load} /> : !catalog ? <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p> :
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <section aria-label={t('Texts')} className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-48 flex-1">
              <Search className="pointer-events-none absolute top-2 left-2 size-4 text-muted-foreground" aria-hidden />
              <Input aria-label={t('Filter texts')} placeholder={t('Filter by key or wording')} className="pl-8" value={filter} onChange={e => setFilter(e.target.value)} />
            </div>
            <Button size="sm" variant="ghost" aria-pressed={onlyCustom} className={cn(onlyCustom && 'bg-muted')} onClick={() => setOnlyCustom(!onlyCustom)}>{t('Customized only')}</Button>
          </div>
          <div className="max-h-[720px] space-y-4 overflow-y-auto rounded-lg border p-3">
            {Object.keys(groups).concat([...new Set(shown.map(k => group(k.key)))].filter(g => !groups[g])).map(g => {
              const keys = shown.filter(k => group(k.key) === g)
              if (!keys.length) return null
              return <fieldset key={g} className="space-y-3">
                <legend className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{groups[g] ?? g}</legend>
                {keys.map(k => {
                  const value = draft[k.key] ?? ''
                  const id = `text-${k.key}`
                  const problem = problems[k.key]
                  return <div key={k.key} className="space-y-1">
                    <div className="flex items-baseline justify-between gap-2">
                      <label htmlFor={id} className="font-mono text-[11px] text-muted-foreground">{k.key}</label>
                      {value && <span className={cn('text-[11px]', [...value.trim()].length > k.max_length ? 'text-destructive' : 'text-muted-foreground')}>{[...value.trim()].length}/{k.max_length}</span>}
                    </div>
                    <Input id={id} value={value} placeholder={k.default} disabled={!canWrite} aria-invalid={!!problem || undefined} aria-describedby={problem ? `${id}-problem` : undefined}
                      onChange={e => setDraft({ ...draft, [k.key]: e.target.value })} />
                    {problem ? <p id={`${id}-problem`} className="text-xs text-destructive">{problem}</p>
                      : k.placeholders.length > 0 && <p className="text-[11px] text-muted-foreground">{t('Keeps {{placeholders}}', { placeholders: k.placeholders.join(', ') })}</p>}
                  </div>
                })}
              </fieldset>
            })}
            {shown.length === 0 && <p className="text-sm text-muted-foreground">{t('No texts match.')}</p>}
          </div>
          {canWrite && <div className="flex flex-wrap items-center gap-2">
            <Button onClick={save} disabled={!changed || invalid || saving}>{saving ? t('Saving…') : t('Save')}</Button>
            <Button variant="outline" disabled={!changed} onClick={() => setDraft(saved)}>{t('Discard')}</Button>
            {count > 0 && <Button variant="ghost" className="gap-1.5" onClick={() => setRemoving(true)}><RotateCcw className="size-4" />{t('Remove these texts')}</Button>}
          </div>}
        </section>
        <TextsPreview base={base} scope={scope} locale={locale} texts={clean(draft)} />
      </div>}
    {removing && <ConfirmDialog title={t('Remove these texts?')} description={t('Every text of this language goes back to the inherited wording.')} confirmLabel={t('Remove')} onClose={() => setRemoving(false)}
      confirm={async () => { await api.delete(scopePath(base, scope, locale)); setSaved({}); setDraft({}); toast.success(t('Sign-in texts removed')); loadSets() }} />}
  </div>
}

// clean drops empty texts (they inherit).
function clean(texts: Record<string, string>) {
  return Object.fromEntries(Object.entries(texts).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v).sort(([a], [b]) => a.localeCompare(b)))
}

// TextsPreview renders a hosted page with the unsaved texts over the saved
// branding and the inherited texts of the scope.
function TextsPreview({ base, scope, locale, texts }: { base: string; scope: string; locale: string; texts: Record<string, string> }) {
  const [page, setPage] = useState<Page>('identify')
  const [html, setHtml] = useState('')
  const [error, setError] = useState('')
  const body = JSON.stringify(texts)
  useEffect(() => {
    let stale = false
    const [kind, id] = scope.split(':')
    const timer = window.setTimeout(() => {
      api.post<{ html: string }>(`${base}/login-settings/texts/preview`, { page, locale, texts: JSON.parse(body), ...(kind === 'client' && { client_id: id }), ...(kind === 'organization' && { organization_id: id }) })
        .then(r => { if (!stale) { setHtml(r.html); setError('') } }).catch(e => { if (!stale) setError(message(e)) })
    }, 300)
    return () => { stale = true; window.clearTimeout(timer) }
  }, [base, scope, locale, page, body])
  return <section aria-label={t('Preview')} className="min-w-0 space-y-3 xl:sticky xl:top-4">
    <select aria-label={t('Preview page')} className={cn(selectClass, 'w-auto')} value={page} onChange={e => setPage(e.target.value as Page)}>
      {pages.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
    </select>
    {error && <p role="alert" className="rounded-lg border border-destructive/30 px-3 py-2 text-sm text-destructive">{error}</p>}
    <div className="overflow-hidden rounded-lg border bg-muted/40 p-3">
      <div className="overflow-hidden rounded-md border shadow-sm">
        {html ? <PreviewFrame html={html} className="h-[640px]" /> : <div role="status" className="flex h-[640px] items-center justify-center text-sm text-muted-foreground">{t('Rendering preview…')}</div>}
      </div>
    </div>
    <p className="text-xs text-muted-foreground">{t('Rendered with sample data in the saved branding. Errors and notices show on the pages that use them.')}</p>
  </section>
}
