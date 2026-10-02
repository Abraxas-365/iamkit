import { useEffect, useRef, useState } from 'react'
import { Eye, PenLine } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { body as brandingBody, normalize } from '@/lib/branding'
import type { Branding } from '@/lib/branding'
import { copyLength, copyLimits, EMAIL_PURPOSES, emptyCopy, localeLabel, MAX_APP_NAME, overLimit, purposeLabel } from '@/lib/delivery'
import type { Copy, Locale, Preview, TemplateSummary, TemplateView } from '@/lib/delivery'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ConfirmDialog, ErrorState } from '@/components/library/patterns'
import { EmailPreview } from './preview-dialog'
import { rich, t } from '@/lib/i18n'

// TemplatesCard lists every email × language with its state; an editor
// changes the wording and the brand name (text only; the layout stays IAMKit's).
export function TemplatesCard({ path, brandPath, locales, canWrite, active }: { path: string; brandPath: string; locales: Locale[]; canWrite: boolean; active: boolean }) {
  const [items, setItems] = useState<TemplateSummary[] | null>(null)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<{ purpose: string; locale: string } | null>(null)
  const load = () => {
    setError('')
    api.get<{ items: TemplateSummary[] }>(`${path}/templates`).then(r => setItems(r?.items ?? [])).catch(e => setError(message(e)))
  }
  useEffect(load, [path])
  const find = (purpose: string, locale: string) => items?.find(tpl => tpl.purpose === purpose && tpl.locale === locale)
  const name = (code: string) => { const l = locales.find(l => l.code === code); return l ? localeLabel(l) : code }
  const codes = locales.length ? locales.map(l => l.code) : [...new Set(items?.map(tpl => tpl.locale))]

  return <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2 text-base"><PenLine className="size-4" /> {t('Email templates')}</CardTitle>
      <CardDescription>
        {canWrite
          ? t('The wording of the emails IAMKit writes, per language, and the name they show. Choose Edit on an email to change it; empty fields use the default text and the layout follows the branding.')
          : t('The wording of the emails IAMKit writes, per language, and the name they show. Choose View on an email to see it; empty fields use the default text and the layout follows the branding.')}
        {!active && (' ' + t('They apply when this environment sends through SMTP or Resend (or the global sender does); a webhook writes its own emails.'))}
      </CardDescription>
    </CardHeader>
    <CardContent>
      {error ? <ErrorState error={error} retry={load} /> : !items ? <div className="h-32 animate-pulse rounded-lg bg-muted" /> :
        <div className="max-h-[32rem] overflow-auto">
        <Table>
          {/* One row per language (the list grows), one column per email. */}
          <TableHeader><TableRow><TableHead>{t('Language')}</TableHead>{EMAIL_PURPOSES.map(p => <TableHead key={p.purpose}><span className="text-sm">{p.label}</span><p className="font-mono text-[11px] font-normal text-muted-foreground">{p.purpose}</p></TableHead>)}</TableRow></TableHeader>
          <TableBody>
            {codes.map(c => <TableRow key={c}>
              <TableCell><span className="text-sm">{name(c)}</span><p className="font-mono text-[11px] text-muted-foreground">{c}</p></TableCell>
              {EMAIL_PURPOSES.map(p => {
                const tpl = find(p.purpose, c)
                return <TableCell key={p.purpose}>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" className="gap-1.5" aria-label={canWrite ? t('Edit {{email}} ({{language}})', { email: p.label, language: name(c) }) : t('View {{email}} ({{language}})', { email: p.label, language: name(c) })} onClick={() => setEditing({ purpose: p.purpose, locale: c })}>
                      {canWrite ? <PenLine className="size-3.5" /> : <Eye className="size-3.5" />} {canWrite ? t('Edit') : t('View')}
                    </Button>
                    {tpl?.customized ? <Badge variant="secondary" className="bg-primary/10 text-primary">{t('Custom')}</Badge> : <Badge variant="secondary" className="bg-muted text-muted-foreground">{t('Default')}</Badge>}
                  </div>
                </TableCell>
              })}
            </TableRow>)}
          </TableBody>
        </Table>
        </div>}
    </CardContent>
    {editing && <TemplateEditor path={path} brandPath={brandPath} purpose={editing.purpose} locale={editing.locale} localeName={name(editing.locale)} canWrite={canWrite} onClose={() => setEditing(null)} onChanged={load} />}
  </Card>
}

const FIELDS: { key: keyof Copy; label: string; multiline?: boolean }[] = [
  { key: 'subject', label: t('Subject') },
  { key: 'heading', label: t('Heading') },
  { key: 'body', label: t('Body'), multiline: true },
  { key: 'action', label: t('Button') },
  { key: 'footer', label: t('Footer'), multiline: true },
]

const same = (a: Copy, b: Copy) => FIELDS.every(f => a[f.key].trim() === b[f.key].trim())

// TemplateEditor edits one email in one language, with a live preview of
// the draft (rendered by the server, nothing is saved or sent). The name
// the emails show is the hosted login display name (brandPath), shared by
// every email and language and by the sign-in pages.
function TemplateEditor({ path, brandPath, purpose, locale, localeName, canWrite, onClose, onChanged }: { path: string; brandPath: string; purpose: string; locale: string; localeName: string; canWrite: boolean; onClose: () => void; onChanged: () => void }) {
  const url = `${path}/templates/${purpose}/${locale}`
  const [view, setView] = useState<TemplateView | null>(null)
  const [draft, setDraft] = useState<Copy>(emptyCopy())
  const [brand, setBrand] = useState<Branding | null>(null)
  const [appName, setAppName] = useState('')
  const [loadError, setLoadError] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [preview, setPreview] = useState<Preview | null>(null)
  const [previewError, setPreviewError] = useState('')
  const [previewing, setPreviewing] = useState(false)
  const focused = useRef<HTMLInputElement | HTMLTextAreaElement | null>(null)

  useEffect(() => {
    api.get<TemplateView>(url).then(v => { setView(v); setDraft({ ...emptyCopy(), ...v.template }) }).catch(e => setLoadError(message(e)))
  }, [url])
  // Without the branding (not served, or unreadable) the name is not editable here.
  useEffect(() => {
    api.get<Branding>(brandPath).then(b => { const n = normalize(b ?? {}); setBrand(n); setAppName(n.display_name) }).catch(() => setBrand(null))
  }, [brandPath])

  // Live preview: debounced; viewers see the saved wording.
  const request = JSON.stringify({ template: draft, ...(brand && { app_name: appName }) })
  useEffect(() => {
    if (!view) return
    const controller = new AbortController()
    const timer = setTimeout(() => {
      setPreviewing(true)
      const load = canWrite
        ? api.post<Preview>(`${path}/preview`, { purpose, locale, ...JSON.parse(request) })
        : api.get<Preview>(`${path}/preview?${new URLSearchParams({ purpose, locale })}`, controller.signal)
      load.then(p => { if (!controller.signal.aborted) { setPreview(p); setPreviewError('') } })
        .catch(e => { if (!controller.signal.aborted) setPreviewError(message(e)) })
        .finally(() => { if (!controller.signal.aborted) setPreviewing(false) })
    }, 400)
    return () => { clearTimeout(timer); controller.abort() }
  }, [view, request, path, purpose, locale, canWrite])

  const fields = FIELDS.filter(f => f.key !== 'action' || view?.defaults.action)
  const wordingDirty = !!view && !same(draft, view.template)
  const nameDirty = !!brand && appName.trim() !== brand.display_name.trim()
  const dirty = wordingDirty || nameDirty
  const tooLong = overLimit(draft)
  const nameLength = copyLength(appName), nameTooLong = nameLength > MAX_APP_NAME
  const [discarding, setDiscarding] = useState(false)
  const close = () => { if (busy) return; if (canWrite && dirty) setDiscarding(true); else onClose() }
  const set = (key: keyof Copy, value: string) => setDraft(prev => ({ ...prev, [key]: value }))
  const insert = (placeholder: string) => {
    const el = focused.current
    const key = el?.dataset.field as keyof Copy | undefined
    if (!el || !key) return
    const token = `{{${placeholder}}}`
    const start = el.selectionStart ?? el.value.length, end = el.selectionEnd ?? start
    set(key, el.value.slice(0, start) + token + el.value.slice(end))
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(start + token.length, start + token.length) })
  }

  const save = async () => {
    if (busy) return
    setBusy(true); setError('')
    try {
      const saved: string[] = []
      if (nameDirty && brand) {
        // Re-read the branding so a style saved meanwhile is not overwritten;
        // the language is omitted, which keeps the stored one.
        const current = normalize(await api.get<Branding>(brandPath) ?? {})
        const out = normalize(await api.put<Branding>(brandPath, brandingBody({ ...current, locale: undefined, display_name: appName.trim() })))
        setBrand(out); setAppName(out.display_name)
        saved.push(t('Name saved'))
      }
      if (wordingDirty) {
        const out = await api.put<TemplateView>(url, draft)
        setView(out); setDraft({ ...emptyCopy(), ...out.template })
        saved.push(out.customized ? t('Template saved') : t('Template reset to default'))
        onChanged()
      }
      toast.success(saved.join(' · '))
    } catch (e) { setError(message(e)) } finally { setBusy(false) }
  }

  return <Dialog open onOpenChange={open => { if (!open) close() }}>
    <DialogContent className="sm:max-w-5xl">
      <DialogTitle className="pr-6 text-base font-semibold">{purposeLabel(purpose)} · {localeName}</DialogTitle>
      <DialogDescription className="text-muted-foreground">
        {t('Empty fields use the default shown in grey. Placeholders are replaced when the email is sent. The app name applies to every email.')}
      </DialogDescription>
      {loadError ? <ErrorState error={loadError} /> : !view ? <div className="h-96 animate-pulse rounded-lg bg-muted" /> :
        <div className="grid min-w-0 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <fieldset disabled={!canWrite || busy} className="min-w-0 space-y-3">
            <legend className="sr-only">{t('Wording')}</legend>
            {brand && <div className="space-y-1.5 rounded-lg border border-dashed p-3">
              <div className="flex items-baseline justify-between gap-2">
                <label className="text-sm font-medium" htmlFor="template-app-name">{t('App name')}</label>
                {appName && <span className={`text-[11px] ${nameTooLong ? 'font-medium text-destructive' : 'text-muted-foreground'}`}>{nameLength}/{MAX_APP_NAME}<span className="sr-only"> {nameTooLong ? t('characters, too long') : t('characters')}</span></span>}
              </div>
              <Input id="template-app-name" value={appName} placeholder={t('IAMKit')} aria-invalid={nameTooLong || undefined} aria-describedby="template-app-name-hint"
                onChange={e => setAppName(e.target.value)} />
              <p id="template-app-name-hint" className="text-xs text-muted-foreground">{rich('Shown at the top of every email and as {{code}}, in all languages. It is also the name on the hosted sign-in pages. Empty: “IAMKit”.', { code: <code className="text-[10px]">{'{{app_name}}'}</code> })}</p>
            </div>}
            {fields.map(f => {
              const id = `template-${f.key}`
              const length = copyLength(draft[f.key]), over = length > copyLimits[f.key]
              const props = {
                id, value: draft[f.key], placeholder: view.defaults[f.key], 'data-field': f.key,
                'aria-describedby': draft[f.key] ? `${id}-count` : undefined, 'aria-invalid': over || undefined,
                onFocus: (e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>) => { focused.current = e.currentTarget },
                onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => set(f.key, e.target.value),
              }
              return <div key={f.key} className="space-y-1.5">
                <div className="flex items-baseline justify-between gap-2">
                  <label className="text-sm font-medium" htmlFor={id}>{f.label}</label>
                  {draft[f.key] && <span id={`${id}-count`} className={`text-[11px] ${over ? 'font-medium text-destructive' : 'text-muted-foreground'}`}>{length}/{copyLimits[f.key]}<span className="sr-only"> {over ? t('characters, too long') : t('characters')}</span></span>}
                </div>
                {f.multiline
                  ? <textarea {...props} rows={f.key === 'body' ? 5 : 2} className="w-full rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30" />
                  : <Input {...props} />}
              </div>
            })}
            {canWrite && <div className="space-y-1.5">
              <p className="text-xs text-muted-foreground">{t('Insert into the selected field:')}</p>
              <div className="flex flex-wrap gap-1" role="group" aria-label={t('Placeholders')}>
                {view.placeholders.map(p => <Button key={p} type="button" variant="outline" size="sm" className="h-6 px-1.5 font-mono text-[11px]" onMouseDown={e => e.preventDefault()} onClick={() => insert(p)}>{`{{${p}}}`}</Button>)}
              </div>
            </div>}
            {error && <ErrorState error={error} />}
          </fieldset>
          <div className="min-w-0 space-y-2">
            <p className="text-xs font-medium text-muted-foreground">{canWrite ? t('Preview (not saved)') : t('Preview')}</p>
            <EmailPreview preview={preview} error={previewError} loading={previewing} live />
          </div>
        </div>}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-4">
        <div>{canWrite && view?.customized && <Button type="button" variant="outline" className="text-destructive hover:bg-destructive/10" disabled={busy} onClick={() => setResetting(true)}>{t('Reset to default')}</Button>}</div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" disabled={busy} onClick={close}>{canWrite && dirty ? t('Cancel') : t('Close')}</Button>
          {canWrite && <Button type="button" disabled={busy || !dirty || tooLong.length > 0 || nameTooLong} onClick={() => void save()}>{busy ? t('Saving…') : t('Save')}</Button>}
        </div>
      </div>
      {discarding && <ConfirmDialog title={t('Discard changes?')} confirmLabel={t('Discard')} description={t('Your changes to the “{{purpose}}” email in {{localeName}} have not been saved.', { purpose: purposeLabel(purpose), localeName })}
        onClose={() => setDiscarding(false)} confirm={async () => onClose()} />}
      {resetting && <ConfirmDialog title={t('Reset to the default wording?')} confirmLabel={t('Reset')} description={t('The “{{purpose}}” email in {{localeName}} will use IAMKit’s default text again.', { purpose: purposeLabel(purpose), localeName })}
        onClose={() => setResetting(false)}
        confirm={async () => {
          await api.delete(url)
          toast.success(t('Template reset to default'))
          onChanged(); onClose()
        }} />}
    </DialogContent>
  </Dialog>
}
