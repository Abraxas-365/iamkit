import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { EMAIL_PURPOSES } from '@/lib/delivery'
import type { Locale, Preview } from '@/lib/delivery'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { ErrorState, selectClass } from '@/components/library/patterns'
import { PreviewFrame } from '@/components/library/preview-frame'

// EmailPreview shows a rendered email: its subject, then the HTML part in
// a sandboxed frame or the plain-text part. live announces each new
// rendering (the editor's preview follows typing) to screen readers.
export function EmailPreview({ preview, error, loading, live }: { preview: Preview | null; error: string; loading?: boolean; live?: boolean }) {
  const [text, setText] = useState(false)
  // One stable live region (errors announce themselves via role=alert);
  // only settled results are announced, not every keystroke's loading.
  return <div className={`space-y-2 ${loading && preview ? 'opacity-60' : ''}`} aria-busy={loading || !preview || undefined}>
    {live && <p role="status" aria-live="polite" className="sr-only">{!loading && !error && preview ? `Preview updated. Subject: ${preview.subject}` : ''}</p>}
    {error ? <ErrorState error={error} /> : !preview ? <div className="h-96 animate-pulse rounded-lg bg-muted" /> : <>
      <div className="flex items-center justify-between gap-2">
        <p className="min-w-0 truncate text-sm"><span className="text-muted-foreground">Subject: </span><span aria-label="Preview subject" className="font-medium">{preview.subject}</span></p>
        <div className="flex shrink-0 gap-1" role="group" aria-label="Preview format">
          <Button type="button" size="sm" variant={text ? 'ghost' : 'secondary'} aria-pressed={!text} onClick={() => setText(false)}>HTML</Button>
          <Button type="button" size="sm" variant={text ? 'secondary' : 'ghost'} aria-pressed={text} onClick={() => setText(true)}>Text</Button>
        </div>
      </div>
      {text
        ? <pre aria-label="Plain-text email" className="h-96 overflow-auto whitespace-pre-wrap rounded-lg border bg-muted/40 p-3 text-xs">{preview.text}</pre>
        : <PreviewFrame title="Email preview" html={preview.html} className="h-96 rounded-lg border" />}
    </>}
  </div>
}

// PreviewDialog renders sample emails with the saved branding and wording;
// nothing is sent.
export function PreviewDialog({ path, locales, onClose }: { path: string; locales: Locale[]; onClose: () => void }) {
  const [purpose, setPurpose] = useState('login')
  const [locale, setLocale] = useState('')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    setError('')
    const q = new URLSearchParams({ purpose, ...(locale && { locale }) })
    api.get<Preview>(`${path}/preview?${q}`, controller.signal).then(setPreview).catch(e => { if (!controller.signal.aborted) setError(message(e)) })
    return () => controller.abort()
  }, [path, purpose, locale])

  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogContent className="sm:max-w-2xl">
      <DialogTitle className="pr-6 text-base font-semibold">Email preview</DialogTitle>
      <DialogDescription className="text-muted-foreground">Sample emails with this environment’s branding and wording. Nothing is sent.</DialogDescription>
      <div className="grid gap-3 sm:grid-cols-2">
        <select aria-label="Email" className={selectClass} value={purpose} onChange={e => setPurpose(e.target.value)}>
          {EMAIL_PURPOSES.map(p => <option key={p.purpose} value={p.purpose}>{p.label}</option>)}
        </select>
        <select aria-label="Language" className={selectClass} value={locale} onChange={e => setLocale(e.target.value)}>
          <option value="">Environment default</option>
          {locales.map(l => <option key={l.code} value={l.code}>{l.name}</option>)}
        </select>
      </div>
      <EmailPreview preview={preview} error={error} live />
    </DialogContent>
  </Dialog>
}
