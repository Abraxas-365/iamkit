import { useState } from 'react'
import { Languages } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { LANGUAGES, remember, saved, t } from '@/lib/i18n'
import { message } from '@/lib/utils'

/** The operator's console language (operators.locale); empty follows the
 * browser. A change is saved, then the page reloads in that language. */
export function LanguageMenu() {
  const [value, setValue] = useState<string>(saved() ?? '')
  const [busy, setBusy] = useState(false)
  async function choose(next: string) {
    setBusy(true)
    try {
      await api.put('/preferences', { locale: next || null })
      setValue(next)
      if (remember(next || null)) window.location.reload()
    } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
  }
  return <label className="flex items-center gap-2 px-2 text-xs text-muted-foreground">
    <Languages className="size-3.5 shrink-0" aria-hidden />
    <select aria-label={t('Console language')} className="h-7 min-w-0 flex-1 rounded-md border border-input bg-background px-2 text-xs" value={value} disabled={busy} onChange={e => void choose(e.target.value)}>
      <option value="">{t('Browser language')}</option>
      {LANGUAGES.map(l => <option key={l.code} value={l.code} lang={l.code}>{l.name}</option>)}
    </select>
  </label>
}
