import { useId, useState } from 'react'
import { t } from '@/lib/i18n'
import type { PermissionText } from '@/lib/descriptions'

const SCOPE_PREVIEW = 3

/** CollapsibleScopes lists permissions as chips. With `text`, a described permission shows its display name and the raw name beside it, greyed (D40). */
export function CollapsibleScopes({ scopes, text }: { scopes: string[]; text?: (permission: string) => PermissionText }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const visible = open ? scopes : scopes.slice(0, SCOPE_PREVIEW)

  return <div className="space-y-1">
    <div id={id} className="flex flex-wrap gap-1">
      {visible.map(p => {
        const d = text?.(p)
        return d?.described
          ? <span key={p} className="inline-block rounded-md bg-secondary px-1.5 py-0.5 text-xs" title={d.description || undefined}>{d.display_name} <span className="font-mono text-[11px] text-muted-foreground">{p}</span></span>
          : <span key={p} className="inline-block rounded-md bg-secondary px-1.5 py-0.5 font-mono text-xs">{p}</span>
      })}
    </div>
    {scopes.length > SCOPE_PREVIEW && <button
      type="button"
      className="text-xs text-primary hover:underline"
      aria-expanded={open}
      aria-controls={id}
      onClick={() => setOpen(!open)}
    >
      {open ? t('Show less') : t('+{{value}} more', { value: scopes.length - SCOPE_PREVIEW })}
    </button>}
  </div>
}
