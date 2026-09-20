import { useId, useState } from 'react'

const SCOPE_PREVIEW = 3

export function CollapsibleScopes({ scopes }: { scopes: string[] }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const visible = open ? scopes : scopes.slice(0, SCOPE_PREVIEW)

  return <div className="space-y-1">
    <div id={id} className="flex flex-wrap gap-1">
      {visible.map(p => <span key={p} className="inline-block rounded-md bg-secondary px-1.5 py-0.5 font-mono text-xs">{p}</span>)}
    </div>
    {scopes.length > SCOPE_PREVIEW && <button
      type="button"
      className="text-xs text-primary hover:underline"
      aria-expanded={open}
      aria-controls={id}
      onClick={() => setOpen(!open)}
    >
      {open ? 'Show less' : `+${scopes.length - SCOPE_PREVIEW} more`}
    </button>}
  </div>
}
