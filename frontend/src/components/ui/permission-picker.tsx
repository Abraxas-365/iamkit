import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

interface PermissionPickerProps {
  /** API path of the resource list, e.g. /environments/:id/resources */
  resourcesPath: string
  /** Currently selected resource ID */
  resourceId: string
  /** Hidden input name — submitted as comma-joined string */
  name: string
  /** Pre-selected permissions */
  defaultValue?: string[]
  disabled?: boolean
}

interface Resource { id: string; permissions?: string[] }

export function PermissionPicker({ resourcesPath, resourceId, name, defaultValue, disabled }: PermissionPickerProps) {
  const [catalog, setCatalog] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set(defaultValue ?? []))

  useEffect(() => {
    if (!resourceId) { setCatalog([]); return }
    setLoading(true)
    const controller = new AbortController()
    api.get<Resource>(`${resourcesPath}/${resourceId}`, controller.signal)
      .then(data => {
        if (!controller.signal.aborted) {
          const perms = data?.permissions ?? []
          setCatalog(perms)
          // Remove any selected permissions that no longer exist in the catalog
          setSelected(prev => {
            const next = new Set<string>()
            for (const p of prev) if (perms.includes(p)) next.add(p)
            return next
          })
          setLoading(false)
        }
      })
      .catch(() => { if (!controller.signal.aborted) { setCatalog([]); setLoading(false) } })
    return () => controller.abort()
  }, [resourcesPath, resourceId])

  const toggle = (perm: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(perm)) next.delete(perm)
      else next.add(perm)
      return next
    })
  }

  const selectAll = () => setSelected(new Set(catalog))
  const selectNone = () => setSelected(new Set())

  return (
    <div className="space-y-2">
      <input type="hidden" name={name} value={[...selected].join(',')} />
      {!resourceId && (
        <p className="text-xs text-muted-foreground">Select a resource first to see available permissions.</p>
      )}
      {loading && (
        <p className="text-xs text-muted-foreground">Loading permissions…</p>
      )}
      {!loading && resourceId && catalog.length === 0 && (
        <p className="text-xs text-muted-foreground">This resource has no permissions defined.</p>
      )}
      {!loading && catalog.length > 0 && (
        <>
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground">{selected.size} of {catalog.length} selected</span>
            <button type="button" className="text-xs text-primary hover:underline" onClick={selectAll} disabled={disabled}>All</button>
            <button type="button" className="text-xs text-primary hover:underline" onClick={selectNone} disabled={disabled}>None</button>
          </div>
          <div className="grid gap-1.5 rounded-lg border border-input bg-transparent p-2.5">
            {catalog.map(perm => (
              <label key={perm} className={cn('flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-accent', disabled && 'cursor-not-allowed opacity-50')}>
                <input
                  type="checkbox"
                  className="accent-primary"
                  checked={selected.has(perm)}
                  onChange={() => toggle(perm)}
                  disabled={disabled}
                />
                <code className="font-mono text-xs">{perm}</code>
              </label>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
