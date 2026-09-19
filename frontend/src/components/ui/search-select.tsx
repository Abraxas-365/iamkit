import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { api, type ListResult } from '@/lib/api'

interface Option { id: string; label: string }

interface SearchSelectProps {
  path: string
  /** Map API response items to { id, label } */
  mapItem: (item: Record<string, unknown>) => Option
  name: string
  id?: string
  defaultValue?: string
  required?: boolean
  disabled?: boolean
  placeholder?: string
  className?: string
  /** Called when the selected value changes */
  onChange?: (value: string) => void
}

const DEBOUNCE_MS = 250
const LIMIT = 25

export function SearchSelect({ path, mapItem, name, id, defaultValue = '', required, disabled, placeholder, className, onChange }: SearchSelectProps) {
  const [options, setOptions] = useState<Option[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState(defaultValue)
  const ref = useRef<HTMLDivElement>(null)

  // Debounce search input
  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(query), DEBOUNCE_MS)
    return () => clearTimeout(id)
  }, [query])

  // Fetch options from server with search + limit
  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    const params = new URLSearchParams()
    if (debouncedQuery) params.set('search', debouncedQuery)
    params.set('limit', String(LIMIT))
    const url = `${path}?${params.toString()}`

    api.list<Record<string, unknown>>(url, controller.signal)
      .then((result: ListResult<Record<string, unknown>>) => {
        if (!controller.signal.aborted) {
          setOptions(result.data.map(mapItem))
          setLoading(false)
        }
      })
      .catch(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [path, debouncedQuery])

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const selectedLabel = options.find(o => o.id === selected)?.label

  return <div ref={ref} className="relative">
    <input type="hidden" name={name} value={selected} />
    <input
      id={id}
      type="text"
      role="combobox"
      aria-expanded={open}
      autoComplete="off"
      required={required && !selected}
      disabled={disabled || (loading && !open)}
      placeholder={loading && !open ? 'Loading…' : placeholder ?? 'Search…'}
      className={cn('h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30', className)}
      value={open ? query : (selectedLabel ? `${selectedLabel} (${selected.slice(0, 8)}…)` : selected)}
      onFocus={() => { setOpen(true); setQuery('') }}
      onChange={e => { setQuery(e.target.value); setOpen(true) }}
    />
    {open && options.length > 0 && <ul className="absolute z-50 mt-1 max-h-48 w-full overflow-auto rounded-lg border bg-popover py-1 text-sm shadow-lg">
      {options.map(o => <li key={o.id} className={cn('cursor-pointer px-3 py-1.5 hover:bg-accent', o.id === selected && 'bg-accent font-medium')} onMouseDown={e => { e.preventDefault(); setSelected(o.id); setOpen(false); onChange?.(o.id) }}>
        <span>{o.label}</span>
        <span className="ml-2 font-mono text-xs text-muted-foreground">{o.id.slice(0, 8)}…</span>
      </li>)}
    </ul>}
    {open && options.length === 0 && !loading && <div className="absolute z-50 mt-1 w-full rounded-lg border bg-popover px-3 py-2 text-xs text-muted-foreground shadow-lg">No matches found</div>}
    {open && loading && <div className="absolute z-50 mt-1 w-full rounded-lg border bg-popover px-3 py-2 text-xs text-muted-foreground shadow-lg">Searching…</div>}
  </div>
}
