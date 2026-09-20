import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'
import { api, type ListResult } from '@/lib/api'

interface Option { id: string; label: string; inactive?: boolean }

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
  const inputRef = useRef<HTMLInputElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const [dropdownStyle, setDropdownStyle] = useState<React.CSSProperties>({})

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

  // Close on click outside (check both the input container and the portalled dropdown)
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      const target = e.target as Node
      if (ref.current?.contains(target)) return
      if (dropdownRef.current?.contains(target)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // Position the dropdown using fixed coordinates so it escapes overflow containers
  useEffect(() => {
    if (!open || !inputRef.current) return
    const rect = inputRef.current.getBoundingClientRect()
    setDropdownStyle({
      position: 'fixed',
      top: rect.bottom + 4,
      left: rect.left,
      width: rect.width,
    })
  }, [open])

  const selectedOption = options.find(o => o.id === selected)
  const selectedLabel = selectedOption?.label

  const dropdownContent = open && (
    <div ref={dropdownRef}>
      {options.length > 0
        ? <ul style={dropdownStyle} className="z-[100] max-h-48 overflow-auto rounded-lg border bg-popover py-1 text-sm shadow-lg">
            {options.map(o => <li key={o.id} className={cn('cursor-pointer px-3 py-1.5 hover:bg-accent', o.id === selected && 'bg-accent font-medium')} onMouseDown={e => { e.preventDefault(); setSelected(o.id); setOpen(false); onChange?.(o.id) }}>
              <span>{o.label}</span>
              {o.inactive && <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">Inactive</span>}
              <span className="ml-2 font-mono text-xs text-muted-foreground">{o.id.slice(0, 8)}…</span>
            </li>)}
          </ul>
        : !loading
          ? <div style={dropdownStyle} className="z-[100] rounded-lg border bg-popover px-3 py-2 text-xs text-muted-foreground shadow-lg">No matches found</div>
          : <div style={dropdownStyle} className="z-[100] rounded-lg border bg-popover px-3 py-2 text-xs text-muted-foreground shadow-lg">Searching…</div>
      }
    </div>
  )

  return <div ref={ref} className="relative">
    <input type="hidden" name={name} value={selected} />
    <input
      ref={inputRef}
      id={id}
      type="text"
      role="combobox"
      aria-expanded={open}
      autoComplete="off"
      required={required && !selected}
      disabled={disabled || (loading && !open)}
      placeholder={loading && !open ? 'Loading…' : placeholder ?? 'Search…'}
      className={cn('h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30', className)}
      value={open ? query : (selectedLabel ? `${selectedLabel}${selectedOption?.inactive ? ' (inactive)' : ''} (${selected.slice(0, 8)}…)` : selected)}
      onFocus={() => { setOpen(true); setQuery('') }}
      onChange={e => { setQuery(e.target.value); setOpen(true) }}
    />
    {dropdownContent && createPortal(dropdownContent, document.body)}
  </div>
}
