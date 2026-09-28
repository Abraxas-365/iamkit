import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'
import { Blocks, Building2, CornerDownLeft, FileText, Search, User } from 'lucide-react'
import { requestList } from '@/lib/api'
import { cn } from '@/lib/utils'

/** A destination the palette can open: a console page or a searched entity. */
export interface PaletteItem { to: string; label: string; group: string; hint?: string }

interface Named { id: string; name?: string; email?: string }
const searched: [path: string, group: string, icon: typeof User][] = [['users', 'Users', User], ['organizations', 'Organizations', Building2], ['applications', 'Applications', Blocks]]
const icons: Record<string, typeof User> = Object.fromEntries(searched.map(([, group, icon]) => [group, icon]))

/** CommandPalette (⌘K / Ctrl+K) jumps to any console page and, inside an
 * environment, searches its users, organizations and applications by name. */
export function CommandPalette({ pages, envBase, environment }: { pages: PaletteItem[]; envBase: string; environment?: string }) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen(o => !o) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
  return <>
    <button type="button" onClick={() => setOpen(true)} aria-keyshortcuts={mac ? 'Meta+K' : 'Control+K'}
      className="inline-flex h-7 min-w-0 items-center gap-2 rounded-md border border-input bg-background px-2 text-xs text-muted-foreground transition-colors hover:text-foreground sm:w-56">
      <Search className="size-3.5 shrink-0" /><span className="hidden truncate sm:inline">Search or jump to…</span><span className="sr-only sm:hidden">Search</span>
      <kbd className="ml-auto hidden rounded border bg-muted px-1 font-mono text-[10px] sm:inline">{mac ? '⌘' : 'Ctrl'} K</kbd>
    </button>
    <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
      {open && <Palette pages={pages} envBase={envBase} environment={environment} close={() => setOpen(false)} />}
    </DialogPrimitive.Root>
  </>
}

function Palette({ pages, envBase, environment, close }: { pages: PaletteItem[]; envBase: string; environment?: string; close: () => void }) {
  const navigate = useNavigate()
  const [text, setText] = useState('')
  const [found, setFound] = useState<PaletteItem[]>([])
  const [searching, setSearching] = useState(false)
  const [active, setActive] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)
  const q = text.trim().toLowerCase()

  useEffect(() => {
    if (!environment || q.length < 2) { setFound([]); setSearching(false); return }
    const controller = new AbortController()
    setSearching(true)
    const timer = setTimeout(() => {
      Promise.all(searched.map(([path, group]) =>
        requestList<Named>(`/environments/${environment}/${path}?limit=5&search=${encodeURIComponent(q)}`, controller.signal)
          .then(r => r.data.map(item => ({ to: `${envBase}/${path}/${item.id}`, group, label: item.name || item.email || item.id, hint: item.name && item.email ? item.email : undefined })))
          .catch(() => [] as PaletteItem[])))
        .then(groups => { if (!controller.signal.aborted) { setFound(groups.flat()); setSearching(false) } })
    }, 200)
    return () => { clearTimeout(timer); controller.abort() }
  }, [q, environment, envBase])

  const results = useMemo(() => {
    const matched = pages.filter(p => !q || p.label.toLowerCase().includes(q) || p.group.toLowerCase().includes(q))
    return [...matched, ...found]
  }, [pages, q, found])
  useEffect(() => { setActive(0) }, [q, found.length])
  useEffect(() => { listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' }) }, [active])

  const go = (item: PaletteItem | undefined) => { if (!item) return; close(); navigate(item.to) }
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(i => Math.min(i + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(i => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); go(results[active]) }
  }

  // Consecutive results of one group render as a labelled role=group, so the
  // listbox only contains groups and options (ARIA required children).
  const groups: { name: string; items: [PaletteItem, number][] }[] = []
  results.forEach((item, i) => {
    if (groups.at(-1)?.name !== item.group) groups.push({ name: item.group, items: [] })
    groups.at(-1)!.items.push([item, i])
  })
  return <DialogPrimitive.Portal>
    <DialogPrimitive.Backdrop className="fixed inset-0 z-50 bg-black/40" />
    <DialogPrimitive.Popup aria-label="Command palette" className="fixed top-[12vh] left-1/2 z-50 flex max-h-[70dvh] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 flex-col overflow-hidden rounded-xl bg-popover text-sm text-popover-foreground shadow-lg ring-1 ring-foreground/10 outline-none">
      <DialogPrimitive.Title className="sr-only">Search or jump to</DialogPrimitive.Title>
      <div className="flex items-center gap-2 border-b px-3">
        <Search className="size-4 shrink-0 text-muted-foreground" />
        <input autoFocus value={text} onChange={e => setText(e.target.value)} onKeyDown={onKeyDown}
          role="combobox" aria-expanded aria-controls="palette-results" aria-activedescendant={results[active] ? `palette-${active}` : undefined} aria-autocomplete="list"
          placeholder={environment ? 'Search users, organizations, applications, or pages…' : 'Jump to a page…'}
          className="h-11 w-full bg-transparent outline-none placeholder:text-muted-foreground" />
      </div>
      <div ref={listRef} id="palette-results" role="listbox" aria-label="Results" className={cn('overflow-y-auto p-1.5', !results.length && 'hidden')}>
        {groups.map((g, gi) => <div key={`${gi}:${g.name}`} role="group" aria-labelledby={`palette-group-${gi}`}>
          <p id={`palette-group-${gi}`} className="px-2 pt-2 pb-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{g.name}</p>
          {g.items.map(([item, i]) => {
            const Icon = icons[item.group] ?? FileText
            return <div key={`${item.group}:${item.to}`} id={`palette-${i}`} data-index={i} role="option" aria-selected={i === active}
              onMouseMove={() => setActive(i)} onClick={() => go(item)}
              className={cn('flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5', i === active && 'bg-accent text-accent-foreground')}>
              <Icon className="size-4 shrink-0 text-muted-foreground" />
              <span className="truncate">{item.label}</span>
              {item.hint && <span className="truncate text-xs text-muted-foreground">{item.hint}</span>}
              {i === active && <CornerDownLeft className="ml-auto size-3.5 shrink-0 text-muted-foreground" />}
            </div>
          })}
        </div>)}
      </div>
      {!results.length && !searching && <p className="px-3 py-6 text-center text-muted-foreground">{q.length >= 2 || !environment ? `Nothing matches “${text.trim()}”.` : 'Type at least two letters to search.'}</p>}
      <p role="status" className={cn('px-3 text-xs text-muted-foreground', searching ? 'py-2' : 'sr-only')}>{searching ? 'Searching…' : `${results.length} result${results.length === 1 ? '' : 's'}`}</p>
      <div className="flex gap-3 border-t px-3 py-2 text-[11px] text-muted-foreground"><span>↑↓ to move</span><span>↵ to open</span><span>esc to close</span></div>
    </DialogPrimitive.Popup>
  </DialogPrimitive.Portal>
}
